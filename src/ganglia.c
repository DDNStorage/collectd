#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <pthread.h>
#include <ganglia.h>

#define TMAX_DEFAULT	60
#define DMAX_DEFAULT	0

Ganglia_pool global_context = NULL;
Ganglia_gmond_config gmond_config = NULL;
Ganglia_udp_send_channels send_channels = NULL;
static char *gmondconfpath = NULL;
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *config_keys[] = {
	"GmondConfPath"
};

static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);

#define TMAX_DEFAULT	60
#define DMAX_DEFAULT	0
static void dispatch_to_ganglia(char *name, 
				char *value, 
				char *type, 
				char *unit)
{
	int rval;
	Ganglia_metric gmetric = NULL;

	pthread_mutex_lock(&send_lock);
	/* create the message */
	gmetric = Ganglia_metric_create(global_context);
	if(!gmetric) {
		ERROR("Unable to allocate gmetric structure. Exiting");
		goto out;
	}

	if( !(name && value && type)) {
		ERROR("Incorrect options supplied, exiting");
		goto out;
	}
	rval = Ganglia_metric_set( gmetric, name, value, type, unit, 
			GANGLIA_SLOPE_UNSPECIFIED,
			TMAX_DEFAULT, DMAX_DEFAULT);

	/* TODO: make this less ugly later */
	switch(rval) {
		case 1:
			ERROR("gmetric parameters invalid. exiting.");
			goto out; 
		case 2:
			ERROR("one of your parameters has an invalid character '\"'. exiting.");
			goto out;
		case 3:
			ERROR("the type parameter \"%s\" is not a valid type. exiting.", type);
			goto out;
		case 4: ERROR("the value parameter \"%s\" does not represent a number. exiting.", value);
			goto out;
	}

	/* send the message */
	rval = Ganglia_metric_send(gmetric, send_channels);
	if(rval) {
		ERROR("There was an error sending to %d of the send channels.", rval);
	}

out:
	/* cleanup */
	if (gmetric) {
		Ganglia_metric_destroy(gmetric); /* not really necessary but for symmetry */
	}

	pthread_mutex_unlock(&send_lock);
	return ;
}

static int value_list_to_metricname(char *buffer, size_t buffer_size, 
	value_list_t const *vl)
{
	snprintf(buffer, buffer_size, "%s_%s%s_%s", vl->host, 
		vl->plugin, vl->plugin_instance, vl->type_instance);
	return 0;
}

/*
 * must be thread safe
 */
static int ganglia_write(const data_set_t *ds, 
			const value_list_t *vl, 
		user_data_t __attribute__((unused)) *user_data)
{
	int i = 0;
	char metricname[512];
	char value[32];
	char *type = NULL;

	if (value_list_to_metricname(metricname, sizeof(metricname), vl))
		return -1;

	for (i = 0;i < vl->values_len;i++) {
		switch(ds->ds[i].type) {
		case DS_TYPE_DERIVE:
			snprintf(value, 32, "%"PRIi64, vl->values[i].derive);
			type = "uint32";
			break;
		case DS_TYPE_GAUGE:
			snprintf(value, 32, "%lf", vl->values[i].gauge);
			type = "double";
			break;
		case DS_TYPE_COUNTER:
			snprintf(value, 32, "%llu", vl->values[i].counter);
			type = "uint32";
			break;
		case DS_TYPE_ABSOLUTE:
			snprintf(value, 32, "%"PRIi64, vl->values[i].absolute);
			type = "uint32";
			break;
		default:
			return EINVAL;
		}
		dispatch_to_ganglia(metricname, value, type, 
				(char *)vl->type_instance);
	}

	return 0;
}

static int file_exist(const char *path)
{
	struct stat st;
	int ret = 0;

	ret = stat(path, &st);
	if (ret) {
		ERROR("failed to stat %s", path);
		return 0;
	}

	if (!S_ISREG (st.st_mode)) {
		ERROR("%s is not a regular file", path);
		return 0;	
	}
	return 1;
}

static int ganglia_init(void )
{
	INFO("ganglia plugin init");
	/* create the global context */
	global_context = Ganglia_pool_create(NULL);
	if(!global_context) {
		ERROR("Unable to create global context. Exiting");
		return -1;
	}

	/* parse the configuration file */
	if (NULL == gmondconfpath) {
		ERROR("You must config the path of gmond config file");
		return -1;
	}	

	if (!file_exist(gmondconfpath)) {
		ERROR("conf file: %s not exist", gmondconfpath);
		return -1;
	}
	gmond_config = Ganglia_gmond_config_create(gmondconfpath, 0);

	/* build the udp send channels */
	send_channels = Ganglia_udp_send_channels_create(global_context, gmond_config);
	if(!send_channels) {
		ERROR("Unable to create ganglia send channels. Exiting");
		return -1;
	}

	return 0;
}

static int ganglia_config(const char *key, const char *value)
{
	INFO("ganglia plugin config key: %s value: %s", key, value);
	if (strcasecmp("GmondConfPath", key) == 0) {
		if (gmondconfpath != NULL)
			free(gmondconfpath);
		gmondconfpath = strdup(value);
	} else {
		ERROR("ganglia plugin config error");
		return -1;
	}

	return 0;
}

void module_register(void)
{
	plugin_register_config("ganglia", ganglia_config, 
			config_keys, config_keys_num);
	plugin_register_init("ganglia", ganglia_init);
	plugin_register_write("ganglia", ganglia_write, NULL);
}
