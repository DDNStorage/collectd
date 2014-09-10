#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "utils_cache.h"
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
		ERROR("ganglia: Unable to allocate gmetric structure.");
		goto out;
	}

	if( !(name && value && type)) {
		ERROR("ganglia: Incorrect options supplied.");
		goto out;
	}
	rval = Ganglia_metric_set(gmetric, name, value, type, unit, 
				  GANGLIA_SLOPE_UNSPECIFIED,
				  TMAX_DEFAULT, DMAX_DEFAULT);

	/* TODO: make this less ugly later */
	switch(rval) {
		case 1:
			ERROR("ganglia: Gmetric parameters invalid.");
			goto out; 
		case 2:
			ERROR("ganglia: One of your parameters has an invalid "
			      "character '\"'.");
			goto out;
		case 3:
			ERROR("ganglia: The type parameter \"%s\" is not a "
			      "valid type.", type);
			goto out;
		case 4: ERROR("ganglia: The value parameter \"%s\" does not "
			      "represent a number.", value);
			goto out;
	}

	/* send the message */
	rval = Ganglia_metric_send(gmetric, send_channels);
	if(rval)
		ERROR("ganglia: There was an error sending to %d of the send "
		      "channels.", rval);

out:
	/* cleanup */
	if (gmetric)
		Ganglia_metric_destroy(gmetric); /* not really necessary but for symmetry */

	pthread_mutex_unlock(&send_lock);
	return ;
}

static int value_list_to_metricname(char *buffer,
				    size_t buffer_size, 
				    value_list_t const *vl)
{
	snprintf(buffer, buffer_size, "%s_%s-%s_%s", vl->host, 
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
	gauge_t	*rate;

	if (ds->ds_num != 1) {
		ERROR ("ganglia: The \"%s\" type (data set) has more than one "
		       "data source. This is currently not supported by this plugin. "
		       "Sorry.", ds->type);
		return (EINVAL);
	}

	rate = uc_get_rate(ds, vl);
	if (rate == NULL) {
		char ident[6 * DATA_MAX_NAME_LEN];
		FORMAT_VL (ident, sizeof (ident), vl);
		ERROR ("ganglia: Unable to read the current rate of \"%s\".",
		       ident);
		return (ENOENT);
	}

	if (isnan(rate[0])) {
		sfree(rate);
		return 0;
	}

	if (value_list_to_metricname(metricname, sizeof(metricname), vl)) {
		sfree(rate);
		return -1;
	}

	switch(ds->ds[i].type) {
	case DS_TYPE_GAUGE:
		snprintf(value, 32, "%f", vl->values[i].gauge);
		type = "double";
		break;
	case DS_TYPE_DERIVE:
	case DS_TYPE_COUNTER:
	case DS_TYPE_ABSOLUTE:
		snprintf(value, 32, "%f", rate[0]);
		type = "uint32";
		break;
	default:
		sfree(rate);
		return EINVAL;
	}
	INFO("ganglia: Metricname: %s value: %s", metricname, value);
	dispatch_to_ganglia(metricname, value, type, 
			    (char *)vl->type_instance);

	sfree(rate);
	return 0;
}

static int file_exist(const char *path)
{
	struct stat st;
	int ret = 0;

	ret = stat(path, &st);
	if (ret) {
		ERROR("ganglia: Failed to stat %s", path);
		return 0;
	}

	if (!S_ISREG (st.st_mode)) {
		ERROR("ganglia: %s is not a regular file", path);
		return 0;	
	}
	return 1;
}

static int ganglia_init(void )
{
	/* create the global context */
	global_context = Ganglia_pool_create(NULL);
	if(!global_context) {
		ERROR("ganglia: Unable to create global context.");
		return -1;
	}

	/* parse the configuration file */
	if (NULL == gmondconfpath) {
		ERROR("ganglia: You must config the path of gmond config file");
		return -1;
	}	

	if (!file_exist(gmondconfpath)) {
		ERROR("ganglia: Conf file: %s not exist", gmondconfpath);
		return -1;
	}
	gmond_config = Ganglia_gmond_config_create(gmondconfpath, 0);

	/* build the udp send channels */
	send_channels = Ganglia_udp_send_channels_create(global_context, gmond_config);
	if(!send_channels) {
		ERROR("ganglia: Unable to create ganglia send channels.");
		return -1;
	}

	return 0;
}

static int ganglia_config(const char *key, const char *value)
{
	INFO("ganglia: plugin config key: %s value: %s", key, value);
	if (strcasecmp("GmondConfPath", key) == 0) {
		if (gmondconfpath != NULL)
			free(gmondconfpath);
		gmondconfpath = strdup(value);
	} else {
		ERROR("ganglia: plugin config error");
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
