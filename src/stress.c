/**
 * collectd - src/lustre.c
 * Copyright (C) 2013  Li Xi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Li Xi <lixi at ddn.com>
 **/

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include <pthread.h>

enum stress_option {
	STRESS_OPTION_HOST = 0,
	STRESS_OPTION_PLUGIN,
	STRESS_OPTION_PLUGIN_INSTANCE,
	STRESS_OPTION_TYPE,
	STRESS_OPTION_TYPE_INSTANCE,
	STRESS_OPTION_MAX,
};

struct stress_thread_data {
	pthread_t	std_thread;
	pthread_attr_t	std_attr;
	int		std_thread_id;
	int		std_number[STRESS_OPTION_MAX];
};

struct stress_timer {
	struct timeval st_startRealTime;
	struct timeval st_startUserTime;
	struct timeval st_startSysTime;

	struct timeval st_stopRealTime;
	struct timeval st_stopUserTime;
	struct timeval st_stopSysTime;
};

struct stress_environment {
	int				 se_thread_number;
	struct stress_thread_data	*se_thread_datas;
	struct stress_timer		 se_timer;
	int				 se_commit_number;
	int				 se_number[STRESS_OPTION_MAX];
};

struct stress_environment *stress_environment_g = NULL;

void stress_timer_init(struct stress_timer *t)
{
	memset(t, 0, sizeof(struct stress_timer));
}

void stress_timer_start(struct stress_timer *t)
{
	struct rusage ru;

	if (gettimeofday(&(t->st_startRealTime), NULL)) {
		ERROR("Error in gettimeofday");
		exit(10);
	}

	if (getrusage(RUSAGE_SELF, &ru)) {
		ERROR("Error in getrusage");
		exit(11);
	}

	memcpy(&(t->st_startUserTime), &(ru.ru_utime), sizeof(struct timeval ));
	memcpy(&(t->st_startSysTime), &(ru.ru_stime), sizeof(struct timeval ));
}

void stress_timer_stop(struct stress_timer *t)
{
	struct rusage ru;

	if(gettimeofday( &(t->st_stopRealTime), NULL ))
	{
		ERROR("Error in gettimeofday");
		exit(10);
	}

	if( getrusage( RUSAGE_SELF, &ru ))
	{
		ERROR("Error in getrusage");
		exit(11);
	}

	memcpy(&(t->st_stopUserTime), &(ru.ru_utime), sizeof( struct timeval ));
	memcpy(&(t->st_stopSysTime), &(ru.ru_stime), sizeof( struct timeval ));
}

double stress_timer_realtime(const struct stress_timer *t)
{
	double value;

	value = t->st_stopRealTime.tv_sec - t->st_startRealTime.tv_sec;
	value += (t->st_stopRealTime.tv_usec -
		  t->st_startRealTime.tv_usec)/1000000.0;

	return value;
}

double stress_timer_usertime(const struct stress_timer *t)
{
	double value;

	value = t->st_stopUserTime.tv_sec - t->st_startUserTime.tv_sec;
	value += (t->st_stopUserTime.tv_usec -
		  t->st_startUserTime.tv_usec)/1000000.0;

	return value;
}

double stress_timer_systime(const struct stress_timer *t)
{
	double value;

	value = t->st_stopSysTime.tv_sec - t->st_startSysTime.tv_sec;
	value += (t->st_stopSysTime.tv_usec -
		  t->st_startSysTime.tv_usec)/1000000.0;

	return value;
}


static void stress_instance_submit(const char *host,
				   const char *plugin,
				   const char *plugin_instance,
				   const char *type,
				   const char *type_instance,
				   derive_t value)
{
	value_t values[1];
	int status;
	value_list_t vl = VALUE_LIST_INIT;

	values[0].derive = value;

	vl.values = values;
	vl.values_len = 1;
	sstrncpy (vl.host, host, sizeof (vl.host));
	sstrncpy (vl.plugin, plugin, sizeof (vl.plugin));
	sstrncpy (vl.plugin_instance, plugin_instance, sizeof (vl.plugin_instance));
	sstrncpy (vl.type, type, sizeof (vl.type));
	sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
#if 0
	INFO("host %s, "
	     "plugin %s, "
	     "plugin_instance %s, "
	     "type %s, "
	     "type_instance %s, "
	     "value %llu",
	     vl.host,
	     vl.plugin,
	     vl.plugin_instance,
	     vl.type,
	     vl.type_instance,
	     (unsigned long long)vl.values[0].derive);
#endif

	status = plugin_dispatch_values(&vl);
	if (status)
		ERROR("failt to dispatch vaue: "
		      "host %s, "
		      "plugin %s, "
		      "plugin_instance %s, "
		      "type %s, "
		      "type_instance %s, "
		      "value %llu",
		      vl.host,
		      vl.plugin,
		      vl.plugin_instance,
		      vl.type,
		      vl.type_instance,
		      (unsigned long long)vl.values[0].derive);
}

static inline long tv_delta(struct timeval *s, struct timeval *e)
{
	long c = e->tv_sec - s->tv_sec;
	c *= 1000;
	c += (long int)(e->tv_usec - s->tv_usec) / 1000;
	return c;
}

#define STRESS_FOREACH_ONE(_index, _number, _i) \
    for(_index[_i] = 0; _index[_i] < _number[_i]; _index[_i]++)


#define STRESS_FOREACH(_index, _number) \
    STRESS_FOREACH_ONE(_index, _number, 0) \
    STRESS_FOREACH_ONE(_index, _number, 1) \
    STRESS_FOREACH_ONE(_index, _number, 2) \
    STRESS_FOREACH_ONE(_index, _number, 3) \
    STRESS_FOREACH_ONE(_index, _number, 4)

#define MAX_NAME 1024

const char *stress_option_prefix[STRESS_OPTION_MAX] = {
	"host",
	"plugin",
	"instance",
	"type",
	"type_instance",
};

void stress_get_option(int thread_id, char *option,
		       int index, int option_index)
{
	if (option_index == STRESS_OPTION_TYPE) {
		snprintf(option, MAX_NAME, "derive");
	} else if (option_index == STRESS_OPTION_HOST) {
		snprintf(option, MAX_NAME, "thread_%d-%s_%d",
			 thread_id,
			 stress_option_prefix[option_index], index);
	} else {
		snprintf(option, MAX_NAME, "%s_%d",
			 stress_option_prefix[option_index], index);
	}
}

void *stress_proc(void *data)
{
	int index[STRESS_OPTION_MAX];
	char option[STRESS_OPTION_MAX][MAX_NAME];
	int i;
	derive_t value = 0;
	struct stress_thread_data *thread_data;

	thread_data = (struct stress_thread_data *)data;

	STRESS_FOREACH(index, thread_data->std_number) {
		for (i = 0; i < STRESS_OPTION_MAX; i++) {
			stress_get_option(thread_data->std_thread_id,
					  option[i], index[i], i);
		}
		stress_instance_submit(option[0], option[1],
				       option[2], option[3],
				       option[4], value);
		value++;
	}
	return 0;
}

static void stress_complete()
{
	struct stress_thread_data *data;
	int i;

	for (i = 0 ; i < stress_environment_g->se_thread_number; i++) {
		data = &stress_environment_g->se_thread_datas[i];
		pthread_join(data->std_thread, NULL);
	}
}

static int stress_read(void)
{
	struct stress_thread_data *data;
	int status;
	int i;
	double realtime;

	if (stress_environment_g == NULL) {
		ERROR("lustre plugin is not configured properly");
		return -1;
	}

	for (i = 0 ; i < stress_environment_g->se_thread_number; i++) {
		data = &stress_environment_g->se_thread_datas[i];
		status = pthread_create(&data->std_thread,
					&data->std_attr,
					stress_proc,
					data);
		if (status) {
			ERROR("Error creating threads");
			return -1;
		}
	}
	stress_timer_start(&stress_environment_g->se_timer);
	stress_complete();
	stress_timer_stop(&stress_environment_g->se_timer);
	realtime = stress_timer_realtime(&stress_environment_g->se_timer);
	ERROR("time: %.5f for %d commits with %d threads, %.5f commits/second",
	      realtime,
	      stress_environment_g->se_commit_number,
	      stress_environment_g->se_thread_number,
	      stress_environment_g->se_commit_number / realtime);
	return 0;
}


void stress_fini()
{
	if (stress_environment_g == NULL)
		return;
	if (stress_environment_g->se_thread_datas)
		free(stress_environment_g->se_thread_datas);
	free(stress_environment_g);
}

static int stress_config(oconfig_item_t *ci)
{
	int i;
	struct stress_thread_data *thread_data;
	int j;
	int value;
	int status;

	stress_environment_g = calloc(1, sizeof (struct stress_environment));
	if (stress_environment_g == NULL) {
		ERROR("not enough memory");
		return -1;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		status = cf_util_get_int(child, &value);
		if (status) {
			ERROR("stress: failed to get value for \"%s\"",
			      child->key);
			break;
		}
		if (strcasecmp(child->key, "Thread") == 0) {
			stress_environment_g->se_thread_number = value;
		} else if (strcasecmp(child->key, "Host") == 0) {
			stress_environment_g->se_number[STRESS_OPTION_HOST]
				= value;
		} else if (strcasecmp(child->key, "Plugin") == 0) {
			stress_environment_g->se_number[STRESS_OPTION_PLUGIN]
				= value;
		} else if (strcasecmp(child->key, "PluginInstance") == 0) {
			stress_environment_g->se_number[STRESS_OPTION_PLUGIN_INSTANCE]
				= value;
		} else if (strcasecmp(child->key, "TypeInstance") == 0) {
			stress_environment_g->se_number[STRESS_OPTION_TYPE_INSTANCE]
				= value;
		}
	}

	if (stress_environment_g->se_thread_number < 1) {
		WARNING("stress plugin: thread number invalid: %i, "
			"use 1 instead",
			stress_environment_g->se_thread_number);
		stress_environment_g->se_thread_number = 1;
	}

	/* Should always be 1 */
	stress_environment_g->se_number[STRESS_OPTION_TYPE] = 1;
	stress_environment_g->se_commit_number =
		stress_environment_g->se_thread_number;
	for (i = 0; i < STRESS_OPTION_MAX; i++) {
		if (stress_environment_g->se_number[i] < 1) {
			WARNING("stress plugin: Invalid number: %i, use 1 instead",
				stress_environment_g->se_number[i]);
			stress_environment_g->se_number[i] = 1;
		}
		stress_environment_g->se_commit_number *=
			stress_environment_g->se_number[i];
	}

	stress_environment_g->se_thread_datas =
		calloc(stress_environment_g->se_thread_number,
		       sizeof (struct stress_thread_data));
	if (stress_environment_g->se_thread_datas == NULL) {
		ERROR("stress plugin: Not enough memory");
		free(stress_environment_g);
		stress_environment_g = NULL;
		return -1;
	}

	for (i = 0; i < stress_environment_g->se_thread_number; i++) {
		thread_data = &stress_environment_g->se_thread_datas[i];

		thread_data->std_thread_id = i;
		pthread_attr_init(&thread_data->std_attr);

		for (j = 0; j < STRESS_OPTION_MAX; j++) {
			thread_data->std_number[j] = stress_environment_g->se_number[j];
		}
	}
	return 0;
}

void module_register (void)
{
	plugin_register_complex_config("stress", stress_config);
	plugin_register_read("stress", stress_read);
} /* void module_register */
