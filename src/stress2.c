/**
 * collectd - src/stress2.c
 * Copyright (C) 2017  Li Xi
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
#include "list.h"
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <regex.h>
#include <stdlib.h>

#define STRESS_MAX_NAME 1024
#define MAX_TSDB_TAGS_LENGTH	1024
#define VARIABLE_NAME_LEN	64

enum stress_option {
	STRESS_OPTION_HOST = 0,
	STRESS_OPTION_PLUGIN,
	STRESS_OPTION_PLUGIN_INSTANCE,
	STRESS_OPTION_TYPE,
	STRESS_OPTION_TYPE_INSTANCE,
	STRESS_OPTION_MAX,
};

struct stress_variable_type {
	int			svt_value_number;
	int			svt_update_interval;
	char			svt_name[STRESS_MAX_NAME];
	char			svt_print[STRESS_MAX_NAME];
	struct list_head	svt_linkage;
};

struct stress_variable {
	int				 sv_value_current;
	struct stress_variable_type	*sv_type;
};

struct stress_thread_data {
	pthread_t		 std_thread;
	pthread_attr_t		 std_attr;
	int			 std_thread_id;
	int			 std_variable_number;
	struct stress_variable	*std_variables;
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
	int				 se_variable_number;
	struct list_head		 se_variable_types;
	char				 se_options[STRESS_OPTION_MAX][STRESS_MAX_NAME];
	char				 se_tsdb_name[STRESS_MAX_NAME];
	char				 se_tsdb_tags[STRESS_MAX_NAME];
	regex_t				 se_regex;
	/* How many times this plugin has been readed*/
	int				 se_read_number;
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
				   const char *tsdb_name,
				   const char *tsdb_tags,
				   derive_t value,
				   cdtime_t interval)
{
	value_t values[1];
	int status;
	value_list_t vl = VALUE_LIST_INIT;

	values[0].derive = value;

	vl.meta = meta_data_create();
	vl.interval = interval;
	if (vl.meta == NULL) {
		ERROR("Submit: meta_data_create failed");
		return;
	}

	vl.values = values;
	vl.values_len = 1;
	sstrncpy (vl.host, host, sizeof (vl.host));
	sstrncpy (vl.plugin, plugin, sizeof (vl.plugin));
	sstrncpy (vl.plugin_instance, plugin_instance, sizeof (vl.plugin_instance));
	sstrncpy (vl.type, type, sizeof (vl.type));
	sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
	status = meta_data_add_string(vl.meta, "tsdb_name", tsdb_name);
	if (status != 0) {
		ERROR("Submit: meta_data_add_string failed");
		goto out;
	}
	status = meta_data_add_string(vl.meta, "tsdb_tags", tsdb_tags);
	if (status != 0) {
		ERROR("Submit: meta_data_add_string failed");
		goto out;
	}
#if 0
	INFO("host %s, "
	     "plugin %s, "
	     "plugin_instance %s, "
	     "type %s, "
	     "type_instance %s, "
	     "tsdb_name %s, "
	     "tsdb_tags %s, "
	     "value %llu ",
	     vl.host,
	     vl.plugin,
	     vl.plugin_instance,
	     vl.type,
	     vl.type_instance,
	     tsdb_name,
	     tsdb_tags,
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
out:
	meta_data_destroy(vl.meta);
	vl.meta = NULL;
}

static inline long tv_delta(struct timeval *s, struct timeval *e)
{
	long c = e->tv_sec - s->tv_sec;
	c *= 1000;
	c += (long int)(e->tv_usec - s->tv_usec) / 1000;
	return c;
}

static int stress_key_field_get(char *field, size_t size, const char *name)
{
	if (strcmp(name, "hostname") == 0) {
		if (strlen(hostname_g) >= size) {
			ERROR("stress plugin: hostname `%s' is too long",
			      hostname_g);
			return -1;
		} else {
			strncpy(field, hostname_g, size - 1);
		}
	}

	return 0;
}

static int stress_variable_field_get(char *field, size_t size, const char *name,
				     const char *print_string,
				     struct stress_thread_data *thread_data)
{
	char variable_value[STRESS_MAX_NAME];
	struct stress_variable_type *type;
	struct stress_variable *variable;
	int read_number = stress_environment_g->se_read_number;
	int value;
	int i;

	if (strcmp(name, "hostname") == 0) {
		if (strlen(hostname_g) >= size) {
			strncpy(field, hostname_g, size - 1);
			field[size - 1] = '\0';
			WARNING("hostname: %s is too long, "
				"truncate it to: \"%s\"", hostname_g, field);
		} else {
			strncpy(field, hostname_g, size - 1);
		}
	}

	for (i = 0; i < thread_data->std_variable_number; i++) {
		variable = &thread_data->std_variables[i];
		type = variable->sv_type;
		if (strcmp(type->svt_name, name) == 0) {
			value = variable->sv_value_current;
			if (type->svt_update_interval != 0) {
				value += type->svt_value_number * (read_number / type->svt_update_interval);
			}
			snprintf(variable_value, STRESS_MAX_NAME, print_string,
				 value);
			if (strlen(variable_value) >= size) {
				ERROR("stress plugin: variable is too long");
				return -1;
			} else {
				strncpy(field, variable_value, size - 1);
			}
			return 0;
		}
	}

	return 0;
}

static int stress_compile_regex(regex_t *preg, const char *regex)
{
	int status = regcomp(preg, regex, REG_EXTENDED | REG_NEWLINE);
	if (status != 0) {
		char error_message[STRESS_MAX_NAME];
		regerror(status, preg, error_message, STRESS_MAX_NAME);
		return -1;
	}
	return 0;
}

static int stress_string_translate(const char *origin_string,
				   char *value,
				   int size,
				   struct stress_thread_data *thread_data)
{
	int status = 0;
	regmatch_t matched_fields[3];
	const char *pointer = origin_string;
	char *match_value = NULL;
	int max_size = size - 1;
	char *value_pointer = value;
	char type[STRESS_MAX_NAME];
	char name[STRESS_MAX_NAME];
	char field_value[STRESS_MAX_NAME];
	char *separator;
	char *print_string;
	int i;

	while (pointer < origin_string + strlen(origin_string)) {
		status = regexec(&stress_environment_g->se_regex,
				 pointer,
				 3,
				 matched_fields, 0);
		if (status) {
			/* No match */
			if (strlen(pointer) > max_size) {
				status = -EINVAL;
				break;
			}
			strncpy(value_pointer, pointer, max_size);
			value_pointer += strlen(pointer);
			max_size -= strlen(pointer);
			status = 0;
			break;
		}
		for (i = 0; i <= 2; i++) {
			int start;
			int finish;
			if (matched_fields[i].rm_so == -1)
				break;
			start = matched_fields[i].rm_so +
				(pointer - origin_string);
			finish = matched_fields[i].rm_eo +
				(pointer - origin_string);

			if ((i != 0) && ((finish - start) > VARIABLE_NAME_LEN)) {
				status = -EINVAL;
				ERROR("%s length: %d is too long",
				       (i == 1) ? "type" : "name",
				       finish - start);
				goto out;
			}

			if (i == 1) {
				strncpy(type, origin_string + start,
					finish - start);
				type[finish - start] = '\0';
			} else if (i == 2) {
				strncpy(name, origin_string + start,
					finish - start);
				name[finish - start] = '\0';
			}
		}

		if (strcmp(type, "key") == 0) {
			status = stress_key_field_get(field_value,
						      sizeof(field_value),
						      name);
			if (status) {
				ERROR("failed to get field of key \"%s\"",
				      name);
				status = -EINVAL;
				goto out;
			}
			match_value = field_value;
		} else if (strcmp(type, "variable") == 0) {
			separator = strstr(name, ":");
			if (separator == NULL) {
				ERROR("stress plugin: failed to parse variable with name \"%s\"",
				      name);
				status = -EINVAL;
				goto out;
			}
			if (strlen(separator) <= 1) {
				ERROR("stress plugin: no print format is given in \"%s\"",
				      name);
				status = -EINVAL;
				goto out;
			}
			*separator = '\0';
			print_string = separator + 1;

			status = stress_variable_field_get(field_value,
						           sizeof(field_value),
						           name,
						           print_string,
						           thread_data);
			if (status) {
				ERROR("failed to get field of key \"%s\"",
				      name);
				goto out;
			}
			match_value = field_value;
		} else {
			ERROR("stress plugin: unknown type to translate \"%s\"", type);
			status = -EINVAL;
			goto out;
		}

		if (strlen(match_value) + matched_fields[0].rm_so > max_size) {
			ERROR("stress plugin: value overflows: size: %d", size);
			status = -EINVAL;
			goto out;
		}

		if (matched_fields[0].rm_so > 0) {
			strncpy(value_pointer, pointer,
				matched_fields[0].rm_so);
			value_pointer += matched_fields[0].rm_so;
			value_pointer[0] = '\0';
			max_size -= matched_fields[0].rm_so;
		}

		strncpy(value_pointer, match_value, max_size);
		value_pointer += strlen(match_value);
		max_size -= strlen(match_value);
		match_value = NULL;

		pointer += matched_fields[0].rm_eo;
	}

out:
	return status;
}

/* Generate a random value between [0, max - 1] */
static int stress_random_value(int max)
{
	return random() % max;
}

void *stress_proc(void *data)
{
	char option_values[STRESS_OPTION_MAX][STRESS_MAX_NAME];
	char *option;
	char tsdb_name[STRESS_MAX_NAME];
	char tsdb_tags[MAX_TSDB_TAGS_LENGTH];
	int i;
	derive_t value = 0;
	struct stress_thread_data *thread_data;
	struct stress_variable *variable;
	int not_finished = 1;
	int ret;
	cdtime_t interval = cf_get_default_interval();
	int number = 0;
	int thread_index;

	thread_data = (struct stress_thread_data *)data;
	for (i = 0; i < thread_data->std_variable_number; i++) {
		variable = &(thread_data->std_variables[i]);
		variable->sv_value_current = 0;
	}

	while (not_finished) {
		thread_index = number % stress_environment_g->se_thread_number;
		number++;

		if (thread_index == thread_data->std_thread_id) {
			for (i = 0; i < STRESS_OPTION_MAX; i++) {
				option = stress_environment_g->se_options[i];
				ret = stress_string_translate(option, option_values[i],
							      STRESS_MAX_NAME,
							      thread_data);
				if (ret) {
					ERROR("stress plugin: failed to get option value [%d], aborting",
					      i);
					break;
				}
			}
	
			option = stress_environment_g->se_tsdb_tags;
			ret = stress_string_translate(option, tsdb_tags,
						      STRESS_MAX_NAME,
						      thread_data);
			if (ret) {
				ERROR("stress plugin: failed to get tsdb_tags value, aborting");
				break;
			}
	
			option = stress_environment_g->se_tsdb_name;
			ret = stress_string_translate(option, tsdb_name,
						      STRESS_MAX_NAME,
						      thread_data);
			if (ret) {
				ERROR("stress plugin: failed to get tsdb_name value, aborting");
				break;
			}
	
			stress_instance_submit(option_values[0], option_values[1],
					       option_values[2], option_values[3],
					       option_values[4], tsdb_name, tsdb_tags, value,
					       interval);
			/* Add an random value, so no problem for DERIVE and other data source types */
			value += stress_random_value(1024);
		}

		for (i = 0; i < thread_data->std_variable_number; i++) {
			variable = &(thread_data->std_variables[i]);
			if (variable->sv_value_current + 1 < variable->sv_type->svt_value_number) {
				variable->sv_value_current++;
				break;
			}
			variable->sv_value_current = 0;
			/* Carry over to next variable */
		}
		if (i == thread_data->std_variable_number)
			not_finished = 0;
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
		ERROR("stress plugin is not configured properly");
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
	stress_environment_g->se_read_number++;
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

static int stress_variable_find_add(struct stress_environment *environment,
				    struct stress_variable_type *variable_type)
{
	struct stress_variable_type *type;

	list_for_each_entry(type,
	                    &stress_environment_g->se_variable_types,
	                    svt_linkage) {
		if (strcmp(type->svt_name, variable_type->svt_name) == 0) {
			ERROR("stress plugin: multiple variables with same name \"%s\"",
			      type->svt_name);
			return -1;
		}
	}
	list_add_tail(&variable_type->svt_linkage, &environment->se_variable_types);
	environment->se_variable_number++;
	return 0;
}

static int stress_config_variable(struct stress_environment *environment,
				  oconfig_item_t *ci)
{
	struct stress_variable_type *variable_type;
	oconfig_item_t *child;
	int value;
	int ret;

	variable_type = calloc(1, sizeof(*variable_type));
	if (variable_type == NULL) {
		ERROR("stress plugin: calloc failed.");
		return -1;
	}

	for (int i = 0; i < ci->children_num; i++) {
		child = ci->children + i;
		if (strcasecmp("Name", child->key) == 0) {
			ret = cf_util_get_string_buffer(child, variable_type->svt_name,
							sizeof(variable_type->svt_name));
			if (ret) {
				ERROR("stress plugin: failed to get string for \"Name\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "Number") == 0) {
			ret = cf_util_get_int(child, &value);
			if (ret) {
				ERROR("stress: failed to config \"Variable\" because of Number");
				goto out;
			}
			if (value < 1) {
				ERROR("stress: invalid Number value `%d' for `Variable'", value);
				goto out;
			}
			variable_type->svt_value_number = value;
		} else if (strcasecmp(child->key, "UpdateIterval") == 0) {
			ret = cf_util_get_int(child, &value);
			if (ret) {
				ERROR("stress: failed to config \"Variable\" because of UpdateIterval");
				goto out;
			}
			if (value < 0) {
				ERROR("stress: invalid UpdateIterval value `%d' for `Variable'", value);
				goto out;
			}
			variable_type->svt_update_interval = value;
		} else {
			ERROR("stress plugin: Option `%s' not allowed here.", child->key);
			goto out;
		}
	}
	ret = stress_variable_find_add(environment, variable_type);
	if (ret)
		goto out;
	environment->se_commit_number *= variable_type->svt_value_number;
	return 0;
out:
	free(variable_type);
	return -1;
}

static int stress_config(oconfig_item_t *ci)
{
	int i;
	struct stress_thread_data *thread_data;
	int value;
	int status;
	struct stress_variable *variables;
	struct stress_variable *variable;
	struct stress_variable_type *variable_type;
	struct stress_variable_type *n;
	int variable_index = 0;
	const char *stress_pattern = "\\$\\{(key|variable):([^}]+)\\}";

	srand(time(NULL));

	stress_environment_g = calloc(1, sizeof(struct stress_environment));
	if (stress_environment_g == NULL) {
		ERROR("not enough memory");
		return -1;
	}
	stress_environment_g->se_variable_number = 0;
	stress_environment_g->se_commit_number = 1;
	INIT_LIST_HEAD(&stress_environment_g->se_variable_types);
	stress_environment_g->se_read_number = 0;
	status = stress_compile_regex(&stress_environment_g->se_regex, stress_pattern);
	if (status) {
		ERROR("stress: failed to compile regex `%s'", stress_pattern);
		goto out;
	}
	

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp(child->key, "Thread") == 0) {
	    		status = cf_util_get_int(child, &value);
			if (status) {
				ERROR("stress: failed to get value for \"Thread\"");
				goto out;
			}
			stress_environment_g->se_thread_number = value;
		} else if (strcasecmp(child->key, "Variable") == 0) {
			status = stress_config_variable(stress_environment_g, child);
			if (status) {
				ERROR("stress: failed to config \"Variable\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "Host") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_options[STRESS_OPTION_HOST],
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"Host\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "Plugin") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_options[STRESS_OPTION_PLUGIN],
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"Plugin\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "PluginInstance") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_options[STRESS_OPTION_PLUGIN_INSTANCE],
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"PluginInstance\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "Type") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_options[STRESS_OPTION_TYPE],
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"Type\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "TypeInstance") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_options[STRESS_OPTION_TYPE_INSTANCE],
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"TypeInstance\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "TsdbName") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_tsdb_name,
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"TsdbName\"");
				goto out;
			}
		} else if (strcasecmp(child->key, "TsdbTags") == 0) {
			status = cf_util_get_string_buffer(child, stress_environment_g->se_tsdb_tags,
							   STRESS_MAX_NAME);
			if (status) {
				ERROR("stress plugin: failed to get string for \"TsdbTags\"");
				goto out;
			}
		} else {
			ERROR("stress plugin: Option `%s' not allowed here", child->key);
			goto out;
		}
	}

	for (i = 0; i < STRESS_OPTION_MAX; i++) {
		if (strlen(stress_environment_g->se_options[i]) == 0) {
			ERROR("stress plugin: Option `%d' not configured", i);
			goto out;
		}
	}

	if (strlen(stress_environment_g->se_tsdb_name) == 0) {
		ERROR("stress plugin: Option `TsdbName' not configured");
		goto out;
	}

	if (strlen(stress_environment_g->se_tsdb_tags) == 0) {
		ERROR("stress plugin: Option `TsdbTags' not configured");
		goto out;
	}

	if (stress_environment_g->se_thread_number < 1) {
		WARNING("stress plugin: thread number invalid: %i, "
			"use 1 instead",
			stress_environment_g->se_thread_number);
		stress_environment_g->se_thread_number = 1;
	}

	if (stress_environment_g->se_variable_number < 1) {
		ERROR("stress plugin: no variable is configured");
		goto out;
	}

	stress_environment_g->se_thread_datas =
		calloc(stress_environment_g->se_thread_number,
		       sizeof(struct stress_thread_data));
	if (stress_environment_g->se_thread_datas == NULL) {
		ERROR("stress plugin: Not enough memory");
		goto out;
	}

	for (i = 0; i < stress_environment_g->se_thread_number; i++) {
		thread_data = &stress_environment_g->se_thread_datas[i];

		thread_data->std_thread_id = i;
		pthread_attr_init(&thread_data->std_attr);
		variables = calloc(1, stress_environment_g->se_variable_number *
				   sizeof(struct stress_variable));
		if (variables == NULL) {
			ERROR("stress plugin: Not enough memory");
			i--;
			goto out_variable;
		}

		thread_data->std_variable_number = stress_environment_g->se_variable_number;
		thread_data->std_variables = variables;
		variable_index = 0;
		list_for_each_entry(variable_type,
				    &stress_environment_g->se_variable_types,
				    svt_linkage) {
			variable = &thread_data->std_variables[variable_index];
			variable->sv_type = variable_type;
			variable_index++;
		}
	}
	return 0;
out_variable:
	for (; i >= 0; i--) {
		thread_data = &stress_environment_g->se_thread_datas[i];
		variables = thread_data->std_variables;
		free(variables);
	}
	free(stress_environment_g->se_thread_datas);
out:
	list_for_each_entry_safe(variable_type,
				 n,
	                         &stress_environment_g->se_variable_types,
	                         svt_linkage) {
		list_del_init(&variable_type->svt_linkage);
		free(variable_type);
	}
	free(stress_environment_g);
	return -1;
}

void module_register (void)
{
	plugin_register_complex_config("stress2", stress_config);
	plugin_register_read("stress2", stress_read);
} /* void module_register */
