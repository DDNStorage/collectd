/**
 * collectd - src/filedata_read.c
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

#include <regex.h>
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "list.h"
#include "filedata_common.h"
#include "filedata_xml.h"
#include "filedata_config.h"
#include "filedata_read.h"
#include "utils_cache.h"
#include <stdbool.h>

static int
__filedata_entry_read(struct filedata_entry *entry,
		      char *pwd,
		      struct list_head *path_head);

static int filedata_init_instance_value(value_t *value,
					const char *type,
					uint64_t v)
{
	if (strcmp(type, "derive") == 0) {
		value->derive = (derive_t)v;
	} else if (strcmp(type, "gauge") == 0) {
		value->gauge = (gauge_t)v;
	} else if (strcmp(type, "counter") == 0) {
		value->counter = (counter_t)v;
	} else if (strcmp(type, "absolute") == 0) {
		value->absolute = (absolute_t)v;
	} else {
		ERROR("unsupported type %s\n", type);
		return -EINVAL;
	}
	return 0;
}

static void filedata_dispatch_values(value_list_t *vl,
				     const char *tsdb_name,
				     const char *tsdb_tags,
				     uint64_t value)
{
	FINFO("host %s, "
	      "plugin %s, "
	      "plugin_instance %s, "
	      "type %s, "
	      "type_instance %s, "
	      "tsdb_name %s, "
	      "tsdb_tags %s, "
	      "value %"PRIu64", "
	      "time %llu ns",
	      vl->host,
	      vl->plugin,
	      vl->plugin_instance,
	      vl->type,
	      vl->type_instance,
	      tsdb_name,
	      tsdb_tags,
	      value,
	      (unsigned long long)CDTIME_T_TO_NS(vl->time));

	plugin_dispatch_values(vl);
}

static void filedata_instance_submit(const char *host,
				     const char *plugin,
				     const char *plugin_instance,
				     const char *type,
				     const char *type_instance,
				     const char *tsdb_name,
				     const char *tsdb_tags,
				     uint64_t value,
				     cdtime_t time,
				     bool fill_first_value,
				     uint64_t first_value,
				     int query_interval)
{
	value_t values[1];
	value_list_t vl = VALUE_LIST_INIT;
	int status;
	char name[6 * DATA_MAX_NAME_LEN];

	vl.meta = meta_data_create();
	if (vl.meta == NULL) {
		FERROR("Submit: meta_data_create failed");
		return;
	}

	vl.values = values;
	vl.values_len = 1;
	sstrncpy(vl.host, host, sizeof(vl.host));
	sstrncpy(vl.plugin, plugin, sizeof(vl.plugin));
	sstrncpy(vl.plugin_instance, plugin_instance,
		 sizeof(vl.plugin_instance));
	sstrncpy(vl.type, type, sizeof(vl.type));
	sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
	status = meta_data_add_string(vl.meta, "tsdb_name", tsdb_name);
	if (status != 0) {
		FERROR("Submit: meta_data_add_string failed");
		goto out;
	}
	status = meta_data_add_string(vl.meta, "tsdb_tags", tsdb_tags);
	if (status != 0) {
		FERROR("Submit: meta_data_add_string failed");
		goto out;
	}

	if (!fill_first_value)
		goto skip;

	if (FORMAT_VL(name, sizeof(name), &vl) != 0) {
		FERROR("Submit: FORMAT_VL failed.");
		goto out;
	}

	/* if found means this is not first inserting */
	if (uc_check_name_existed(name))
		goto skip;

	status = filedata_init_instance_value(&(values[0]), type, first_value);
	if (status)
		goto out;
	/* use 1/2 of interval as average is better ?*/
	vl.time = time - plugin_get_interval() * query_interval;
	filedata_dispatch_values(&vl, tsdb_name, tsdb_tags, first_value);

skip:
	vl.time = time;
	status = filedata_init_instance_value(&(values[0]), type, value);
	if (status)
		goto out;
	filedata_dispatch_values(&vl, tsdb_name, tsdb_tags, value);
out:
	meta_data_destroy(vl.meta);
	vl.meta = NULL;
}

static struct filedata_subpath_field *
filedata_subpath_field_find(struct list_head *path_head,
			    const char *name)
{
	static struct filedata_subpath_field *subpath_field;
	struct filedata_subpath_fields *subpath_fields;
	struct filedata_subpath_field_type *type;
	int i;

	list_for_each_entry(subpath_fields,
			    path_head,
			    fpfs_linkage) {
		for (i = 1; i <= subpath_fields->fpfs_field_number; i++) {
			subpath_field = &subpath_fields->fpfs_fileds[i];
			type = subpath_field->fpf_type;
			if (strcmp(type->fpft_name, name) == 0)
				return subpath_field;
		}
	}
	return NULL;
}

static struct filedata_field *
filedata_field_find(struct filedata_field *fields,
		    int content_field_number,
		    const char *name)
{
	static struct filedata_field *content_field;
	struct filedata_field_type *type;
	int i;

	for (i = 1; i <= content_field_number; i++) {
		content_field = &fields[i];
		type = content_field->ff_type;
		if (strcmp(type->fft_name, name) == 0)
			return content_field;
	}

	return NULL;
}

static int filedata_key_field_get(char *field, size_t size, const char *name)
{
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

	return 0;
}

static int filedata_extag_value_find(const char *extra_tags,
				     char *tag_value,
				     const char *name)
{
	char *val;
	size_t len, count = 0;
	char key[MAX_TSDB_TAGS_LENGTH];

	snprintf(key, sizeof(key), "%s=", name);
	len = strlen(extra_tags);
	val = strstr(extra_tags, key);
	if (val == NULL) {
		WARNING("Not found key '%s' from extra_tags '%s'",
			name, extra_tags);
		goto out;
	}

	val += strlen(key); /* skip the prefix key */
	while (val < extra_tags + len && isspace(*val))
		val++;

	while (val < extra_tags + len && isgraph(*val)) {
		tag_value[count] = *val;
		++count;
		++val;
	}
out:
	tag_value[count] = '\0';
	return 0;
}

static int filedata_submit_option_get(struct filedata_submit_option *option,
				      struct list_head *path_head,
				      struct filedata_field_type **field_types,
				      struct filedata_field *fields,
				      int content_field_number,
				      int content_index,
				      char *value,
				      int size,
				      const char *ext_tags)
{
	int status = 0;
	regmatch_t matched_fields[3];
	char *pointer = option->lso_string;
	char *match_value = NULL;
	int max_size = size - 1;
	char *value_pointer = value;
	char type[TYPE_NAME_LEN + 1];
	char name[TYPE_NAME_LEN + 1];
	struct filedata_subpath_field *subpath_field;
	struct filedata_field *content_field;
	char key_field[MAX_SUBMIT_STRING_LENGTH];
	char tag_value[MAX_TSDB_TAGS_LENGTH];
	const char *pattern = "\\$\\{(subpath|content|key|extra_tag):([^}]+)\\}";
	static regex_t regex;
	static int regex_inited = 0;
	int i;

	if (regex_inited == 0) {
		regex_inited = 1;
		status = filedata_compile_regex(&regex, pattern);
		assert(status == 0);
	}

	while (1) {
		status = regexec(&regex,
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
				(pointer - option->lso_string);
			finish = matched_fields[i].rm_eo +
				(pointer - option->lso_string);

			if ((i != 0) && ((finish - start) > TYPE_NAME_LEN)) {
				status = -EINVAL;
				ERROR("%s length: %d is too long",
				       (i == 1) ? "type" : "name",
				       finish - start);
				goto out;
			}

			if (i == 1) {
				strncpy(type, option->lso_string + start,
					finish - start);
				type[finish - start] = '\0';
			} else if (i == 2) {
				strncpy(name, option->lso_string + start,
					finish - start);
				name[finish - start] = '\0';
			}
		}

		if (strcmp(type, "subpath") == 0) {
			subpath_field = filedata_subpath_field_find(path_head,
								    name);
			if (subpath_field == NULL) {
				ERROR("failed to get subpath for %s", name);
				break;
			}
			match_value = subpath_field->fpf_value;
		} else if (strcmp(type, "content") == 0) {
			content_field = filedata_field_find(fields,
							    content_field_number,
							    name);
			if (content_field == NULL) {
				ERROR("failed to get content for %s", name);
				break;
			}
			match_value = content_field->ff_string;
		} else if (strcmp(type, "key") == 0) {
			status = filedata_key_field_get(key_field,
						        sizeof(key_field),
						        name);
			if (status) {
				ERROR("failed to get field of key \"%s\"",
				      name);
				break;
			}
			match_value = key_field;
		} else if (strcmp(type, "extra_tag") == 0) {
			assert(strlen(ext_tags) < MAX_TSDB_TAGS_LENGTH);
			status = filedata_extag_value_find(ext_tags,
							   tag_value, name);
			if (status) {
				ERROR("failed to get value of extra tag %s %s",
				      name, ext_tags);
				break;
			}
			FINFO("Get extra_tag KV %s:%s from tags \"%s\"",
			      name, tag_value, ext_tags);
			match_value = tag_value;
		} else {
			ERROR("unknown type \"%s\"", type);
			status = -EINVAL;
			break;
		}

		if (strlen(match_value) + matched_fields[0].rm_so > max_size) {
			ERROR("option value overflows: size: %d", size);
			status = -EINVAL;
			break;
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

/* operation check have been done in filedata_check_math_entry() */
static uint64_t filedata_cal_math_value(uint64_t left, char *operation,
					uint64_t right)
{
	if (strncmp(operation, "-", 1) == 0)
		return left - right;
	if (strncmp(operation, "+", 1) == 0)
		return left + right;
	if (strncmp(operation, "*", 1) == 0)
		return left * right;
	if (strncmp(operation, "/", 1) == 0)
		return left / right;

	return 0;
}

static void
filedata_hash_math_entry_free(struct filedata_hash_math_entry *fhme)
{
	if (fhme) {
		free(fhme->fhme_host);
		free(fhme->fhme_plugin);
		free(fhme->fhme_plugin_instance);
		free(fhme->fhme_type);
		free(fhme->fhme_type_instance);
		free(fhme->fhme_key);
		free(fhme);
	}
}

static void
filedata_generate_hash_math_key(char *key, const char *tsdb_name,
				const char *tsdb_tags)
{
	memcpy(key, tsdb_name, strlen(tsdb_name));
	memcpy(key + strlen(tsdb_name), ",", 1);
	memcpy(key + strlen(tsdb_name) + 1, tsdb_tags,
	       strlen(tsdb_tags));
}

static int
filedata_add_math_instance(struct filedata_hash_math_entry **head,
			   const char *host, const char *plugin,
			   const char *plugin_instance,
			   const char *type,
			   const char *type_instance,
			   const char *tsdb_name,
			   const char *tsdb_tags, uint64_t value)
{
	struct filedata_hash_math_entry *fhme, *tmp;
	int status = 0;

	fhme = calloc(sizeof(*fhme), 1);
	if (!fhme) {
		status = -ENOMEM;
		goto failed;
	}
	fhme->fhme_key = calloc(strlen(tsdb_name) +
			   strlen(tsdb_tags) + 2, 1);
	if (!fhme->fhme_key) {
		status = -ENOMEM;
		goto failed;
	}
	filedata_generate_hash_math_key(fhme->fhme_key, tsdb_name,
					tsdb_tags);
	fhme->fhme_host = strdup(host);
	fhme->fhme_plugin = strdup(plugin);
	fhme->fhme_plugin_instance = strdup(plugin_instance);
	fhme->fhme_type = strdup(type);
	fhme->fhme_type_instance = strdup(type_instance);
	fhme->fhme_tsdb_name_len = strlen(tsdb_name);
	fhme->fhme_value = value;
	if (!fhme->fhme_host || !fhme->fhme_plugin ||
	    !fhme->fhme_plugin_instance ||
	    !fhme->fhme_type || !fhme->fhme_type_instance) {
		status = -ENOMEM;
		goto failed;
	}
	HASH_FIND_STR(*head, fhme->fhme_key, tmp);
	if (tmp) {
		status = -EEXIST;
		goto failed;
	}
	HASH_ADD_STR(*head, fhme_key, fhme);
failed:
	if (status)
		filedata_hash_math_entry_free(fhme);
	return status;
}

static int
filedata_add_math_instances(struct filedata_submit *submit,
			    const char *host, const char *plugin,
			    const char *plugin_instance,
			    const char *type,
			    const char *type_instance,
			    const char *tsdb_name,
			    const char *tsdb_tags, uint64_t value)
{
	struct filedata_math_entry *fme;
	int i, status = 0;

	for (i = 0; i < submit->fs_math_entry_num; i++) {
		fme = submit->fs_math_entries[i];
		/* we think it possible that @left_operand
		 * and @right_operand are same, something
		 * like A * A operation spotted by Li Xi.
		 */
		if (strncmp(fme->fme_left_operand, tsdb_name,
			    strlen(tsdb_name)) == 0) {
			status = filedata_add_math_instance(
					&fme->fme_left_htable,
					host, plugin, plugin_instance,
					type, type_instance, tsdb_name,
					tsdb_tags, value);
			if (status)
				break;
		}
		if (strncmp(fme->fme_right_operand, tsdb_name,
			    strlen(tsdb_name)) == 0) {
			status = filedata_add_math_instance(
					&fme->fme_right_htable,
					host, plugin, plugin_instance,
					type, type_instance,
					tsdb_name, tsdb_tags, value);
			if (status)
				break;
		}
	}

	return status;
}

static int filedata_submit(struct filedata_submit *submit,
			   struct list_head *path_head,
			   struct filedata_field_type **field_types,
			   struct filedata_field *fields,
			   int content_field_number,
			   int content_index,
			   uint64_t value,
			   const char *ext_tsdb_tags,
			   int ext_tags_used,
			   struct filedata_definition *fd,
			   cdtime_t time, int query_interval)
{
	char host[MAX_SUBMIT_STRING_LENGTH];
	char plugin[MAX_SUBMIT_STRING_LENGTH];
	char plugin_instance[MAX_SUBMIT_STRING_LENGTH];
	char type[MAX_SUBMIT_STRING_LENGTH];
	char type_instance[MAX_SUBMIT_STRING_LENGTH];
	char tsdb_name[MAX_SUBMIT_STRING_LENGTH];
	char tsdb_tags[MAX_TSDB_TAGS_LENGTH];
	int status;
	int n;
	const char *ext_tags = fd->extra_tags;
	uint64_t first_value = field_types[content_index]->fft_first_value;
	bool fill_first_value = false;

	/* don't fill first value if this is first time query */
	if ((field_types[content_index]->fft_flags &
		FILEDATA_FIELD_FLAG_FILL_FIRST_VALUE) &&
	    fd->fd_query_times > 1)
		fill_first_value = true;

	status = filedata_submit_option_get(&submit->fs_host,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, host,
					    MAX_SUBMIT_STRING_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get host");
		return status;
	}

	status = filedata_submit_option_get(&submit->fs_plugin,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, plugin,
					    MAX_SUBMIT_STRING_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get plugin");
		return status;
	}

	status = filedata_submit_option_get(&submit->fs_plugin_instance,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, plugin_instance,
					    MAX_SUBMIT_STRING_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get plugin_instance");
		return status;
	}

	status = filedata_submit_option_get(&submit->fs_type,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, type,
					    MAX_SUBMIT_STRING_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get type");
		return status;
	}

	status = filedata_submit_option_get(&submit->fs_type_instance,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, type_instance,
					    MAX_SUBMIT_STRING_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get type_instance");
		return status;
	}

	status = filedata_submit_option_get(&submit->fs_tsdb_name,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, tsdb_name,
					    MAX_SUBMIT_STRING_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get tsdb_name");
		return status;
	}

	status = filedata_submit_option_get(&submit->fs_tsdb_tags,
					    path_head, field_types,
					    fields, content_field_number,
					    content_index, tsdb_tags,
					    MAX_TSDB_TAGS_LENGTH,
					    ext_tags);
	if (status) {
		ERROR("submit: failed to get tsdb_name");
		return status;
	}

	if (ext_tags_used) {
		if (strlen(tsdb_tags) + strlen(ext_tsdb_tags) + 1 >=
		    MAX_TSDB_TAGS_LENGTH) {
			ERROR("submit: tsdb_tags too long");
			return -EINVAL;
		}

		if (strlen(tsdb_tags) > 0) {
			strncat(tsdb_tags, " ", 1);
			strncat(tsdb_tags, ext_tsdb_tags,
				MAX_TSDB_TAGS_LENGTH - 1);
		} else {
			strncpy(tsdb_tags, ext_tsdb_tags,
				MAX_TSDB_TAGS_LENGTH - 1);
		}
	}
	n = MAX_TSDB_TAGS_LENGTH - 1 - strlen(tsdb_tags);
	if (ext_tags && n > strlen(ext_tags) + 1) {
		if (strlen(tsdb_tags) > 0)
			strncat(tsdb_tags, " ", 1);
		strncat(tsdb_tags, ext_tags,
			MAX_TSDB_TAGS_LENGTH - 1 - strlen(tsdb_tags));
	} else if (ext_tags){
		FERROR("submit: ignore overflow extra tsdb tags");
	}

	if (submit->fs_math_entry_num) {
		status = filedata_add_math_instances(submit,
					host, plugin, plugin_instance,
					type, type_instance,
					tsdb_name, tsdb_tags, value);
		if (status)
			return status;
	}
	filedata_instance_submit(host, plugin, plugin_instance,
				 type, type_instance,
				 tsdb_name, tsdb_tags,
				 value, time, fill_first_value, first_value,
				 query_interval);
	return status;
}

static int filedata_data_submit(struct filedata_item_type *type,
				struct list_head *path_head,
				struct filedata_item_data *data,
				struct filedata_item *item)
{
	int i;

	for (i = 1; i <= type->fit_field_number; i++) {
		if (data->fid_fields[i].ff_allowed == 0)
			continue;
		if (type->fit_field_array[i]->fft_type == TYPE_NUMBER)
			filedata_submit(&type->fit_field_array[i]->fft_submit,
					path_head,
					type->fit_field_array,
					data->fid_fields,
					type->fit_field_number,
					i,
					data->fid_fields[i].ff_value,
					data->fid_ext_tags,
					data->fid_ext_tags_used,
					type->fit_definition,
					data->fid_query_time,
					item->fi_query_interval);
	}

	return 0;
}

static struct filedata_item_data *
filedata_item_data_alloc(struct filedata_item_type *type)
{
	int field_number = type->fit_field_number;
	struct filedata_item_data *data;
	int i;

	data = calloc(1, sizeof(struct filedata_item_data));
	if (data == NULL)
		return NULL;

	data->fid_fields = calloc(field_number + 1,
				  sizeof(struct filedata_field));
	if (data->fid_fields == NULL) {
		free(data);
		return NULL;
	}
	data->fid_field_number = field_number;

	for (i = 1; i <= field_number; i++)
		data->fid_fields[i].ff_type = type->fit_field_array[i];
	return data;
}

/* TODO: do we really need this? */
static void filedata_item_data_clean(struct filedata_item_data *data)
{
	int i;
	for (i = 1; i <= data->fid_field_number; i++) {
		data->fid_fields[i].ff_string[0] = '\0';
		data->fid_fields[i].ff_value = 0;
	}
}

static void filedata_item_data_free(struct filedata_item_data *data)
{
	free(data->fid_fields);
	free(data);
}

static int filedata_item_extend_form_tsdbtags(struct filedata_item_type *itype,
		struct filedata_item_data *data)
{
	int status = 0;
	regmatch_t matched_fields[3];
	char *pointer = itype->fit_ext_tags;
	char *match_value = NULL;
	int max_size = sizeof(itype->fit_ext_tags) - 1;
	char *value_pointer = data->fid_ext_tags;
	char type[TYPE_NAME_LEN + 1];
	char name[TYPE_NAME_LEN + 1];
	struct filedata_item_type_extend_field *ext_field;
	const char *pattern = "\\$\\{(extendfield):([^}]+)\\}";
	static regex_t regex;
	static int regex_inited = 0;
	int i;

	if (regex_inited == 0) {
		regex_inited = 1;
		status = filedata_compile_regex(&regex, pattern);
		assert(status == 0);
	}

	while (1) {
		status = regexec(&regex,
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
				(pointer - itype->fit_ext_tags);
			finish = matched_fields[i].rm_eo +
				(pointer - itype->fit_ext_tags);

			if ((i != 0) && ((finish - start) > TYPE_NAME_LEN)) {
				status = -EINVAL;
				FERROR("%s length: %d is too long",
				       (i == 1) ? "type" : "name",
				       finish - start);
				goto out;
			}

			if (i == 1) {
				strncpy(type, itype->fit_ext_tags + start,
					finish - start);
				type[finish - start] = '\0';
			} else if (i == 2) {
				strncpy(name, itype->fit_ext_tags + start,
					finish - start);
				name[finish - start] = '\0';
			}
		}

		if (strcmp(type, "extendfield") == 0) {
			ext_field = filedata_item_extend_field_find(itype, name);
			if (ext_field == NULL) {
				FERROR("failed to get extend field for %s", name);
				break;
			}
			match_value = ext_field->fitef_value;
		} else {
			FERROR("unknown type \"%s\"", type);
			status = -EINVAL;
			break;
		}

		if (strlen(match_value) + matched_fields[0].rm_so > max_size) {
			FERROR("extend tsdb tags overflows: %d", max_size);
			status = -EINVAL;
			break;
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

	FINFO("status: %d tsdb tags: %s", status, data->fid_ext_tags);
out:
	return status;
}

static int filedata_item_extend_parse(struct filedata_item_type *type,
				      struct filedata_item_data *data)
{
	struct filedata_item_type_extend *ext;
	struct filedata_item_type_extend_field *ext_field;
	regmatch_t *match_fields;
	char *pos = NULL;
	int len;
	int status;

	if (list_empty(&type->fit_extends))
		return 0;

	list_for_each_entry(ext, &type->fit_extends, fite_linkage) {
		assert(ext->fite_field_index <= type->fit_field_number);
		match_fields = calloc(ext->fite_field_number + 1,
				      sizeof (regmatch_t));
		if (match_fields == NULL) {
			FERROR("Extended parse: not enough memory");
			return -ENOMEM;
		}
		status = regexec(&ext->fite_regex,
				 data->fid_fields[ext->fite_field_index].ff_string,
				 ext->fite_field_number + 1,
				 match_fields,
				 0);

		if (status == REG_NOMATCH) {
			FINFO("Extended parse: failed to parse field: \"%s\"",
			    data->fid_fields[ext->fite_field_index].ff_string);
			free(match_fields);
			status = -EINVAL;
			goto out;
		}

		list_for_each_entry(ext_field, &ext->fite_fields, fitef_linkage) {
			assert(ext_field->fitef_index <= ext->fite_field_number);

			pos = data->fid_fields[ext->fite_field_index].ff_string +
				match_fields[ext_field->fitef_index].rm_so;
			len = match_fields[ext_field->fitef_index].rm_eo -
				match_fields[ext_field->fitef_index].rm_so;

			strncpy(ext_field->fitef_value, pos, len);
			ext_field->fitef_value[len] = '\0';
		}

		free(match_fields);
		match_fields = NULL;
	}

	status = filedata_item_extend_form_tsdbtags(type, data);
	if (status)
		return status;

	data->fid_ext_tags_used = 1;

out:
	return status;
}

static int _filedata_parse(struct filedata_item_type *type,
			   const char *content, cdtime_t time,
			   struct list_head *path_head)
{
	const char *previous = content;
	regmatch_t *fields;
	struct filedata_item_data *data;
	char string[MAX_JOBSTAT_FIELD_LENGTH];
	unsigned long long value;
	int status = 0;
	struct filedata_item *ret_item = NULL;

	fields = calloc(type->fit_field_number + 1, sizeof(regmatch_t));
	if (fields == NULL) {
		ERROR("parse: not enough memory");
		return -1;
	}

	data = filedata_item_data_alloc(type);
	if (data == NULL) {
		ERROR("parse: not enough memory");
		status = -1;
		goto out;
	}
	data->fid_query_time = time;

	while (1) {
		int i = 0;
		int nomatch = regexec(&type->fit_regex, previous,
				      type->fit_field_number + 1, fields, 0);
		if (nomatch)
			break;

		filedata_item_data_clean(data);

		for (i = 0; i <= type->fit_field_number; i++) {
			int start;
			int finish;

			if (fields[i].rm_so == -1) {
				ERROR("unused field %d", i);
				break;
			}

			start = fields[i].rm_so + (previous - content);
			finish = fields[i].rm_eo + (previous - content);
			if (i != 0) {
				value_type_t value_type;
				if (finish - start >
				    MAX_JOBSTAT_FIELD_LENGTH - 1) {
					ERROR("field is too long %d",
					      finish - start);
					status = -1;
					break;
				}

				strncpy(string,
					content + start, finish - start);
				string[finish - start] = '\0';

				strncpy(data->fid_fields[i].ff_string, string,
					MAX_JOBSTAT_FIELD_LENGTH);
				FINFO("type %s, field %d, bytes %d:%d,"
				      " value %s",
				      type->fit_type_name, i,
				      start, finish, string);
				value_type = type->fit_field_array[i]->fft_type;
				if (value_type == TYPE_STRING) {
					/* TODO: combine string algorithm */
				} else if (value_type == TYPE_NUMBER) {
					value = strtoull(string,
							 NULL, 10);
					data->fid_fields[i].ff_value = value;
				} else {
					assert(value_type == TYPE_NULL);
				}
			}
		}

		if (filedata_item_match(data->fid_fields,
					type->fit_field_number,
					type, &ret_item)) {
			status = filedata_item_extend_parse(type, data);
			if (status == 0) {
				filedata_data_submit(type, path_head, data,
						     ret_item);
			} else {
				FINFO("Parse: failed to do extended parse");
			}
		}
		previous += fields[0].rm_eo;
	}
	filedata_item_data_free(data);
out:
	free(fields);
	return status;
}

static int filedata_parse_context_regular_exp(struct filedata_item_type *type,
					      const char *content,
					      cdtime_t time,
					      struct list_head *path_head)
{
	const char *previous = content;
	regmatch_t *fields;
	char *buf;
	int status = 0;

	fields = calloc(type->fit_context_regex.re_nsub + 1,
			sizeof(regmatch_t));
	if (fields == NULL) {
		ERROR("parse: not enough memory");
		return -1;
	}

	buf = malloc(strlen(content) + 1);
	if (buf == NULL) {
		ERROR("parse: not enough memory");
		status = -1;
		goto out;
	}

	while (1) {
		int start;
		int finish;
		int nomatch = regexec(&type->fit_context_regex, previous,
				      type->fit_context_regex.re_nsub + 1,
				      fields, 0);
		if (nomatch)
			break;

		start = fields[0].rm_so + (previous - content);
		finish = fields[0].rm_eo + (previous - content);
		strncpy(buf,
			content + start, finish - start);
		buf[finish - start] = '\0';

		status = _filedata_parse(type, buf, time, path_head);
		if (status)
			break;
		previous += fields[0].rm_eo;
	}

	free(buf);
out:
	free(fields);
	return status;
}

static int filedata_parse_context_start_end(struct filedata_item_type *type,
					    const char *content, cdtime_t time,
					    struct list_head *path_head)
{
	const char *previous = content;
	char *buf;
	int status = 0;
	char *p_start = NULL;
	size_t start_len = strlen(type->fit_context_start);
	const char *p_end = content + strlen(content) - 1;

	buf = malloc(strlen(content) + 1);
	if (buf == NULL) {
		ERROR("parse: not enough memory");
		status = -1;
		goto out;
	}

	/* avoid infinite loop */
	while (previous - content < strlen(content)) {
		p_start = strstr(previous, type->fit_context_start);
		if (!p_start)
			break;

		p_start += start_len;

		if (strlen(type->fit_context_end)) {
			p_end = strstr(p_start, type->fit_context_end);
			if (!p_end)
				break;
		}
		strncpy(buf, p_start, p_end - p_start + 1);

		status = _filedata_parse(type, buf, time, path_head);
		if (status)
			break;
		previous = p_end;
	}

	free(buf);
out:
	return status;
}

static int filedata_parse(struct filedata_item_type *type,
			const char *content, cdtime_t time,
			struct list_head *path_head)
{
	if (type->fit_flags & FILEDATA_ITEM_FLAG_CONTEXT_REGULAR_EXP)
		return filedata_parse_context_regular_exp(type, content,
							  time, path_head);
	else if (type->fit_flags & FILEDATA_ITEM_FLAG_CONTEXT_START_END)
		return filedata_parse_context_start_end(type, content,
							time, path_head);
	else
		return _filedata_parse(type, content, time, path_head);
}

#define START_FILE_SIZE (1048576)
#define MAX_FILE_SIZE   (1048576 * 1024)

static int filedata_read_file(const char *path, char **buf, ssize_t *data_size)
{
	int bufsize = START_FILE_SIZE;
	char *filebuf;
	char *pointer;
	int status;
	int fd;
	char *tmp;
	ssize_t offset = 0;
	ssize_t size;
	ssize_t left_size = 0;

	filebuf = malloc(bufsize);
	if (filebuf == NULL) {
		ERROR("jobstat: failed to allocate memory");
		return -1;
	}

	pointer = filebuf;
	left_size = bufsize;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("failed to open %s", path);
		free(filebuf);
		return -1;
	}

read_again:
	size = read(fd, pointer, left_size - 1);
	if (size < 0) {
		ERROR("failed to read %s", path);
		status = -1;
		goto err;
	} else if (size == 0) {
		/* finished */
		filebuf[offset] = '\0';
	} else {
		assert(size > 0);
		assert(size <= left_size - 1);
		offset += size;
		if (size == left_size - 1) {
			if (bufsize > MAX_FILE_SIZE) {
				ERROR("file is too big");
				status = -1;
				goto err;
			}
			bufsize *= 2;
			tmp = realloc(filebuf, bufsize);
			if (tmp == NULL) {
				ERROR("failed to allocate memory");
				status = -1;
				goto err;
			}
			filebuf = tmp;
		}
		pointer = filebuf + offset;
		left_size = bufsize - offset;
		assert(offset < bufsize);
		goto read_again;
	}

	close(fd);
	*buf = filebuf;
	*data_size = offset;
	FINFO("buff size %d, file size :%zd:%zd",
	      bufsize, offset, strlen(filebuf));
	return 0;
err:
	close(fd);
	free(filebuf);
	return status;
}

static int filedata_write_file(const char *path, char *value)
{
	struct stat st;
	ssize_t count;
	int status;
	int fd;

	status = stat(path, &st);
	if (status) {
		ERROR("failed to stat %s", path);
		return -1;
	}

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		FERROR("failed to open %s", path);
		return -1;
	}

	count = write(fd, value, strlen(value));
	if (count < 0) {
		ERROR("failed to write %s: %s", path, strerror(errno));
		status = -1;
	} else if (count < strlen(value)) {
		ERROR("wrote only %zd", count);
		status = -1;
	} else {
		FINFO("wrote content '%s' to '%s'", value, path);
	}
	close(fd);

	return status;
}

static struct filedata_subpath_fields *
filedata_subpath_fields_alloc(struct filedata_entry	*entry)
{
	struct filedata_subpath_fields *fields;
	int field_number = entry->fe_subpath_field_number;
	struct filedata_subpath_field_type *path;
	int i;

	fields = calloc(1, sizeof(struct filedata_subpath_fields));
	if (fields == NULL)
		return NULL;

	fields->fpfs_fileds = calloc(field_number + 1,
				     sizeof(struct filedata_subpath_field));
	if (fields->fpfs_fileds == NULL) {
		free(fields);
		return NULL;
	}

	i = 1;
	list_for_each_entry(path,
			    &entry->fe_subpath_field_types,
			    fpft_linkage) {
		fields->fpfs_fileds[i].fpf_type = path;
		i++;
	}

	INIT_LIST_HEAD(&fields->fpfs_linkage);
	fields->fpfs_field_number = field_number;
	return fields;
}

void filedata_subpath_fields_free(struct filedata_subpath_fields *fields)
{
	free(fields->fpfs_fileds);
	free(fields);
}

/*
 Return 1 when matched, 0 if not, -1 if error.
*/
static int
filedata_subpath_match(char *string,
		       struct filedata_entry *entry,
		       struct list_head *path_head,
		       struct filedata_subpath_fields **subpath)
{
	const char *pointer = string;
	regmatch_t *fields;
	int i = 0;
	int status = 0;
	int matched = 0;
	struct filedata_subpath_fields *subpath_fields;

	subpath_fields = filedata_subpath_fields_alloc(entry);
	if (subpath_fields == NULL) {
		ERROR("not enough memory");
		return -1;
	}

	fields = calloc(entry->fe_subpath_field_number + 1, sizeof(regmatch_t));
	if (fields == NULL) {
		ERROR("not enough memory");
		status = -1;
		goto out;
	}

	while (1) {
		status = regexec(&entry->fe_subpath_regex,
				 pointer,
				 entry->fe_subpath_field_number + 1,
				 fields, 0);
		if (status) {
			if (matched != 1)
				status = 0;
			else
				status = 1;
			break;
		} else if (matched) {
			ERROR("too many matches");
			status = -1;
			break;
		}
		matched++;
		for (i = 0; i <= entry->fe_subpath_field_number; i++) {
			int start;
			int finish;
			struct filedata_subpath_field *field;
			if (fields[i].rm_so == -1)
				break;
			start = fields[i].rm_so + (pointer - string);
			finish = fields[i].rm_eo + (pointer - string);
			if (i != 0) {
				field = &subpath_fields->fpfs_fileds[i];
				strncpy(field->fpf_value,
					string + start, finish - start);
				FINFO("subpath %d, bytes %d:%d, value %.*s\n",
				      i,
				      start, finish,
				      (finish - start), string + start);
			}
		}
		pointer += fields[0].rm_eo;
	}
out:
	if (status == 1) {
		list_add_tail(&subpath_fields->fpfs_linkage, path_head);
		*subpath = subpath_fields;
	} else {
		filedata_subpath_fields_free(subpath_fields);
	}
	free(fields);

	return status;
}

static int
filedata_entry_read_directory(struct filedata_entry *entry,
			      char *path,
			      struct list_head *path_head)
{
	struct filedata_entry *child;
	int status = 0;
	struct stat st;

	assert(list_empty(&entry->fe_active_item_types));
	assert(list_empty(&entry->fe_item_types));

	status = stat(path, &st);
	if (status) {
		INFO("failed to stat %s: %s", path, strerror(errno));
		return 0;
	}

	list_for_each_entry(child,
			    &entry->fe_active_children,
			    fe_active_linkage) {
		status = __filedata_entry_read(child, path, path_head);
		if (status)
			WARNING("entry path: %s not found, continue", path);
	}
	return 0;
}

static int
filedata_entry_read_constant(struct filedata_entry *entry,
			     char *pwd, char *subpath,
			     struct list_head *path_head)
{
	char path[MAX_NAME_LENGH + 1];
	int status = 0;
	char *filebuf;
	struct filedata_item_type *type;
	ssize_t size;
	int max_size = sizeof(path) - 1;
	cdtime_t query_time;

	strncpy(path, pwd, max_size);
	max_size -= strlen(pwd);
	if (subpath[0] != '/' &&
	    strlen(path) != 0 &&
	    path[strlen(path) - 1] != '/') {
		strncat(path, "/", max_size);
		max_size -= 1;
	} else if (subpath[0] == '/' &&
		   strlen(path) != 0 &&
		   path[strlen(path) - 1] == '/') {
		subpath++;
	}
	strncat(path, subpath, max_size);
	max_size -= strlen(subpath);
	assert(entry->fe_mode == S_IFREG || entry->fe_mode == S_IFDIR);

	FINFO("going down to path %s", path);
	if (entry->fe_mode == S_IFREG) {
		assert(list_empty(&entry->fe_active_children));
		assert(list_empty(&entry->fe_children));
		query_time = cdtime();
		if (entry->fe_definition->fd_read_file != NULL) {
			status = entry->fe_definition->fd_read_file(path,
				&filebuf, &size,
				(entry->fe_definition)->fd_private_definition.fd_private_data);
		} else {
			status = filedata_read_file(path, &filebuf, &size);
		}
		if (status) {
			ERROR("unable to read file %s", path);
			return status;
		}
		list_for_each_entry(type,
				    &entry->fe_active_item_types,
				    fit_active_linkage) {
			assert(!list_empty(&type->fit_items));
			FINFO("parsing %s for type %s",
			      path,
			      type->fit_type_name);
			status = filedata_parse(type, filebuf, query_time,
						path_head);
			if (status) {
				ERROR("unable to parse file %s for type %s",
				      path,
				      type->fit_type_name);
				free(filebuf);
				return status;
			}
		}
		free(filebuf);
		if (entry->fe_write_after_read) {
			status = filedata_write_file(path, entry->fe_write_content);
			if (status) {
				ERROR("unable to write file %s:%s",
				      path, entry->fe_write_content);
				return status;
			}
		}
	} else {
		filedata_entry_read_directory(entry,
					      path,
					      path_head);
	}
	return 0;
}

int
__filedata_entry_read(struct filedata_entry *entry,
		      char *pwd,
		      struct list_head *path_head)
{
	char *subpath;
	int status = 0;
	DIR *parent_dir;
	struct dirent *dp;
	struct filedata_subpath_fields *subpath_fields = NULL;

	assert(entry->fe_active);
	if (entry->fe_subpath_type == SUBPATH_CONSTANT) {
		subpath = entry->fe_subpath;
		status = filedata_entry_read_constant(entry,
					pwd, subpath, path_head);
	} else {
		assert(entry->fe_subpath_type == SUBPATH_REGULAR_EXPRESSION);
		parent_dir = opendir(pwd);
		if (parent_dir == NULL) {
			FINFO("unable to open proc directory: %s", pwd);
			return -1;
		}
		while ((dp = readdir(parent_dir)) != NULL) {
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0) {
				continue;
			}

			status = filedata_subpath_match(dp->d_name,
							entry,
							path_head,
							&subpath_fields);
			if (status == 1) {
				subpath = dp->d_name;
				status = filedata_entry_read_constant(entry,
						pwd, subpath, path_head);

				list_del_init(&subpath_fields->fpfs_linkage);
				filedata_subpath_fields_free(subpath_fields);
				subpath_fields = NULL;

				if (status)
					break;
			} else if (status) {
				ERROR("failed to match subpath %s", dp->d_name);
				break;
			}
		}
		closedir(parent_dir);
	}

	return status;
}

static int
filedata_submit_math_instance(struct filedata_entry *entry)
{
	int status = 0;
	struct filedata_hash_math_entry *fhme, *tmp, *fhme_found;
	struct filedata_math_entry *fme;
	char *search_key = NULL;
	uint64_t m_value;
	char *tsdb_tags;

	list_for_each_entry(fme, &entry->fe_definition->fd_math_entries,
			    fme_linkage) {
		HASH_ITER(hh, fme->fme_left_htable, fhme, tmp) {
			tsdb_tags = fhme->fhme_key +
				    fhme->fhme_tsdb_name_len + 1;
			search_key = calloc(strlen(fme->fme_right_operand) +
					    strlen(tsdb_tags) + 2, 1);
			if (!search_key) {
				status = -ENOMEM;
				break;
			}
			filedata_generate_hash_math_key(search_key,
					fme->fme_right_operand, tsdb_tags);
			HASH_FIND_STR(fme->fme_right_htable, search_key,
				      fhme_found);
			if (fhme_found) {
				m_value = filedata_cal_math_value(
							fhme->fhme_value,
							fme->fme_operation,
							fhme_found->fhme_value);
				filedata_instance_submit(fhme->fhme_host,
						fhme->fhme_plugin,
						fhme->fhme_plugin_instance,
						fme->fme_type ?
						fme->fme_type : fhme->fhme_type,
						fme->fme_type_instance ?
						fme->fme_type_instance :
						fhme->fhme_type_instance,
						fme->fme_tsdb_name, tsdb_tags,
						m_value, cdtime(),
						false, 0, 1);
			}
			free(search_key);
		}
	}

	/* free memory now */
	list_for_each_entry(fme, &entry->fe_definition->fd_math_entries,
			    fme_linkage) {
		HASH_ITER(hh, fme->fme_left_htable, fhme, tmp) {
			HASH_DEL(fme->fme_left_htable, fhme);
			filedata_hash_math_entry_free(fhme);
		}
		HASH_ITER(hh, fme->fme_right_htable, fhme, tmp) {
			HASH_DEL(fme->fme_right_htable, fhme);
			filedata_hash_math_entry_free(fhme);
		}
		fme->fme_left_htable = NULL;
		fme->fme_right_htable = NULL;
	}

	return status;
}

int filedata_entry_read(struct filedata_entry *entry, char *pwd)
{
	int status, status1;
	struct list_head path_head;

	INIT_LIST_HEAD(&path_head);
	status = __filedata_entry_read(entry, pwd, &path_head);

	status1 = filedata_submit_math_instance(entry);
	if (!status && status1)
		status = status1;

	return status;
}
