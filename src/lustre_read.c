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

#include <regex.h>
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "list.h"
#include "lustre_common.h"
#include "lustre_xml.h"
#include "lustre_config.h"
#include "lustre_read.h"

static void lustre_instance_submit(const char *host,
				   const char *plugin,
				   const char *plugin_instance,
				   const char *type,
				   const char *type_instance,
				   const char *tsdb_name,
				   const char *tsdb_tags,
				   uint64_t value)
{
	value_t values[1];
	value_list_t vl = VALUE_LIST_INIT;
	int status;

	if (strcmp(type, "derive") == 0) {
		values[0].derive = value;
	} else if (strcmp(type, "gauge") == 0) {
		values[0].gauge = value;
	} else if (strcmp(type, "counter") == 0) {
		values[0].counter = value;
	} else if (strcmp(type, "absolute") == 0) {
		values[0].absolute = value;
	} else {
		ERROR("unsupported type %s\n", type);
		return;
	}

	vl.meta = meta_data_create();
	if (vl.meta == NULL) {
		LERROR("Submit: meta_data_create failed");
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
		LERROR("Submit: meta_data_add_string failed");
		goto out;
	}
	status = meta_data_add_string(vl.meta, "tsdb_tags", tsdb_tags);
	if (status != 0) {
		LERROR("Submit: meta_data_add_string failed");
		goto out;
	}
	LINFO("host %s, "
	      "plugin %s, "
	      "plugin_instance %s, "
	      "type %s, "
	      "type_instance %s, "
	      "tsdb_name %s, "
	      "tsdb_tags %s, "
      	      "value %llu",
	      vl.host,
	      vl.plugin,
	      vl.plugin_instance,
	      vl.type,
	      vl.type_instance,
	      tsdb_name,
	      tsdb_tags,
	      (unsigned long long)vl.values[0].derive);

	plugin_dispatch_values(&vl);
out:
	meta_data_destroy(vl.meta);
	vl.meta = NULL;
}

static struct lustre_subpath_field *
lustre_subpath_field_find(struct list_head *path_head,
			  const char *name)
{
	static struct lustre_subpath_field *subpath_field;
	struct lustre_subpath_fields *subpath_fields;
	struct lustre_subpath_field_type *type;
	int i;

	list_for_each_entry(subpath_fields,
			    path_head,
			    lpfs_linkage) {
		for (i = 1; i <= subpath_fields->lpfs_field_number; i++) {
			subpath_field = &subpath_fields->lpfs_fileds[i];
			type = subpath_field->lpf_type;
			if (strcmp(type->lpft_name, name) == 0)
				return subpath_field;
		}
	}
	return NULL;
}

static struct lustre_field *
lustre_field_find(struct lustre_field *fields,
		  int content_field_number,
		  const char *name)
{
	static struct lustre_field *content_field;
	struct lustre_field_type *type;
	int i;

	for (i = 1; i <= content_field_number; i++) {
		content_field = &fields[i];
		type = content_field->lf_type;
		if (strcmp(type->lft_name, name) == 0)
			return content_field;
	}

	return NULL;
}

static int lustre_key_field_get(char *field, size_t size, const char *name)
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

static int lustre_submit_option_get(struct lustre_submit_option *option,
				    struct list_head *path_head,
				    struct lustre_field_type **field_types,
				    struct lustre_field *fields,
				    int content_field_number,
				    int content_index,
				    char *value,
				    int size)
{
	int status = 0;
	regmatch_t matched_fields[3];
	char *pointer = option->lso_string;
	char *match_value = NULL;
	int max_size = size - 1;
	char *value_pointer = value;
	char type[TYPE_NAME_LEN + 1];
	char name[TYPE_NAME_LEN + 1];
	struct lustre_subpath_field *subpath_field;
	struct lustre_field *content_field;
	char key_field[MAX_SUBMIT_STRING_LENGTH];
	const char *pattern = "\\$\\{(subpath|content|key):([^}]+)\\}";
	static regex_t regex;
	static int regex_inited = 0;
	int i;

	if (regex_inited == 0) {
		regex_inited = 1;
		status = lustre_compile_regex(&regex, pattern);
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
			subpath_field = lustre_subpath_field_find(path_head,
								  name);
			if (subpath_field == NULL) {
				ERROR("failed to get subpath for %s", name);
				break;
			}
			match_value = subpath_field->lpf_value;
		} else if (strcmp(type, "content") == 0) {
			content_field = lustre_field_find(fields,
							  content_field_number,
							  name);
			if (content_field == NULL) {
				ERROR("failed to get content for %s", name);
				break;
			}
			match_value = content_field->lf_string;
		} else if (strcmp(type, "key") == 0) {
			status = lustre_key_field_get(key_field,
						      sizeof(key_field),
						      name);
			if (status) {
				ERROR("failed to get field of key \"%s\"",
				      name);
				break;
			}
			match_value = key_field;
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
	if (regex_inited)
		regfree(&regex);
	return status;
}

static int lustre_submit(struct lustre_submit *submit,
			 struct list_head *path_head,
			 struct lustre_field_type **field_types,
			 struct lustre_field *fields,
			 int content_field_number,
			 int content_index,
			 uint64_t value,
			 const char *ext_tsdb_tags,
			 int ext_tags_used)
{
	char host[MAX_SUBMIT_STRING_LENGTH];
	char plugin[MAX_SUBMIT_STRING_LENGTH];
	char plugin_instance[MAX_SUBMIT_STRING_LENGTH];
	char type[MAX_SUBMIT_STRING_LENGTH];
	char type_instance[MAX_SUBMIT_STRING_LENGTH];
	char tsdb_name[MAX_SUBMIT_STRING_LENGTH];
	char tsdb_tags[MAX_TSDB_TAGS_LENGTH];
	int status;

	status = lustre_submit_option_get(&submit->ls_host,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, host,
					  MAX_SUBMIT_STRING_LENGTH);
	if (status) {
		ERROR("submit: failed to get host");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_plugin,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, plugin,
					  MAX_SUBMIT_STRING_LENGTH);
	if (status) {
		ERROR("submit: failed to get plugin");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_plugin_instance,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, plugin_instance,
					  MAX_SUBMIT_STRING_LENGTH);
	if (status) {
		ERROR("submit: failed to get plugin_instance");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_type,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, type,
					  MAX_SUBMIT_STRING_LENGTH);
	if (status) {
		ERROR("submit: failed to get type");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_type_instance,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, type_instance,
					  MAX_SUBMIT_STRING_LENGTH);
	if (status) {
		ERROR("submit: failed to get type_instance");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_tsdb_name,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, tsdb_name,
					  MAX_SUBMIT_STRING_LENGTH);
	if (status) {
		ERROR("submit: failed to get tsdb_name");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_tsdb_tags,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, tsdb_tags,
					  MAX_TSDB_TAGS_LENGTH);
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
	lustre_instance_submit(host, plugin, plugin_instance,
			       type, type_instance,
			       tsdb_name, tsdb_tags,
			       value);
	return status;
}

static int lustre_data_submit(struct lustre_item_type *type,
			      struct list_head *path_head,
			      struct lustre_item_data *data)
{
	int i;

	for (i = 1; i <= type->lit_field_number; i++) {
		if (data->lid_fields[i].lf_allowed == 0)
			continue;
		if (type->lit_field_array[i]->lft_type == TYPE_NUMBER)
			lustre_submit(&type->lit_field_array[i]->lft_submit,
				      path_head,
				      type->lit_field_array,
				      data->lid_fields,
				      type->lit_field_number,
				      i,
				      data->lid_fields[i].lf_value,
				      data->lid_ext_tags,
				      data->lid_ext_tags_used);
	}

	return 0;
}

static struct lustre_item_data *
lustre_item_data_alloc(struct lustre_item_type *type)
{
	int field_number = type->lit_field_number;
	struct lustre_item_data *data;
	int i;

	data = calloc(1, sizeof(struct lustre_item_data));
	if (data == NULL)
		return NULL;

	data->lid_fields = calloc(field_number + 1,
				  sizeof(struct lustre_field));
	if (data->lid_fields == NULL) {
		free(data);
		return NULL;
	}
	data->lid_filed_number = field_number;

	for (i = 1; i <= field_number; i++)
		data->lid_fields[i].lf_type = type->lit_field_array[i];
	return data;
}

/* TODO: do we really need this? */
static void lustre_item_data_clean(struct lustre_item_data *data)
{
	int i;
	for (i = 1; i <= data->lid_filed_number; i++) {
		data->lid_fields[i].lf_string[0] = '\0';
		data->lid_fields[i].lf_value = 0;
	}
}

static void lustre_item_data_free(struct lustre_item_data *data)
{
	free(data->lid_fields);
	free(data);
}

static int lustre_item_extend_form_tsdbtags(struct lustre_item_type *itype,
		struct lustre_item_data *data)
{
	int status = 0;
	regmatch_t matched_fields[3];
	char *pointer = itype->lit_ext_tags;
	char *match_value = NULL;
	int max_size = sizeof(itype->lit_ext_tags) - 1;
	char *value_pointer = data->lid_ext_tags;
	char type[TYPE_NAME_LEN + 1];
	char name[TYPE_NAME_LEN + 1];
	struct lustre_item_type_extend_field *ext_field;
	const char *pattern = "\\$\\{(extendfield):([^}]+)\\}";
	static regex_t regex;
	static int regex_inited = 0;
	int i;

	if (regex_inited == 0) {
		regex_inited = 1;
		status = lustre_compile_regex(&regex, pattern);
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
				(pointer - itype->lit_ext_tags);
			finish = matched_fields[i].rm_eo +
				(pointer - itype->lit_ext_tags);

			if ((i != 0) && ((finish - start) > TYPE_NAME_LEN)) {
				status = -EINVAL;
				LERROR("%s length: %d is too long",
				       (i == 1) ? "type" : "name",
				       finish - start);
				goto out;
			}

			if (i == 1) {
				strncpy(type, itype->lit_ext_tags + start,
					finish - start);
				type[finish - start] = '\0';
			} else if (i == 2) {
				strncpy(name, itype->lit_ext_tags + start,
					finish - start);
				name[finish - start] = '\0';
			}
		}

		if (strcmp(type, "extendfield") == 0) {
			ext_field = lustre_item_extend_field_find(itype, name);
			if (ext_field == NULL) {
				LERROR("failed to get extend field for %s", name);
				break;
			}
			match_value = ext_field->litef_value;
		} else {
			LERROR("unknown type \"%s\"", type);
			status = -EINVAL;
			break;
		}

		if (strlen(match_value) + matched_fields[0].rm_so > max_size) {
			LERROR("extend tsdb tags overflows: %d", max_size);
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

	LINFO("status: %d tsdb tags: %s", status, data->lid_ext_tags);
out:
	if (regex_inited)
		regfree(&regex);
	return status;
}

static int lustre_item_extend_parse(struct lustre_item_type *type,
			     struct lustre_item_data *data)
{
	struct lustre_item_type_extend *ext;
	struct lustre_item_type_extend_field *ext_field;
	regmatch_t *match_fields;
	char *pos = NULL;
	int len;
	int status;

	if (list_empty(&type->lit_extends))
		return 0;

	list_for_each_entry(ext, &type->lit_extends, lite_linkage) {
		assert(ext->lite_field_index <= type->lit_field_number);
		match_fields = calloc(ext->lite_field_number + 1,
				      sizeof (regmatch_t));
		if (match_fields == NULL) {
			LERROR("Extended parse: not enough memory");
			return -ENOMEM;
		}
		status = regexec(&ext->lite_regex,
				 data->lid_fields[ext->lite_field_index].lf_string,
				 ext->lite_field_number + 1,
				 match_fields,
				 0);

		if (status == REG_NOMATCH) {
			LINFO("Extended parse: failed to parse field: \"%s\"",
			    data->lid_fields[ext->lite_field_index].lf_string);
			free(match_fields);
			status = -EINVAL;
			goto out;
		}

		list_for_each_entry(ext_field, &ext->lite_fields, litef_linkage) {
			assert(ext_field->litef_index <= ext->lite_field_number);

			pos = data->lid_fields[ext->lite_field_index].lf_string +
				match_fields[ext_field->litef_index].rm_so;
			len = match_fields[ext_field->litef_index].rm_eo -
				match_fields[ext_field->litef_index].rm_so;

			strncpy(ext_field->litef_value, pos, len);
			ext_field->litef_value[len] = '\0';
		}

		free(match_fields);
		match_fields = NULL;
	}

	status = lustre_item_extend_form_tsdbtags(type, data);
	if (status)
		return status;

	data->lid_ext_tags_used = 1;

out:
	return status;
}

static int _lustre_parse(struct lustre_item_type *type,
			 const char *content,
			 struct list_head *path_head)
{
	const char *previous = content;
	regmatch_t *fields;
	struct lustre_item_data *data;
	char string[MAX_JOBSTAT_FIELD_LENGTH];
	unsigned long long value;
	int status = 0;

	fields = calloc(type->lit_field_number + 1, sizeof(regmatch_t));
	if (fields == NULL) {
		ERROR("parse: not enough memory");
		return -1;
	}

	data = lustre_item_data_alloc(type);
	if (data == NULL) {
		ERROR("parse: not enough memory");
		status = -1;
		goto out;
	}

	while (1) {
		int i = 0;
		int nomatch = regexec(&type->lit_regex, previous,
				      type->lit_field_number + 1, fields, 0);
		if (nomatch)
			break;

		lustre_item_data_clean(data);

		for (i = 0; i <= type->lit_field_number; i++) {
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

				strncpy(data->lid_fields[i].lf_string, string,
					MAX_JOBSTAT_FIELD_LENGTH);
				LINFO("type %s, field %d, bytes %d:%d,"
				      " value %s",
				      type->lit_type_name, i,
				      start, finish, string);
				value_type = type->lit_field_array[i]->lft_type;
				if (value_type == TYPE_STRING) {
					/* TODO: combine string algorithm */
				} else if (value_type == TYPE_NUMBER) {
					value = strtoull(string,
							 NULL, 10);
					data->lid_fields[i].lf_value = value;
				} else {
					assert(value_type == TYPE_NULL);
				}
			}
		}

		if (lustre_item_match(data->lid_fields,
				      type->lit_field_number,
				      type)) {
			status = lustre_item_extend_parse(type, data);
			if (status == 0) {
				lustre_data_submit(type, path_head, data);
			} else {
				LINFO("Parse: failed to do extended parse");
			}
		}
		previous += fields[0].rm_eo;
	}
	lustre_item_data_free(data);
out:
	free(fields);
	return status;
}

static int lustre_parse_context(struct lustre_item_type *type,
				const char *content,
				struct list_head *path_head)
{
	const char *previous = content;
	regmatch_t *fields;
	char *buf;
	int status = 0;

	fields = calloc(type->lit_context_regex.re_nsub + 1,
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
		int nomatch = regexec(&type->lit_context_regex, previous,
				      type->lit_context_regex.re_nsub + 1,
				      fields, 0);
		if (nomatch)
			break;

		start = fields[0].rm_so + (previous - content);
		finish = fields[0].rm_eo + (previous - content);
		strncpy(buf,
			content + start, finish - start);

		status = _lustre_parse(type, buf, path_head);
		if (status)
			break;
		previous += fields[0].rm_eo;
	}

	free(buf);
out:
	free(fields);
	return status;
}

static int lustre_parse(struct lustre_item_type *type,
			const char *content,
			struct list_head *path_head)
{
	if (type->lit_flags & LUSTRE_ITEM_FLAG_CONTEXT)
		return lustre_parse_context(type, content, path_head);
	else
		return _lustre_parse(type, content, path_head);
}

#define START_FILE_SIZE (1048576)
#define MAX_FILE_SIZE   (1048576 * 1024)

static int lustre_read_file(const char *path, char **buf, ssize_t *data_size)
{
	int bufsize = START_FILE_SIZE;
	char *filebuf;
	char *pointer;
	struct stat st;
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

	status = stat(path, &st);
	if (status) {
		ERROR("failed to stat %s", path);
		goto err;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("failed to open %s", path);
		status = -1;
		goto err;
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
	LINFO("buff size %d, file size :%zd:%zd",
	      bufsize, offset, strlen(filebuf));
	return 0;
err:
	free(filebuf);
	return status;
}

static struct lustre_subpath_fields *
lustre_subpath_fields_alloc(struct lustre_entry	*entry)
{
	struct lustre_subpath_fields *fields;
	int field_number = entry->le_subpath_field_number;
	struct lustre_subpath_field_type *path;
	int i;

	fields = calloc(1, sizeof(struct lustre_subpath_fields));
	if (fields == NULL)
		return NULL;

	fields->lpfs_fileds = calloc(field_number + 1,
				     sizeof(struct lustre_subpath_field));
	if (fields->lpfs_fileds == NULL) {
		free(fields);
		return NULL;
	}

	i = 1;
	list_for_each_entry(path,
			    &entry->le_subpath_field_types,
			    lpft_linkage) {
		fields->lpfs_fileds[i].lpf_type = path;
		i++;
	}

	INIT_LIST_HEAD(&fields->lpfs_linkage);
	fields->lpfs_field_number = field_number;
	return fields;
}

void lustre_subpath_fields_free(struct lustre_subpath_fields *fields)
{
	free(fields->lpfs_fileds);
	free(fields);
}

/*
 Return 1 when matched, 0 if not, -1 if error.
*/
static int
lustre_subpath_match(char *string,
		     struct lustre_entry *entry,
		     struct list_head *path_head,
		     struct lustre_subpath_fields **subpath)
{
	const char *pointer = string;
	regmatch_t *fields;
	int i = 0;
	int status = 0;
	int matched = 0;
	struct lustre_subpath_fields *subpath_fields;

	subpath_fields = lustre_subpath_fields_alloc(entry);
	if (subpath_fields == NULL) {
		ERROR("not enough memory");
		return -1;
	}

	fields = calloc(entry->le_subpath_field_number + 1, sizeof(regmatch_t));
	if (fields == NULL) {
		ERROR("not enough memory");
		status = -1;
		goto out;
	}

	while (1) {
		status = regexec(&entry->le_subpath_regex,
				 pointer,
				 entry->le_subpath_field_number + 1,
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
		for (i = 0; i <= entry->le_subpath_field_number; i++) {
			int start;
			int finish;
			struct lustre_subpath_field *field;
			if (fields[i].rm_so == -1)
				break;
			start = fields[i].rm_so + (pointer - string);
			finish = fields[i].rm_eo + (pointer - string);
			if (i != 0) {
				field = &subpath_fields->lpfs_fileds[i];
				strncpy(field->lpf_value,
					string + start, finish - start);
				LINFO("subpath %d, bytes %d:%d, value %.*s\n",
				      i,
				      start, finish,
				      (finish - start), string + start);
			}
		}
		pointer += fields[0].rm_eo;
	}
out:
	if (status == 1) {
		list_add_tail(&subpath_fields->lpfs_linkage, path_head);
		*subpath = subpath_fields;
	} else {
		lustre_subpath_fields_free(subpath_fields);
	}
	free(fields);

	return status;
}

static int
lustre_entry_read_directory(struct lustre_entry *entry,
			    char *path,
			    struct list_head *path_head)
{
	struct lustre_entry *child;
	int status = 0;
	struct stat st;

	assert(list_empty(&entry->le_active_item_types));
	assert(list_empty(&entry->le_item_types));

	status = stat(path, &st);
	if (status) {
		INFO("failed to stat %s: %s", path, strerror(errno));
		return 0;
	}

	list_for_each_entry(child,
			    &entry->le_active_children,
			    le_active_linkage) {
		status = lustre_entry_read(child, path, path_head);
		if (status)
			WARNING("entry path: %s not found, continue", path);
	}
	return 0;
}

static int
_lustre_entry_read(struct lustre_entry *entry,
		   char *pwd,
		   char *subpath,
		   struct list_head *path_head)
{
	char path[MAX_NAME_LENGH + 1];
	int status = 0;
	char *filebuf;
	struct lustre_item_type *type;
	ssize_t size;
	int max_size = sizeof(path) - 1;

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
	assert(entry->le_mode == S_IFREG || entry->le_mode == S_IFDIR);

	LINFO("going down to path %s", path);
	if (entry->le_mode == S_IFREG) {
		assert(list_empty(&entry->le_active_children));
		assert(list_empty(&entry->le_children));
		if (entry->le_definition->ld_read_file != NULL) {
			status = entry->le_definition->ld_read_file(path,
				&filebuf, &size,
				(entry->le_definition)->ld_private_definition.ld_private_data);
		} else {
			status = lustre_read_file(path, &filebuf, &size);
		}
		if (status) {
			ERROR("unable to read file %s", path);
			return status;
		}
		list_for_each_entry(type,
				    &entry->le_active_item_types,
				    lit_active_linkage) {
			assert(!list_empty(&type->lit_items));
			LINFO("parsing %s for type %s",
			      path,
			      type->lit_type_name);
			status = lustre_parse(type, filebuf, path_head);
			if (status) {
				ERROR("unable to parse file %s for type %s",
				      path,
				      type->lit_type_name);
				free(filebuf);
				return status;
			}
		}
		free(filebuf);
	} else {
		lustre_entry_read_directory(entry,
					    path,
					    path_head);
	}
	return 0;
}

int
lustre_entry_read(struct lustre_entry *entry,
		  char *pwd,
		  struct list_head *path_head)
{
	char *subpath;
	int status = 0;
	DIR *parent_dir;
	struct dirent *dp;
	struct lustre_subpath_fields *subpath_fields = NULL;

	assert(entry->le_active);
	if (entry->le_subpath_type == SUBPATH_CONSTANT) {
		subpath = entry->le_subpath;
		return _lustre_entry_read(entry, pwd, subpath, path_head);
	} else {
		assert(entry->le_subpath_type == SUBPATH_REGULAR_EXPRESSION);
		parent_dir = opendir(pwd);
		if (parent_dir == NULL) {
			LINFO("unable to open proc directory: %s", pwd);
			return -1;
		}
		while ((dp = readdir(parent_dir)) != NULL) {
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0) {
				continue;
			}

			status = lustre_subpath_match(dp->d_name,
						      entry,
						      path_head,
						      &subpath_fields);
			if (status == 1) {
				subpath = dp->d_name;
				status =  _lustre_entry_read(entry, pwd,
					subpath, path_head);

				list_del_init(&subpath_fields->lpfs_linkage);
				lustre_subpath_fields_free(subpath_fields);
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
