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
#include "list.h"
#include "lustre.h"
#include "lustre_xml.h"
#include <regex.h>

struct lustre_configs *lustre_config_g = NULL;

/* Compile the regular expression described by regex to preg */
int lustre_compile_regex(regex_t *preg, const char *regex)
{
	int status = regcomp(preg, regex, REG_EXTENDED|REG_NEWLINE);
	if (status != 0) {
		char error_message[MAX_NAME_LENGH];
		regerror(status, preg, error_message, MAX_NAME_LENGH);
		ERROR("regex error compiling '%s': %s\n",
			regex, error_message);
		return -1;
	}
	return 0;
}

static void lustre_item_rule_free(struct lustre_item_rule *rule)
{
	if (rule->lir_regex_inited)
		regfree(&rule->lir_regex);
	free(rule);
}

static void lustre_item_free(struct lustre_item *item)
{
	struct lustre_item_rule *rule;
	struct lustre_item_rule *n;
	list_for_each_entry_safe(rule,
				 n,
	                         &item->li_rules,
	                         lir_linkage) {
		list_del_init(&rule->lir_linkage);
		lustre_item_rule_free(rule);
	}
	free(item);
}

static int lustre_item_rule_match(struct lustre_field *fields,
				  int field_number,
				  struct lustre_item_rule *rule)
{
	int status;

	if (!rule->lir_regex_inited) {
		return 1;
	}

	assert(rule->lir_field_index <= field_number);

	status = regexec(&rule->lir_regex,
			 fields[rule->lir_field_index].lf_string,
			 /* nmatch = */ 0,
			 /* pmatch = */ NULL,
			 /* eflags = */ 0);
	if (status == 0) {
		return 1;
	}
	return 0;
}

static int lustre_item_match_one(struct lustre_field *fields,
				 int field_number,
				 struct lustre_item *item)
{
	struct lustre_item_rule *rule;
	list_for_each_entry(rule,
			    &item->li_rules,
			    lir_linkage) {
		if (!lustre_item_rule_match(fields, field_number, rule)) {
			LINFO("string %s does not match pattern %s",
			      fields[rule->lir_field_index].lf_string,
			      rule->lir_string);
			return 0;
		}
	}
	return 1;
}

static int lustre_item_match(struct lustre_field *fields,
			     int field_number,
			     struct lustre_item_type *type)
{
	struct lustre_item *item;

	list_for_each_entry(item,
			    &type->lit_items,
			    li_linkage) {
		if (lustre_item_match_one(fields, field_number, item)) {
			LINFO("values (1:%s) matches an item with type %s",
			      fields[1].lf_string,
			      type->lit_type_name);
			return 1;
		}
	}
	LINFO("values (1:%s) does not match any item with type %s",
	      fields[1].lf_string,
	      type->lit_type_name);
	return 0;
}

static void lustre_instance_submit(const char *host,
				   const char *plugin,
				   const char *plugin_instance,
				   const char *type,
				   const char *type_instance,
				   uint64_t value)
{
	value_t values[1];
	value_list_t vl = VALUE_LIST_INIT;

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

	vl.values = values;
	vl.values_len = 1;
	sstrncpy (vl.host, host, sizeof (vl.host));
	sstrncpy (vl.plugin, plugin, sizeof (vl.plugin));
	sstrncpy (vl.plugin_instance, plugin_instance, sizeof (vl.plugin_instance));
	sstrncpy (vl.type, type, sizeof (vl.type));
	sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
	LINFO("host %s, "
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

	plugin_dispatch_values(&vl);
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
			if (strcmp(type->lpft_name, name) == 0) {
				return subpath_field;
			}
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
		if (strcmp(type->lft_name, name) == 0) {
			return content_field;
		}
	}

	return NULL;
}

static int lustre_submit_option_get(struct lustre_submit_option *option,
				    struct list_head *path_head,
				    struct lustre_field_type **field_types,
				    struct lustre_field *fields,
				    int content_field_number,
				    int content_index,
				    char *value)
{
	int status = 0;
	regmatch_t matched_fields[3];
	char *pointer = option->lso_string;
	char *value_pointer = value;
	char type[MAX_NAME_LENGH + 1];
	char name[MAX_NAME_LENGH + 1];
	struct lustre_subpath_field *subpath_field;
	struct lustre_field *content_field;
	int i;

	while (1) {
		status = regexec(&lustre_config_g->lc_regex,
	        		 pointer,
	        		 3,
	        		 matched_fields, 0);
		if (status) {
			/* No match */
			strcpy(value_pointer, pointer);
			value_pointer += strlen(pointer);
			status = 0;
			break;
		}
		for (i = 0; i <= 2; i++) {
			int start;
			int finish;
			if (matched_fields[i].rm_so == -1) {
				break;
			}
			start = matched_fields[i].rm_so +
				(pointer - option->lso_string);
			finish = matched_fields[i].rm_eo +
				(pointer - option->lso_string);
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
		if (matched_fields[0].rm_so > 0) {
			strncpy(value_pointer, pointer,
				matched_fields[0].rm_so);
			value_pointer += matched_fields[0].rm_so;
			value_pointer[0] = '\0';
		}
		if (strcmp(type, "subpath") == 0) {
			subpath_field = lustre_subpath_field_find(path_head,
								  name);
			if (subpath_field == NULL) {
				ERROR("failed to get subpath for %s", name);
				break;
			}
			strcpy(value_pointer, subpath_field->lpf_value);
			value_pointer += strlen(subpath_field->lpf_value);
		} else if (strcmp(type, "content") == 0) {
			content_field = lustre_field_find(fields,
							  content_field_number,
							  name);
			if (content_field == NULL) {
				ERROR("failed to get content for %s", name);
				break;
			}
			strcpy(value_pointer, content_field->lf_string);
			value_pointer += strlen(content_field->lf_string);
		}
		pointer += matched_fields[0].rm_eo;
	}

	return status;
}

static int lustre_submit(struct lustre_submit *submit,
			 struct list_head *path_head,
			 struct lustre_field_type **field_types,
			 struct lustre_field *fields,
			 int content_field_number,
			 int content_index,
			 uint64_t value)
{
	char host[MAX_SUBMIT_STRING_LENGTH];
	char plugin[MAX_SUBMIT_STRING_LENGTH];
	char plugin_instance[MAX_SUBMIT_STRING_LENGTH];
	char type[MAX_SUBMIT_STRING_LENGTH];
	char type_instance[MAX_SUBMIT_STRING_LENGTH];
	int status;

	status = lustre_submit_option_get(&submit->ls_host,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, host);
	if (status) {
		ERROR("submit: failed to get host");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_plugin,
					  path_head, field_types,
					  fields, content_field_number,
					  content_index, plugin);
	if (status) {
		ERROR("submit: failed to get plugin");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_plugin_instance,
	                                  path_head, field_types,
					  fields, content_field_number,
					  content_index, plugin_instance);
	if (status) {
		ERROR("submit: failed to get plugin_instance");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_type,
	                                  path_head, field_types,
					  fields, content_field_number,
					  content_index, type);
	if (status) {
		ERROR("submit: failed to get type");
		return status;
	}

	status = lustre_submit_option_get(&submit->ls_type_instance,
	                                  path_head, field_types,
					  fields, content_field_number,
					  content_index, type_instance);
	if (status) {
		ERROR("submit: failed to get type_instance");
		return status;
	}

	lustre_instance_submit(host, plugin, plugin_instance,
			       type, type_instance, value);
	return status;
}

static int lustre_data_submit(struct lustre_item_type *type,
			      struct list_head *path_head,
			      struct lustre_item_data *data)
{
	int i;

	for (i = 1; i <= type->lit_field_number; i++) {
		if (type->lit_field_array[i]->lft_type == TYPE_STRING) {
		} else if (type->lit_field_array[i]->lft_type == TYPE_NUMBER) {
			lustre_submit(&type->lit_field_array[i]->lft_submit,
				      path_head,
				      type->lit_field_array,
				      data->lid_fields,
				      type->lit_field_number,
				      i,
				      data->lid_fields[i].lf_value);
		}
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
	if (data == NULL) {
		return NULL;
	}

	data->lid_fields = calloc(field_number + 1,
				  sizeof(struct lustre_field));
	if (data->lid_fields == NULL) {
		free(data);
		return NULL;
	}
	data->lid_filed_number = field_number;

	for (i = 1; i <= field_number; i++) {
		data->lid_fields[i].lf_type = type->lit_field_array[i];
	}
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
		if (nomatch) {
			break;
		}
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
			if (i != 0 ) {
				if (finish - start > MAX_JOBSTAT_FIELD_LENGTH - 1) {
					ERROR("field is too long %d", finish - start);
					status = -1;
					break;
				}

				strncpy(string,
					content + start, finish - start);
				string[finish - start] = '\0';

				strcpy(data->lid_fields[i].lf_string, string);
				LINFO("type %s, field %d, bytes %d:%d, value %s",
				      type->lit_type_name, i,
				      start, finish, string);
				if (type->lit_field_array[i]->lft_type == TYPE_STRING) {
					/* TODO: combine string algorithm */
				} else if (type->lit_field_array[i]->lft_type == TYPE_NUMBER) {
					value = strtoull(string,
							 NULL, 10);
					data->lid_fields[i].lf_value = value;
				} else {
					assert(type->lit_field_array[i]->lft_type == TYPE_NULL);
				}
			}
		}

		if (lustre_item_match(data->lid_fields,
				      type->lit_field_number,
				      type)) {
			lustre_data_submit(type, path_head, data);
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

	fields = calloc(type->lit_context_regex.re_nsub + 1, sizeof(regmatch_t));
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
				      type->lit_context_regex.re_nsub + 1, fields, 0);
		if (nomatch) {
			break;
		}

		start = fields[0].rm_so + (previous - content);
		finish = fields[0].rm_eo + (previous - content);
		strncpy(buf,
			content + start, finish - start);

		status = _lustre_parse(type, buf, path_head);
		if (status) {
			break;
		}
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
	if (type->lit_flags & LUSTRE_ITEM_FLAG_CONTEXT) {
		return lustre_parse_context(type, content, path_head);
	} else {
		return _lustre_parse(type, content, path_head);
	}
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
	LINFO("buff size %d, file size :%zd:%zd", bufsize, offset, strlen(filebuf));
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
	if (fields == NULL) {
		return NULL;
	}

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

static void lustre_subpath_fields_free(struct lustre_subpath_fields *fields)
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
			if (matched != 1) {
				status = 0;
			} else {
				status = 1;
			}
			break;
		} else if (matched) {
			ERROR("too many matches");
			status = -1;
			break;
		}
		matched ++;
		for (i = 0; i <= entry->le_subpath_field_number; i++) {
			int start;
			int finish;
			if (fields[i].rm_so == -1) {
				break;
			}
			start = fields[i].rm_so + (pointer - string);
			finish = fields[i].rm_eo + (pointer - string);
			if (i != 0) {
				strncpy(subpath_fields->lpfs_fileds[i].lpf_value,
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
lustre_entry_read(struct lustre_entry *entry,
		  char *pwd,
		  struct list_head *path_head);

static int
_lustre_entry_read(struct lustre_entry *entry,
		   char *pwd,
		   char *subpath,
		   struct list_head *path_head)
{
	char path[MAX_NAME_LENGH + 1];
	int status = 0;
	char *filebuf;
	struct lustre_entry *child;
	struct lustre_item_type *type;
	ssize_t size;

	strcpy(path, pwd);
	if (subpath[0] != '/' &&
	    strlen(path) != 0 &&
	    path[strlen(path) - 1] != '/') {
		strcat(path, "/");
	} else if (subpath[0] == '/' &&
		   strlen(path) != 0 &&
		   path[strlen(path) - 1] == '/') {
		subpath++;
	}
	strcat(path, subpath);
	assert(entry->le_mode == S_IFREG || entry->le_mode == S_IFDIR);

	LINFO("going down to path %s", path);
	if (entry->le_mode == S_IFREG) {
		assert(list_empty(&entry->le_active_children));
		assert(list_empty(&entry->le_children));
		status = lustre_read_file(path, &filebuf, &size);
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
		assert(list_empty(&entry->le_active_item_types));
		assert(list_empty(&entry->le_item_types));
		list_for_each_entry(child,
				    &entry->le_active_children,
				    le_active_linkage) {
			status = lustre_entry_read(child, path, path_head);
			if (status) {
				WARNING("entry path: %s not found, continue", path);
			}
		}
	}
	return 0;
}

void
lustre_subpath_field_dump(struct list_head *path_head)
{
	struct lustre_subpath_fields *subpath_fields;
	int i;

	list_for_each_entry(subpath_fields,
	                    path_head,
	                    lpfs_linkage) {
		for (i = 1; i <= subpath_fields->lpfs_field_number; i++) {
			LINFO("subpath[%d]: %s", i, subpath_fields->lpfs_fileds[i].lpf_value);
		}
	}
}

static int
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
				status =  _lustre_entry_read(entry, pwd, subpath, path_head);
				if (status) {
					break;
				}
				list_del_init(&subpath_fields->lpfs_linkage);
			} else if (status) {
				ERROR("failed to match subpath %s", dp->d_name);
				break;
			}
		}
		closedir(parent_dir);
	}

	return status;
}

static int lustre_read(void)
{
	struct list_head path_head;

	if (lustre_config_g == NULL) {
		ERROR("lustre plugin in not configure properly");
		return -1;
	}

	if (!lustre_config_g->lc_definition.ld_root->le_active)
		return 0;

	INIT_LIST_HEAD(&path_head);
	return lustre_entry_read(lustre_config_g->lc_definition.ld_root, "/", &path_head);
}

struct lustre_field_type *lustre_field_type_alloc(void)
{
	struct lustre_field_type *type;

	type = calloc(1, sizeof(struct lustre_field_type));
	if (type == NULL) {
		ERROR("not enough memory");
	}

	return type;
}

void lustre_field_type_free(struct lustre_field_type *field_type)
{
	free(field_type);
}

int
lustre_field_type_add(struct lustre_item_type *type,
		      struct lustre_field_type *field_type)
{
	if (field_type->lft_index != type->lit_field_number + 1) {
		ERROR("index of field is false");
		return -1;
	}
	field_type->lft_item_type = type;
	list_add_tail(&field_type->lft_linkage, &type->lit_field_list);
	type->lit_field_number++;
	return 0;
}


void lustre_item_type_free(struct lustre_item_type *type)
{
	struct lustre_item *item;
	struct lustre_item *n;
	struct lustre_field_type *field_type;
	struct lustre_field_type *f;

	assert(type);
	list_for_each_entry_safe(item,
				 n,
	                         &type->lit_items,
	                         li_linkage) {
		list_del_init(&item->li_linkage);
		lustre_item_free(item);
	}
	list_for_each_entry_safe(field_type,
				 f,
	                         &type->lit_field_list,
	                         lft_linkage) {
		list_del_init(&field_type->lft_linkage);
		lustre_field_type_free(field_type);
	}
	if (type->lit_field_array)
		free(type->lit_field_array);
	if (type->lit_flags & LUSTRE_ITEM_FLAG_PATTERN)
		regfree(&type->lit_regex);
	if (type->lit_flags & LUSTRE_ITEM_FLAG_CONTEXT)
		regfree(&type->lit_context_regex);
	free(type);
}

struct lustre_item_type *lustre_item_type_alloc(void)
{
	struct lustre_item_type *type;

	type = calloc(1, sizeof (struct lustre_item_type));
	if (type == NULL) {
		ERROR("not enough memory");
		return NULL;
	}
	INIT_LIST_HEAD(&type->lit_linkage);
	INIT_LIST_HEAD(&type->lit_items);
	INIT_LIST_HEAD(&type->lit_field_list);
	INIT_LIST_HEAD(&type->lit_active_linkage);
	return type;
}

void lustre_definition_fini(struct lustre_definition *definition)
{
	if (definition->ld_root)
		lustre_entry_free(definition->ld_root);
}

/* TODO: read form XML file */
static int lustre_definition_init(struct lustre_definition *definition,
				  const char *file)
{
	int status = 0;

	if (definition->ld_inited) {
		ERROR("definition is already inited, igoring %s", file);
		status = -1;
		goto out;
	}

	status = lustre_xml_parse(definition, file);
	if (status) {
		ERROR("Lustre config: failed to parse %s", file);
		goto out;
	}

	definition->ld_inited = 1;
	return 0;
out:
	lustre_definition_fini(definition);
	return status;
}

static struct lustre_item_type *
lustre_item_type_find(struct lustre_entry *entry,
		      const char *type_name)
{
	struct lustre_entry *child;
	struct lustre_item_type *item;

	list_for_each_entry(item,
	                    &entry->le_item_types,
	                    lit_linkage) {
		if (strcmp(item->lit_type_name, type_name) == 0) {
			return item;
		}
	}

	list_for_each_entry(child,
	                    &entry->le_children,
	                    le_linkage) {
		item = lustre_item_type_find(child, type_name);
		if (item) {
			return item;
		}
	}
	return NULL;
}

void lustre_config_free(struct lustre_configs *conf)
{
	assert(conf);
	regfree(&conf->lc_regex);
	lustre_definition_fini(&conf->lc_definition);

	sfree(conf);
}

static void lustre_config_dump(struct lustre_configs *conf)
{
	if (conf == NULL) {
		ERROR("Lustre config: empty config");
		return;
	}
}

static int lustre_config_common(const oconfig_item_t *ci,
				struct lustre_configs *conf)
{
	int i;
	int status = 0;
	char *definition_file;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("DefinitionFile", child->key) == 0) {
			definition_file = NULL;
			status = cf_util_get_string(child, &definition_file);
			if (status) {
				ERROR("Common: failed to get definition file");
				break;
			}

			status = lustre_definition_init(&lustre_config_g->lc_definition,
							definition_file);
			free(definition_file);
			if (status) {
				ERROR("Common: failed to init definition");
			}
		} else {
      			ERROR("Common: The \"%s\" key is not allowed"
			      "and will be ignored.", child->key);
          	}
		if (status != 0)
			break;
	}

	return (status);
}

static int lustre_config_item_rule(const oconfig_item_t *ci,
				   struct lustre_item *item)
{
	int i, j;
	int status = 0;
	struct lustre_item_rule *rule;
	struct lustre_item_type *type;
	char *value;
	int found;

	type = item->li_type;
	if (type == NULL) {
		ERROR("Rule: type is not inited\n");
		return -1;
	}

	rule = calloc(1, sizeof (struct lustre_item_rule));
	if (item == NULL) {
		ERROR("Rule: not enough memory");
		return -1;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			value = NULL;
			status = cf_util_get_string(child, &value);
			if (status) {
				WARNING ("Rule: failed to get value for \"%s\"",
					 child->key);
				break;
			}
			found = 0;
			for (j = 1; j <= type->lit_field_number; j++) {
				if (strcmp(value, type->lit_field_array[j]->lft_name) == 0) {
					found = 1;
					rule->lir_field_index = j;
					break;
				}
			}
			if (!found) {
				ERROR("Rule: failed to get find rule of \"%s\"",
				      value);
				break;
			}
			free(value);
		} else if (strcasecmp ("Match", child->key) == 0) {
			value = NULL;
			status = cf_util_get_string (child, &value);
			if (status) {
				ERROR("Rule:failed to get value for \"%s\"",
				      child->key);
				break;
			}
			if (strlen(value) > MAX_NAME_LENGH) {
				ERROR("Rule: value \"%s\" is too long",
				      value);
				free(value);
				break;
			}
			strcpy(rule->lir_string, value);
			status = lustre_compile_regex(&rule->lir_regex,
						      value);
			free(value);
			if (status) {
				ERROR("Rule: failed to compile regex");
				break;
			}
			rule->lir_regex_inited = 1;
		} else {
      			ERROR("Rule: The \"%s\" key is not allowed inside "
          		      "<Item /> blocks and will be ignored.",
          		      child->key);
          	}
		if (status != 0)
			break;
	}

	if (status) {
		lustre_item_rule_free(rule);
	} else {
		list_add(&rule->lir_linkage, &item->li_rules);
	}

	return (status);
}

static int lustre_entry_activate(struct lustre_entry *entry)
{
	struct lustre_entry *parent;

	entry->le_active = 1;
	parent = entry->le_parent;
	if (parent != NULL) {
		if (list_empty(&entry->le_active_linkage)) {
			list_add_tail(&entry->le_active_linkage,
				      &parent->le_active_children);
			if (!parent->le_active) {
				lustre_entry_activate(parent);
			}
		}
	}
	return 0;
}

static int lustre_config_item(const oconfig_item_t *ci,
			      struct lustre_configs *conf)
{
	int i;
	int status = 0;
	struct lustre_item *item;
	char *value;
	struct lustre_entry *entry;

	if (!conf->lc_definition.ld_inited) {
		ERROR("Item: definition is not inited yet");
		return -1;
	}

	item = calloc(1, sizeof (struct lustre_item));
	if (item == NULL) {
		ERROR("Item: not enough memory");
		return -1;
	}
	INIT_LIST_HEAD(&item->li_rules);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Type", child->key) == 0) {
			value = NULL;
			status = cf_util_get_string (child, &value);
			if (status) {
				ERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
			item->li_type = lustre_item_type_find(conf->lc_definition.ld_root,
							      value);
			if (item->li_type == NULL) {
				ERROR("Item: failed to get type for \"%s\"",
				       value);
				status = -1;
				break;
			}
			free(value);
		} else if (strcasecmp("Rule", child->key) == 0) {
			status = lustre_config_item_rule(child, item);
			if (status) {
				ERROR("Item: failed to parse rule");
				break;
			}
		} else {
      			ERROR("Item: The \"%s\" key is not allowed inside "
          		      "<Rule /> blocks and will be ignored.",
          		      child->key);
          	}
		if (status != 0)
			break;
	}

	if (status) {
		lustre_item_free(item);
	} else {
		list_add(&item->li_linkage, &item->li_type->lit_items);
		entry = item->li_type->lit_entry;

		if (list_empty(&item->li_type->lit_active_linkage)) {
			list_add(&item->li_type->lit_active_linkage,
				 &entry->le_active_item_types);
		}
		LINFO("enabling entry %s, type %s",
		      entry->le_subpath,
		      item->li_type->lit_type_name);
		lustre_entry_activate(entry);
	}

	return (status);
}

static int lustre_config(oconfig_item_t *ci)
{
	int i;
	int status = 0;
	const char *pattern = "\\$\\{(subpath|content):(.+)\\}";

	lustre_config_g = calloc(1, sizeof (struct lustre_configs));
	if (lustre_config_g == NULL) {
		ERROR("not enough memory");
		return -1;
	}

	status = lustre_compile_regex(&lustre_config_g->lc_regex, pattern);
	assert(status == 0);

	for (i = 0; i < ci->children_num; i++)
	{
		oconfig_item_t *child = ci->children + i;

		if (strcasecmp ("Common", child->key) == 0) {
			status = lustre_config_common (child, lustre_config_g);
		} else if (strcasecmp ("Item", child->key) == 0) {
			status = lustre_config_item(child, lustre_config_g);
		} else {
			ERROR("Lustre: Ignoring unknown "
			      "configuration option: \"%s\"",
			      child->key);
		}
		if (status) {
			ERROR("Lustre: failed to parse configure");
			goto out;
		}
	}

	lustre_config_dump(lustre_config_g);
	lustre_entry_dump_active(lustre_config_g->lc_definition.ld_root, 0);

out:
	if (status != 0) {
		lustre_config_free(lustre_config_g);
		lustre_config_g = NULL;
	}
	return status;
}

void module_register (void)
{
	plugin_register_complex_config("lustre", lustre_config);
	plugin_register_read("lustre", lustre_read);
} /* void module_register */
