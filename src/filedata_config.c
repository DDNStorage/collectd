/**
 * collectd - src/filedata_config.c
 * Copyright (C) 2014  Li Xi
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <regex.h>
#include <errno.h>
#include "filedata_common.h"
#include "filedata_config.h"
#include "filedata_xml.h"

int filedata_compile_regex(regex_t *preg, const char *regex)
{
	int status = regcomp(preg, regex, REG_EXTENDED|REG_NEWLINE);
	if (status != 0) {
		char error_message[MAX_NAME_LENGH];
		regerror(status, preg, error_message, MAX_NAME_LENGH);
		return -1;
	}
	return 0;
}

void filedata_item_filter_add(struct filedata_item *item,
			      struct filedata_item_filter *filter)
{
	list_add_tail(&filter->fif_linkage, &item->fi_filters);
	filter->fif_item = item;
}

void filedata_item_rule_free(struct filedata_item_rule *rule)
{
	if (rule->fir_regex_inited)
		regfree(&rule->fir_regex);
	free(rule);
}

void filedata_item_rule_add(struct filedata_item *item,
			    struct filedata_item_rule *rule)
{
	list_add_tail(&rule->fir_linkage, &item->fi_rules);
	rule->fir_item = item;
}

void filedata_item_rule_replace(struct filedata_item *item,
				struct filedata_item_rule *old,
				struct filedata_item_rule *new)
{
	list_add_tail(&new->fir_linkage, &old->fir_linkage);
	new->fir_item = item;
	list_del_init(&old->fir_linkage);
}

void filedata_item_rule_unlink(struct filedata_item_rule *rule)
{
	list_del_init(&rule->fir_linkage);
}

void filedata_item_filter_unlink(struct filedata_item_filter *filter)
{
	list_del_init(&filter->fif_linkage);
}

void filedata_item_unlink(struct filedata_item *item)
{
	list_del_init(&item->fi_linkage);
}

void filedata_item_free(struct filedata_item *item)
{
	struct filedata_item_rule *rule;
	struct filedata_item_rule *n;
	struct filedata_item_filter *filter;
	struct filedata_item_filter *tmp;

	list_for_each_entry_safe(rule,
				 n,
	                         &item->fi_rules,
	                         fir_linkage) {
		filedata_item_rule_unlink(rule);
		filedata_item_rule_free(rule);
	}

	list_for_each_entry_safe(filter,
				 tmp,
				 &item->fi_filters,
				 fif_linkage) {
		filedata_item_filter_unlink(filter);
		free(filter);
	}

	free(item);
}

struct filedata_field_type *filedata_field_type_alloc(void)
{
	struct filedata_field_type *type;

	type = calloc(1, sizeof(struct filedata_field_type));
	if (type == NULL) {
		FERROR("not enough memory");
	}

	return type;
}

void filedata_field_type_free(struct filedata_field_type *field_type)
{
	free(field_type->fft_submit.fs_math_entries);
	free(field_type);
}

int
filedata_field_type_add(struct filedata_item_type *type,
			struct filedata_field_type *field_type)
{
	if (field_type->fft_index != type->fit_field_number + 1) {
		FERROR("index of field is false");
		return -1;
	}
	field_type->fft_item_type = type;
	list_add_tail(&field_type->fft_linkage, &type->fit_field_list);
	type->fit_field_number++;
	return 0;
}

static void filedata_item_type_extend_free(struct filedata_item_type_extend *ext)
{
	struct filedata_item_type_extend_field *field, *f;

	list_for_each_entry_safe(field, f, &ext->fite_fields, fitef_linkage) {
		list_del_init(&field->fitef_linkage);
		free(field);
	}

	if (ext->fite_regex_inited)
		regfree(&ext->fite_regex);

	free(ext);
}

static void filedata_item_type_extend_destroy(struct filedata_item_type *type)
{
	struct filedata_item_type_extend *ext, *n;

	list_for_each_entry_safe(ext, n, &type->fit_extends, fite_linkage) {
		list_del_init(&ext->fite_linkage);
		filedata_item_type_extend_free(ext);
	}
}

void filedata_item_type_free(struct filedata_item_type *type)
{
	struct filedata_item *item;
	struct filedata_item *n;
	struct filedata_field_type *field_type;
	struct filedata_field_type *f;

	assert(type);
	list_for_each_entry_safe(item,
				 n,
	                         &type->fit_items,
	                         fi_linkage) {
		filedata_item_unlink(item);
		filedata_item_free(item);
	}
	list_for_each_entry_safe(field_type,
				 f,
	                         &type->fit_field_list,
	                         fft_linkage) {
		list_del_init(&field_type->fft_linkage);
		filedata_field_type_free(field_type);
	}
	filedata_item_type_extend_destroy(type);

	if (type->fit_field_array)
		free(type->fit_field_array);
	if (type->fit_flags & FILEDATA_ITEM_FLAG_PATTERN)
		regfree(&type->fit_regex);
	if (type->fit_flags & FILEDATA_ITEM_FLAG_CONTEXT_REGULAR_EXP)
		regfree(&type->fit_context_regex);
	free(type);
}

struct filedata_item_type *filedata_item_type_alloc(void)
{
	struct filedata_item_type *type;

	type = calloc(1, sizeof (struct filedata_item_type));
	if (type == NULL) {
		FERROR("not enough memory");
		return NULL;
	}
	INIT_LIST_HEAD(&type->fit_linkage);
	INIT_LIST_HEAD(&type->fit_items);
	INIT_LIST_HEAD(&type->fit_extends);
	INIT_LIST_HEAD(&type->fit_field_list);
	INIT_LIST_HEAD(&type->fit_active_linkage);
	return type;
}

static struct filedata_item_type *
filedata_item_type_find(struct filedata_entry *entry,
			const char *type_name)
{
	struct filedata_entry *child;
	struct filedata_item_type *item;

	list_for_each_entry(item,
	                    &entry->fe_item_types,
	                    fit_linkage) {
		if (strcmp(item->fit_type_name, type_name) == 0) {
			return item;
		}
	}

	list_for_each_entry(child,
	                    &entry->fe_children,
	                    fe_linkage) {
		item = filedata_item_type_find(child, type_name);
		if (item) {
			return item;
		}
	}
	return NULL;
}

static int filedata_item_rule_match(struct filedata_field *fields,
				    int field_number,
				    struct filedata_item_rule *rule)
{
	int status;

	if (!rule->fir_regex_inited) {
		return 1;
	}

	assert(rule->fir_field_index <= field_number);

	status = regexec(&rule->fir_regex,
			 fields[rule->fir_field_index].ff_string,
			 /* nmatch = */ 0,
			 /* pmatch = */ NULL,
			 /* eflags = */ 0);
	if (status == 0) {
		return 1;
	}
	return 0;
}

struct filedata_item_type_extend_field *
filedata_item_extend_field_find(struct filedata_item_type *type,
				const char *name)
{
	struct filedata_item_type_extend *ext;
	struct filedata_item_type_extend_field *field;

	list_for_each_entry(ext, &type->fit_extends, fite_linkage) {
		list_for_each_entry(field, &ext->fite_fields, fitef_linkage) {
			if (strcmp(field->fitef_name, name) == 0)
				return field;
		}
	}

	return NULL;
}

static int filedata_item_match_one(struct filedata_field *fields,
				   int field_number,
				   struct filedata_item *item)
{
	struct filedata_item_rule *rule;

	if ((item->fi_definition->fd_query_times % item->fi_query_interval)
	    != 0) {
		FINFO("%s filedata query times: %llu interval: %d",
		      item->fi_type->fit_type_name,
		      item->fi_definition->fd_query_times,
		      item->fi_query_interval);
		return 0;
	}

	list_for_each_entry(rule,
			    &item->fi_rules,
			    fir_linkage) {
		if (!filedata_item_rule_match(fields, field_number, rule)) {
			FINFO("string %s does not match pattern %s",
			      fields[rule->fir_field_index].ff_string,
			      rule->fir_string);
			return 0;
		}
	}

	return 1;
}

static int filedata_item_field_allowed(int field_idx,
				       struct filedata_item *item)
{
	struct filedata_item_filter *filter;

	list_for_each_entry(filter, &item->fi_filters, fif_linkage) {
		if (field_idx == filter->fif_field_index) {
			return 0;
		}
	}

	return 1;
}

static int filedata_item_filter_match(struct filedata_field *fields,
				      int field_number,
				      struct filedata_item *item)
{
	int i = 0, allowed = 0;

	for (i = 1;i <= field_number;i++) {
		if (fields[i].ff_allowed) {
			allowed++;
			continue;
		}

		fields[i].ff_allowed = filedata_item_field_allowed(i, item);
		if (fields[i].ff_allowed) {
			allowed++;
		}
	}

	return allowed;
}

int filedata_item_match(struct filedata_field *fields,
			int field_number,
			struct filedata_item_type *type,
			struct filedata_item **ret_item)
{
	struct filedata_item *item;
	int match = 0, res = 0;

	list_for_each_entry(item,
			    &type->fit_items,
			    fi_linkage) {
		if (filedata_item_match_one(fields, field_number, item)) {
			FINFO("values (1:%s) matches an item with type %s",
			      fields[1].ff_string,
			      type->fit_type_name);
			res = filedata_item_filter_match(
						fields, field_number, item);
			if (res) {
				match = res;
				*ret_item = item;
			}
		}
	}

	if (match == 0) {
		FINFO("values (1:%s) does not match any item with type %s",
			fields[1].ff_string,
			type->fit_type_name);
	}
	return match;
}

void filedata_math_entry_free(struct filedata_math_entry *fme)
{
	free(fme->fme_left_operand);
	free(fme->fme_operation);
	free(fme->fme_right_operand);
	free(fme->fme_tsdb_name);
	free(fme->fme_type);
	free(fme->fme_type_instance);
	free(fme);
}

void filedata_definition_fini(struct filedata_definition *definition)
{
	struct filedata_math_entry *fme;
	struct filedata_math_entry *tmp;

	if (definition->fd_root)
		filedata_entry_free(definition->fd_root);
	if (definition->fd_filename)
		free(definition->fd_filename);
	if (definition->extra_tags)
		free(definition->extra_tags);
	definition->fd_root = NULL;
	definition->fd_filename = NULL;
	definition->fd_inited = 0;
	definition->fd_query_times = 0;
	definition->fd_read_file = NULL;

	list_for_each_entry_safe(fme, tmp, &definition->fd_math_entries,
				 fme_linkage) {
		list_del_init(&fme->fme_linkage);
		filedata_math_entry_free(fme);
	}
}

/* TODO: read form XML file */
static int filedata_definition_init(struct filedata_definition *definition,
				    const char *file)
{
	int status = 0;

	if (definition->fd_inited) {
		FERROR("definition is already inited, igoring %s", file);
		status = -1;
		goto out;
	}

	definition->fd_filename = strdup(file);
	if (definition->fd_filename == NULL) {
		FERROR("Filedata config: failed to copy string %s", file);
		status = -1;
		goto out;
	}

	status = filedata_xml_parse(definition, file);
	if (status) {
		FERROR("Filedata config: failed to parse %s", file);
		goto out;
	}

	definition->fd_inited = 1;
	return 0;
out:
	filedata_definition_fini(definition);
	return status;
}

static void filedata_config_dump(struct filedata_configs *conf)
{
	if (conf == NULL) {
		FERROR("Filedata config: empty config");
		return;
	}
}

int filedata_config_get_string(const oconfig_item_t *ci, char **ret_string)
{
	char *string;

	if ((ci->values_num != 1) ||
	    (ci->values[0].type != OCONFIG_TYPE_STRING)) {
		FERROR("filedata_config_get_string: The %s option requires "
		       "exactly one string argument.", ci->key);
		return -1;
	}

	string = strdup (ci->values[0].value.string);
	if (string == NULL) {
		return -1;
	}

	if (*ret_string != NULL) {
		free(*ret_string);
	}
	*ret_string = string;

	return 0;
}

static int filedata_config_get_int (const oconfig_item_t *ci, int *ret_value) /* {{{ */
{
	if ((ci == NULL) || (ret_value == NULL))
		return EINVAL;

	if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_NUMBER))
	{
		FERROR ("filedata_config_get_int: The %s option requires "
				"exactly one numeric argument.", ci->key);
		return -1;
	}

	*ret_value = (int) ci->values[0].value.number;

	return 0;
}

static inline char* filedata_check_extra_tags(char *extra_tags)
{
	char *p = extra_tags;
	char *key_point;
	int ret;
	regex_t reg;
	const char *pattern = "^[A-Za-z]*=.*";
	int n;

	char *ret_p = calloc(MAX_TSDB_TAGS_LENGTH - 1, 1);
	if (!ret_p)
		return NULL;

	while (p) {
		while ((key_point = strsep(&p, ",")) != NULL) {
			while (*key_point == ' ')
				key_point++;
			if (*key_point == '\0')
				continue;
			break;
		}
		regcomp(&reg, pattern, REG_EXTENDED);
		ret = regexec(&reg, key_point, 0, NULL, 0);
		regfree(&reg);
		n = MAX_TSDB_TAGS_LENGTH - strlen(ret_p) - 1;
		if (ret == 0) {
			if (n > strlen(key_point)) {
				strncat(ret_p, key_point, strlen(key_point));
			} else {
				FERROR("Common: ignore max buffer");
				break;
			}
			strncat(ret_p, " ", 1);
		} else {
			FERROR("Common: ignore invalid extra tag: %s",
			       key_point);
		}
	}

	if (strlen(ret_p) < 3) {
		FERROR("Common: invalid extra tags: %s", extra_tags);
		return NULL;
	}
	return ret_p;
}

static int filedata_config_common(const oconfig_item_t *ci,
				  struct filedata_configs *conf)
{
	int i;
	int status = 0;
	char *definition_file;
	char *root_path = NULL;
	struct filedata_private_definition fd_private_definition =
				conf->fc_definition.fd_private_definition;
	char *extra_tags = NULL;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("DefinitionFile", child->key) == 0) {
			definition_file = NULL;
			status = filedata_config_get_string(child, &definition_file);
			if (status) {
				FERROR("Common: failed to get definition file");
				break;
			}

			status = filedata_definition_init(&conf->fc_definition,
							  definition_file);
			free(definition_file);
			if (status) {
				FERROR("Common: failed to init definition");
			}
		} else if (strcasecmp("Extra_tags", child->key) == 0) {
			free(extra_tags);
			extra_tags = NULL;
			status = filedata_config_get_string(child, &extra_tags);
			if (status)
				FERROR("Common: failed to get extra tags");
			conf->fc_definition.extra_tags =
					filedata_check_extra_tags(extra_tags);
			free(extra_tags);
		}  else if (strcasecmp("RootPath", child->key) == 0) {
			/* in case this is specified mutiple times */
			free(root_path);
			root_path = NULL;
			status = filedata_config_get_string(child, &root_path);
			if (status)
				FERROR("Common: failed to init root path");
		} else if (fd_private_definition.fd_private_config) {
			status = fd_private_definition.fd_private_config(child,
									 conf);
		} else {
			FERROR("Common: The \"%s\" key is not allowed "
			       "and will be ignored.", child->key);
		}
		if (status != 0)
			break;
	}

	if (root_path && !status) {
		if (conf->fc_definition.fd_inited)
			strncpy(conf->fc_definition.fd_root->fe_subpath,
				root_path, MAX_NAME_LENGH);
		free(root_path);
	}
	return (status);
}

static int filedata_config_item_rule(const oconfig_item_t *ci,
				     struct filedata_item *item)
{
	int i, j;
	int status = 0;
	struct filedata_item_rule *rule;
	struct filedata_item_type *type;
	char *value;
	int found;

	type = item->fi_type;
	if (type == NULL) {
		FERROR("Rule: type is not inited\n");
		return -1;
	}

	rule = calloc(1, sizeof (struct filedata_item_rule));
	if (rule == NULL) {
		FERROR("Rule: not enough memory");
		return -1;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Rule: failed to get value for \"%s\"",
						child->key);
				break;
			}
			found = 0;
			for (j = 1; j <= type->fit_field_number; j++) {
				if (strcmp(value, type->fit_field_array[j]->fft_name) == 0) {
					found = 1;
					rule->fir_field_index = j;
					break;
				}
			}
			if (!found) {
				FERROR("Rule: failed to get find rule of \"%s\"",
				      value);
				status = -EINVAL;
				free(value);
				break;
			}
			free(value);
		} else if (strcasecmp ("Match", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string (child, &value);
			if (status) {
				FERROR("Rule:failed to get value for \"%s\"",
				      child->key);
				break;
			}
			if (strlen(value) > MAX_NAME_LENGH) {
				FERROR("Rule: value \"%s\" is too long",
				      value);
				status = -EINVAL;
				free(value);
				break;
			}
			strncpy(rule->fir_string, value, MAX_NAME_LENGH);
			status = filedata_compile_regex(&rule->fir_regex,
						        value);
			free(value);
			if (status) {
				FERROR("Rule: failed to compile regex");
				break;
			}
			rule->fir_regex_inited = 1;
		} else {
      			FERROR("Rule: The \"%s\" key is not allowed inside "
          		      "<Item /> blocks and will be ignored.",
          		      child->key);
          	}
		if (status != 0)
			break;
	}

	if (status) {
		filedata_item_rule_free(rule);
	} else {
		filedata_item_rule_add(item, rule);
	}

	return (status);
}

void filedata_item_type_extend_field_add(struct filedata_item_type_extend *ext,
					 struct filedata_item_type_extend_field *ext_field)
{
	list_add_tail(&ext_field->fitef_linkage, &ext->fite_fields);
	ext_field->fitef_ext = ext;
	ext->fite_field_number++;
}

static int filedata_config_extended_field(const oconfig_item_t *ci,
					  struct filedata_item_type_extend *ext,
					  struct filedata_item_type *type)
{
	struct filedata_item_type_extend_field *ext_field = NULL;
	struct filedata_item_type_extend_field *field = NULL;
	char *value;
	int i;
	int status = 0;

	ext_field = calloc(1, sizeof (struct filedata_item_type_extend_field));
	if (ext_field == NULL) {
		FERROR("Extended field parse: out of memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ext_field->fitef_linkage);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Index", child->key) == 0) {
			status = filedata_config_get_int(child,
						         &ext_field->fitef_index);
			if (status) {
				FERROR("Extended field: failed to get value"
					" for \"%s\"", child->key);
				break;
			}
			if (ext_field->fitef_index - 1 !=
				ext->fite_field_number) {
				FERROR("Extended field: invalid Index: %d",
				       ext_field->fitef_index);
				status = -EINVAL;
				break;
			}
		} else if (strcasecmp("Name", child->key) == 0) {
			field = filedata_item_extend_field_find(type, child->key);
			if (field != NULL) {
				FERROR("Extended field: field \"%s\" already"
				       " existed", child->key);
				status = -EINVAL;
				break;
			}
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Extended field: failed to get value"
					" for \"%s\"", child->key);
				break;
			}
			if (strlen(value) >= sizeof(ext_field->fitef_name)) {
				FERROR("Extended field: length of name \"%s\""
				       " overflow, upper limit is: %lu",
				        value,
					sizeof(ext_field->fitef_name) - 1);
				free(value);
				break;
			}
			strncpy(ext_field->fitef_name, value, MAX_NAME_LENGH);
			free(value);
		} else {
			FERROR("Extended field: unknow value \"%s\"",
					child->key);
			break;
		}
	}

	if (status) {
		free(ext_field);
	} else {
		filedata_item_type_extend_field_add(ext, ext_field);
	}

	return status;
}

static void filedata_item_type_extend_add(struct filedata_item_type *type,
					  struct filedata_item_type_extend *ext)
{
	list_add_tail(&ext->fite_linkage, &type->fit_extends);
	ext->fite_item_type = type;
}

static int filedata_config_extended_parse(const oconfig_item_t *ci,
					  struct filedata_item_type *type)
{
	int i, j;
	int status = 0;
	struct filedata_item_type_extend *extend;
	char *value;
	int found;

	extend = calloc(1, sizeof (struct filedata_item_type_extend));
	if (extend == NULL) {
		FERROR("Extended parse: not enough memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&extend->fite_fields);
	INIT_LIST_HEAD(&extend->fite_linkage);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Extend parse: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}

			found = 0;
			for (j = 1; j <= type->fit_field_number; j++) {
				if (strcmp(type->fit_field_array[j]->fft_name,
					   value) == 0) {
					found = 1;
					extend->fite_field_index = j;
					break;
				}
			}

			if (!found) {
				FERROR("Extended parse: failed to find"
				       " extend of \"%s\"", value);
				status = -EINVAL;
				free(value);
				break;
			}

			free(value);
		} else if (strcasecmp("Pattern", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Extended parse: failed to get value"
				       " for \"%s\"", child->key);
				break;
			}
			if (strlen(value) > MAX_NAME_LENGH) {
				FERROR("Extended parse: value \"%s\" is too"
				       "long", value);
				status = -EINVAL;
				free(value);
				break;
			}
			strncpy(extend->fite_string, value, MAX_NAME_LENGH);
			status = filedata_compile_regex(&extend->fite_regex,
							value);
			free(value);
			if (status) {
				FERROR("Extended parse: failed to compile"
				       " regex");
				break;
			}
			extend->fite_regex_inited = 1;
		} else if (strcasecmp("ExtendedField", child->key) == 0) {
			status = filedata_config_extended_field(child, extend, type);
			if (status) {
				FERROR("Extended parse: failed to parse"
				       " extended field");
				break;
			}
		} else {
			FERROR("Extended parse: invalid key \"%s\"",
			       child->key);
			status = -EINVAL;
		}
	}

	if (status) {
		filedata_item_type_extend_free(extend);
	} else {
		filedata_item_type_extend_add(type, extend);
	}

	return status;
}

static int filedata_config_item_filter(const oconfig_item_t *ci,
				       struct filedata_item *item)
{
	struct filedata_item_filter	*filter = NULL;
	struct filedata_item_type	*type = NULL;
	char	*value = NULL;
	int 	i = 0, status = 0;
	int 	found = 0, j = 0;

	type = item->fi_type;
	if (type == NULL) {
		FERROR("Filter: type is not inited");
		return -EINVAL;
	}

	for (i = 0;i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Field", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Filter: failed to get value for \"%s\"",
				child->key);
				break;
			}

			filter = calloc(1, sizeof(struct filedata_item_filter));
			if (filter == NULL) {
				FERROR("Filter: not enough memory");
				status = -ENOMEM;
				free(value);
				break;
			}
			INIT_LIST_HEAD(&filter->fif_linkage);

			found = 0;
			for (j = 1; j <= type->fit_field_number; j++) {
				if (strcmp(value, type->fit_field_array[j]->fft_name) == 0) {
					found = 1;
					filter->fif_field_index = j;
					break;
				}
			}
			if (!found) {
				FERROR("Filter: failed to find field of \"%s\"",
				      value);
				free(filter);
				free(value);
				status = -EINVAL;
				break;
			}

			strncpy(filter->fif_string, value, MAX_NAME_LENGH);
			filedata_item_filter_add(item, filter);
			free(value);
		} else {
			FERROR("Item: The \"%s\" key is not allowed inside "
				"<Filter /> blocks and will be ignored.",
				child->key);
		}
	}

	return status;
}

static int filedata_entry_activate(struct filedata_entry *entry)
{
	struct filedata_entry *parent;

	entry->fe_active = 1;
	parent = entry->fe_parent;
	if (parent != NULL) {
		if (list_empty(&entry->fe_active_linkage)) {
			list_add_tail(&entry->fe_active_linkage,
				      &parent->fe_active_children);
			if (!parent->fe_active) {
				filedata_entry_activate(parent);
			}
		}
	}
	return 0;
}

struct filedata_item *filedata_item_alloc()
{
	struct filedata_item *item;

	item = calloc(1, sizeof (struct filedata_item));
	if (item == NULL) {
		FERROR("Item: not enough memory");
		return NULL;
	}
	INIT_LIST_HEAD(&item->fi_rules);
	INIT_LIST_HEAD(&item->fi_filters);
	item->fi_query_interval = 1;
	return item;
}

void filedata_item_add(struct filedata_item *item)
{
	struct filedata_item_type *type;
	struct filedata_entry *entry;

	type = item->fi_type;
	entry = type->fit_entry;
	list_add_tail(&item->fi_linkage, &type->fit_items);

	if (list_empty(&type->fit_active_linkage)) {
		list_add_tail(&type->fit_active_linkage,
			      &entry->fe_active_item_types);
	}
	filedata_entry_activate(entry);
}

static int filedata_config_item(const oconfig_item_t *ci,
				struct filedata_configs *conf)
{
	int i;
	int status = 0;
	struct filedata_item *item;
	char *value;

	if (!conf->fc_definition.fd_inited) {
		FERROR("Item: definition is not inited yet");
		return -1;
	}

	item = filedata_item_alloc();
	if (item == NULL) {
		FERROR("Item: failed to alloc item");
		return -1;
	}
	item->fi_definition = &conf->fc_definition;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Type", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string (child, &value);
			if (status) {
				FERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
			item->fi_type = filedata_item_type_find(
				conf->fc_definition.fd_root,
				value);
			if (item->fi_type == NULL) {
				FERROR("Item: failed to get type for \"%s\"",
				       value);
				status = -1;
				free(value);
				break;
			}
			free(value);
		} else if (strcasecmp("Rule", child->key) == 0) {
			status = filedata_config_item_rule(child, item);
			if (status) {
				FERROR("Item: failed to parse rule");
				break;
			}
		} else if (strcasecmp("Query_interval", child->key) == 0) {
			status = filedata_config_get_int(child,
				&item->fi_query_interval);
			if (status) {
				FERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
			if (item->fi_query_interval <= 0) {
				status = -EINVAL;
				FERROR("Item: query interval should be "
				       "positive, %d", item->fi_query_interval);
				break;
			}
		} else if (strcasecmp("Filter", child->key) == 0) {
			status = filedata_config_item_filter (child, item);
			if (status) {
				FERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
		} else {
      			FERROR("Item: The \"%s\" key is not allowed inside "
          		      "<Rule /> blocks and will be ignored.",
          		      child->key);
          	}
		if (status != 0)
			break;
	}

	if (status) {
		filedata_item_free(item);
	} else {
		filedata_item_add(item);
	}

	return (status);
}

static int filedata_config_option(const oconfig_item_t *ci,
				  struct filedata_field_type *field)
{
	int i;
	int flag = 0;
	struct filedata_submit_option *option = NULL;
	char string[1024];
	int inited = 0;
	int status = 0;
	char *value;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Name", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Field option parse: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}
			status = filedata_option_name_extract(value,
							&field->fft_submit,
							&flag,
							&option);
			if (status) {
				FERROR("XML: unkown option");
				break;
			}
			free(value);
		} else if (strcasecmp("Value", child->key) == 0) {
			if (inited != 0) {
				FERROR("Field option: more than one type");
				status = -1;
				break;
			}

			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Field option: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}
			strncpy(string, value, 1024);
			free(value);
			inited = 1;
		} else {
			FERROR("Field option: invalid key \"%s\"",
			       child->key);
			status = -EINVAL;
		}
	}

	if (status) {
		return status;
	}

	if (flag == 0 || option == NULL) {
		FERROR("Field option: option has no name");
		return -1;
	}

	filedata_option_init(option, string);
	return 0;
}

static int filedata_config_field_parse(const oconfig_item_t *ci,
				       struct filedata_item_type *type)
{
	int i, j;
	int status = 0;
	char *value;
	struct filedata_field_type *field = NULL;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			if (field != NULL) {
				status = -1;
				FERROR("Field option parse: multiple field "
				       "found");
				break;
			}

			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("Field option parse: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}

			for (j = 1; j <= type->fit_field_number; j++) {
				if (strcmp(type->fit_field_array[j]->fft_name,
					   value) == 0) {
					field = type->fit_field_array[j];
					break;
				}
			}

			if (field == NULL) {
				FERROR("Field option parse: failed to find"
				       " field of \"%s\"", value);
				status = -EINVAL;
				free(value);
				break;
			}

			free(value);
		} else if (strcasecmp("Option", child->key) == 0) {
			if (field == NULL) {
				status = -1;
				FERROR("Field option parse: no field "
				       "found");
				break;
			}

			status = filedata_config_option(child, field);
			if (status) {
				FERROR("Field option parse: failed to parse"
				       " option");
				break;
			}
		} else {
			FERROR("Field option parse: invalid key \"%s\"",
			       child->key);
			status = -EINVAL;
		}
	}

	return status;
}

static int filedata_config_item_type(const oconfig_item_t *ci,
				     struct filedata_configs *conf)
{
	int i;
	int status = 0;
	struct filedata_item_type *type = NULL;
	char *value;

	if (!conf->fc_definition.fd_inited) {
		FERROR("ItemType: definition is not inited yet");
		return -1;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Type", child->key) == 0) {
			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("ItemType: failed to get value for"
				       " \"%s\"", child->key);
				break;
			}

			type = filedata_item_type_find(
					conf->fc_definition.fd_root,
					value);
			if (type == NULL) {
				FERROR("ItemType: failed to get type"
				       " for \"%s\"", value);
				status = -1;
				free(value);
				break;
			}
			free(value);
		} else if (strcasecmp("ExtendedParse", child->key) == 0) {
			if (type == NULL) {
				FERROR("ItemType: wrong config file"
				       " need to specify item type");
				status = -1;
				break;
			}

			status = filedata_config_extended_parse(child, type);
			if (status) {
				FERROR("ItemType: failed to do extented parse");
				break;
			}
		} else if (strcasecmp("TsdbTags", child->key) == 0) {
			if (type == NULL) {
				FERROR("ItemType: wrong config file"
				       " need to specify item type");
				status = -1;
				break;
			}

			value = NULL;
			status = filedata_config_get_string(child, &value);
			if (status) {
				FERROR("ItemType: failed to get value"
				       " for \"%s\"", child->key);
				break;
			}

			if (strlen(value) >= sizeof(type->fit_ext_tags)) {
				FERROR("ItemType: length of \"%s\" is"
				       " overflow, upper limit is: %lu",
				       value,
				       sizeof(type->fit_ext_tags) - 1);
				status = -EINVAL;
				free(value);
				break;
			}
			strncpy(type->fit_ext_tags, value,
				MAX_TSDB_TAGS_LENGTH);
			free(value);
		} else if (strcasecmp("FieldOption", child->key) == 0) {
			if (type == NULL) {
				FERROR("ItemType: wrong config file"
				       " need to specify item type");
				status = -1;
				break;
			}

			status = filedata_config_field_parse(child, type);
			if (status) {
				FERROR("ItemType: failed to do extented parse");
				break;
			}
		}
	}

	if (status && type != NULL) {
		filedata_item_type_extend_destroy(type);
	}

	return status;
}

void filedata_config_free(struct filedata_configs *conf)
{
	assert(conf);
	if (conf->fc_definition.fd_private_definition.fd_private_fini)
		conf->fc_definition.fd_private_definition.fd_private_fini(conf);
	filedata_definition_fini(&conf->fc_definition);

	free(conf);
}

struct filedata_configs *filedata_config(oconfig_item_t *ci,
		struct filedata_private_definition *fd_private_definition)
{
	int i;
	int status = 0;
	struct filedata_configs *config;

	config = calloc(1, sizeof (struct filedata_configs));
	if (config == NULL) {
		FERROR("not enough memory\n");
		return NULL;
	}

	if (fd_private_definition)
		config->fc_definition.fd_private_definition =
			*fd_private_definition;

	if (fd_private_definition && fd_private_definition->fd_private_init) {
		status = fd_private_definition->fd_private_init(config);
		if (status < 0)
			goto out;
	}

	for (i = 0; i < ci->children_num; i++)
	{
		oconfig_item_t *child = ci->children + i;

		if (strcasecmp ("Common", child->key) == 0) {
			status = filedata_config_common(child, config);
		} else if (strcasecmp ("Item", child->key) == 0) {
			status = filedata_config_item(child, config);
		} else if (strcasecmp ("ItemType", child->key) == 0) {
			status = filedata_config_item_type(child, config);
		} else {
			FERROR("Filedata: Ignoring unknown "
					"configuration option: \"%s\"\n",
			      child->key);
		}
		if (status) {
			FERROR("Filedata: failed to parse configure\n");
			goto out;
		}
	}

	filedata_config_dump(config);
	//filedata_entry_dump_active(config->fc_definition.ld_root, 0);

out:
	if (status != 0) {
		filedata_config_free(config);
		config = NULL;
	}
	return config;
}

#define MAX_INDENT 80

#define filedata_config_print_line(fp, indent, format, ...)    \
do {                                                         \
    char _buf[MAX_INDENT];                                   \
    int _i;                                                  \
    for (_i = 0; _i < MAX_INDENT && _i < indent; _i++) {     \
        _buf[_i] = ' ';                                      \
    }                                                        \
    _buf[_i] = '\0';                                         \
    fprintf(fp, "%s"format"\n", _buf, ##__VA_ARGS__);            \
} while(0)

static void filedata_rule_print(FILE *fp, int indent,
				struct filedata_item_rule *rule,
				struct filedata_item_type *type)
{
	filedata_config_print_line(fp, indent, "<Rule>");
	indent++;
	filedata_config_print_line(fp, indent, "Field \"%s\"",
		type->fit_field_array[rule->fir_field_index]->fft_name);
	filedata_config_print_line(fp, indent, "Match \"%s\"",
				   rule->fir_string);
	indent--;
	filedata_config_print_line(fp, indent, "</Rule>");
}

static void filedata_item_print(FILE *fp, int indent,
				struct filedata_item *item)
{
	struct filedata_item_type *type = item->fi_type;
	struct filedata_item_rule *rule;

	filedata_config_print_line(fp, indent, "<Item>");
	indent++;
	filedata_config_print_line(fp, indent, "Type \"%s\"",
				   type->fit_type_name);
	list_for_each_entry(rule,
			    &item->fi_rules,
			    fir_linkage) {
		filedata_rule_print(fp, indent, rule, type);
	}
	indent--;
	filedata_config_print_line(fp, indent, "</Item>");
}

static void filedata_item_type_print(FILE *fp, int indent,
				     struct filedata_item_type *type)
{
	struct filedata_item *item;

	assert(!list_empty(&type->fit_items));
	list_for_each_entry(item,
			    &type->fit_items,
			    fi_linkage) {
		filedata_item_print(fp, indent, item);
	}
}

static void filedata_active_entry_print(FILE *fp, int indent,
					struct filedata_entry *entry)
{
	struct filedata_item_type *type;
	struct filedata_entry *child;

	assert(entry->fe_active);
	assert(entry->fe_mode == S_IFREG || entry->fe_mode == S_IFDIR);
	if (entry->fe_mode == S_IFREG) {
		assert(list_empty(&entry->fe_active_children));
		assert(list_empty(&entry->fe_children));
		list_for_each_entry(type,
				    &entry->fe_active_item_types,
				    fit_active_linkage) {
			filedata_item_type_print(fp, indent, type);
		}
	} else {
		assert(list_empty(&entry->fe_active_item_types));
		assert(list_empty(&entry->fe_item_types));
		list_for_each_entry(child,
		                    &entry->fe_active_children,
		                    fe_active_linkage) {
			filedata_active_entry_print(fp, indent, child);
		}
	}
}

static void filedata_config_print(struct filedata_configs *conf, FILE *fp)
{
	int indent = 0;

	filedata_config_print_line(fp, indent, "<Plugin \"filedata\">");
	indent++;
	filedata_config_print_line(fp, indent, "<Common>");
	indent++;
	filedata_config_print_line(fp, indent,
			 "DefinitionFile \"%s\"",
			 conf->fc_definition.fd_filename);
	indent--;
	filedata_config_print_line(fp, indent, "</Common>");
	filedata_active_entry_print(fp, indent, conf->fc_definition.fd_root);
	indent--;
	filedata_config_print_line(fp, indent, "</Plugin>");
}

#define TMP_SUFFIX ".tmp"
#define SWAP_SUFFIX ".swap"
const char *config_plugin_start = "^[[:space:]]*<[[:space:]]*Plugin(.+)>";
const char *config_plugin_end = "^[[:space:]]*<[[:space:]]*/[[:space:]]*Plugin[[:space:]]*>";

#define CONFIG_NONE_FILEDATA 0
#define CONFIG_FILEDATA      1

static int filedata_replace_file(const char *oldfile, const char *newfile)
{
	int ret;
	int size;
	char *tmp_file;

	size = strlen(oldfile) + strlen(SWAP_SUFFIX) + 1;

	tmp_file = malloc(size);
	if (tmp_file == NULL) {
		ret = -1;
		return ret;
	}
	snprintf(tmp_file, size, "%s"SWAP_SUFFIX, oldfile);

	ret = rename(oldfile, tmp_file);
	if (ret) {
		goto out_free;
	}

	ret = rename(newfile, oldfile);
	if (ret) {
		goto out_free;
	}

	ret = unlink(tmp_file);
out_free:
	free(tmp_file);
	return ret;
}

int filedata_config_save(struct filedata_configs *conf,
			 const char *config_file)
{
	char *tmp_file;
	int size;
	FILE *config_fp;
	int ret = 0;
	FILE *tmp_fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	regex_t start_regex;
	regex_t end_regex;
	int status = CONFIG_NONE_FILEDATA;
	regmatch_t fields[2];
	int nomatch;

	ret = filedata_compile_regex(&start_regex,
				     config_plugin_start);
	if (ret) {
		return -1;
	}

	ret = filedata_compile_regex(&end_regex,
				     config_plugin_end);
	if (ret) {
		goto out_start;
	}

	size = strlen(config_file) + strlen(TMP_SUFFIX) + 1;

	tmp_file = malloc(size);
	if (tmp_file == NULL) {
		ret = -1;
		goto out_end;
	}

	snprintf(tmp_file, size, "%s"TMP_SUFFIX, config_file);
	tmp_fp = fopen(tmp_file, "w");
	if (tmp_fp == NULL) {
		ret = -1;
		goto out_free;
	}

	config_fp = fopen(config_file, "r");
	if (config_fp == NULL) {
		ret = -1;
		goto out_close_tmp;
	}

	while ((read = getline(&line, &len, config_fp)) != -1) {
		int write;
		if (status == CONFIG_NONE_FILEDATA) {
			/* Not found Filedata plugin */
			int start;
			char *filedata;
			nomatch = regexec(&start_regex,
					      line,
					      2,
					      fields,
					      0);
			if (!nomatch) {
				start = fields[1].rm_so;
				filedata = strcasestr(line + start, "filedata");
				if (filedata != NULL) {
					status = CONFIG_FILEDATA;
					filedata_config_print(conf, tmp_fp);
					continue;
				}
			}
		} else if (status == CONFIG_FILEDATA) {
			/* Found Filedata plugin */
			nomatch = regexec(&end_regex,
					  line,
					  0,
					  NULL,
					  0);
			if (!nomatch) {
				status = CONFIG_NONE_FILEDATA;
				continue;
			}
		}

		if (status == CONFIG_NONE_FILEDATA) {
			write = fprintf(tmp_fp, "%s", line);
			if (write < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (line) {
		free(line);
	}

	filedata_replace_file(config_file, tmp_file);

	fclose(config_fp);
out_close_tmp:
	fclose(tmp_fp);
out_free:
	free(tmp_file);
out_end:
	regfree(&end_regex);
out_start:
	regfree(&start_regex);
	return ret;
}
