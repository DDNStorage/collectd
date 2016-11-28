/**
 * collectd - src/lustre_config.c
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
#include <errno.h>
#include "lustre_common.h"
#include "lustre_config.h"
#include "lustre_xml.h"

int lustre_compile_regex(regex_t *preg, const char *regex)
{
	int status = regcomp(preg, regex, REG_EXTENDED|REG_NEWLINE);
	if (status != 0) {
		char error_message[MAX_NAME_LENGH];
		regerror(status, preg, error_message, MAX_NAME_LENGH);
		return -1;
	}
	return 0;
}

void lustre_item_filter_add(struct lustre_item *item,
			  struct lustre_item_filter *filter)
{
	list_add_tail(&filter->lif_linkage, &item->li_filters);
	filter->lif_item = item;
}

void lustre_item_rule_free(struct lustre_item_rule *rule)
{
	if (rule->lir_regex_inited)
		regfree(&rule->lir_regex);
	free(rule);
}

void lustre_item_rule_add(struct lustre_item *item,
			  struct lustre_item_rule *rule)
{
	list_add_tail(&rule->lir_linkage, &item->li_rules);
	rule->lir_item = item;
}

void lustre_item_rule_replace(struct lustre_item *item,
			      struct lustre_item_rule *old,
			      struct lustre_item_rule *new)
{
	list_add_tail(&new->lir_linkage, &old->lir_linkage);
	new->lir_item = item;
	list_del_init(&old->lir_linkage);
}

void lustre_item_rule_unlink(struct lustre_item_rule *rule)
{
	list_del_init(&rule->lir_linkage);
}

void lustre_item_filter_unlink(struct lustre_item_filter *filter)
{
	list_del_init(&filter->lif_linkage);
}

void lustre_item_unlink(struct lustre_item *item)
{
	list_del_init(&item->li_linkage);
}

void lustre_item_free(struct lustre_item *item)
{
	struct lustre_item_rule *rule;
	struct lustre_item_rule *n;
	struct lustre_item_filter *filter;
	struct lustre_item_filter *tmp;

	list_for_each_entry_safe(rule,
				 n,
	                         &item->li_rules,
	                         lir_linkage) {
		lustre_item_rule_unlink(rule);
		lustre_item_rule_free(rule);
	}

	list_for_each_entry_safe(filter,
				 tmp,
				 &item->li_filters,
				 lif_linkage) {
		lustre_item_filter_unlink(filter);
		free(filter);
	}

	free(item);
}

struct lustre_field_type *lustre_field_type_alloc(void)
{
	struct lustre_field_type *type;

	type = calloc(1, sizeof(struct lustre_field_type));
	if (type == NULL) {
		LERROR("not enough memory");
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
		LERROR("index of field is false");
		return -1;
	}
	field_type->lft_item_type = type;
	list_add_tail(&field_type->lft_linkage, &type->lit_field_list);
	type->lit_field_number++;
	return 0;
}

static void lustre_item_type_extend_free(struct lustre_item_type_extend *ext)
{
	struct lustre_item_type_extend_field *field, *f;

	list_for_each_entry_safe(field, f, &ext->lite_fields, litef_linkage) {
		list_del_init(&field->litef_linkage);
		free(field);
	}

	if (ext->lite_regex_inited)
		regfree(&ext->lite_regex);

	free(ext);
}

static void lustre_item_type_extend_destroy(struct lustre_item_type *type)
{
	struct lustre_item_type_extend *ext, *n;

	list_for_each_entry_safe(ext, n, &type->lit_extends, lite_linkage) {
		list_del_init(&ext->lite_linkage);
		lustre_item_type_extend_free(ext);
	}
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
		lustre_item_unlink(item);
		lustre_item_free(item);
	}
	list_for_each_entry_safe(field_type,
				 f,
	                         &type->lit_field_list,
	                         lft_linkage) {
		list_del_init(&field_type->lft_linkage);
		lustre_field_type_free(field_type);
	}
	lustre_item_type_extend_destroy(type);

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
		LERROR("not enough memory");
		return NULL;
	}
	INIT_LIST_HEAD(&type->lit_linkage);
	INIT_LIST_HEAD(&type->lit_items);
	INIT_LIST_HEAD(&type->lit_extends);
	INIT_LIST_HEAD(&type->lit_field_list);
	INIT_LIST_HEAD(&type->lit_active_linkage);
	return type;
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

struct lustre_item_type_extend_field *
lustre_item_extend_field_find(struct lustre_item_type *type,
		const char *name)
{
	struct lustre_item_type_extend *ext;
	struct lustre_item_type_extend_field *field;

	list_for_each_entry(ext, &type->lit_extends, lite_linkage) {
		list_for_each_entry(field, &ext->lite_fields, litef_linkage) {
			if (strcmp(field->litef_name, name) == 0)
				return field;
		}
	}

	return NULL;
}

static int lustre_item_match_one(struct lustre_field *fields,
				 int field_number,
				 struct lustre_item *item)
{
	struct lustre_item_rule *rule;

	if ((item->li_definition->ld_query_times % item->li_query_interval)
	    != 0) {
		LINFO("%s lustre query times: %llu interval: %d",
		      item->li_type->lit_type_name,
		      item->li_definition->ld_query_times,
		      item->li_query_interval);
		return 0;
	}

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

static int lustre_item_field_allowed(int field_idx, struct lustre_item *item)
{
	struct lustre_item_filter *filter;

	list_for_each_entry(filter, &item->li_filters, lif_linkage) {
		if (field_idx == filter->lif_field_index) {
			return 0;
		}
	}

	return 1;
}

static int lustre_item_filter_match(struct lustre_field *fields,
			      int field_number,
			      struct lustre_item *item)
{
	int i = 0, allowed = 0;

	for (i = 1;i <= field_number;i++) {
		if (fields[i].lf_allowed) {
			allowed++;
			continue;
		}

		fields[i].lf_allowed = lustre_item_field_allowed(i, item);
		if (fields[i].lf_allowed) {
			allowed++;
		}
	}

	return allowed;
}

int lustre_item_match(struct lustre_field *fields,
		      int field_number,
		      struct lustre_item_type *type)
{
	struct lustre_item *item;
	int match = 0, res = 0;

	list_for_each_entry(item,
			    &type->lit_items,
			    li_linkage) {
		if (lustre_item_match_one(fields, field_number, item)) {
			LINFO("values (1:%s) matches an item with type %s",
			      fields[1].lf_string,
			      type->lit_type_name);
			res = lustre_item_filter_match(fields, field_number, item);
			if (res) {
				match = res;
			}
		}
	}

	if (match == 0) {
		LINFO("values (1:%s) does not match any item with type %s",
			fields[1].lf_string,
			type->lit_type_name);
	}
	return match;
}

void lustre_definition_fini(struct lustre_definition *definition)
{
	if (definition->ld_root)
		lustre_entry_free(definition->ld_root);
	if (definition->ld_filename)
		free(definition->ld_filename);
	definition->ld_root = NULL;
	definition->ld_filename = NULL;
	definition->ld_inited = 0;
	definition->ld_query_times = 0;
	definition->ld_read_file = NULL;
}

/* TODO: read form XML file */
static int lustre_definition_init(struct lustre_definition *definition,
				  const char *file)
{
	int status = 0;

	if (definition->ld_inited) {
		LERROR("definition is already inited, igoring %s", file);
		status = -1;
		goto out;
	}

	definition->ld_filename = strdup(file);
	if (definition->ld_filename == NULL) {
		LERROR("Lustre config: failed to copy string %s", file);
		status = -1;
		goto out;
	}

	status = lustre_xml_parse(definition, file);
	if (status) {
		LERROR("Lustre config: failed to parse %s", file);
		goto out;
	}

	definition->ld_inited = 1;
	return 0;
out:
	lustre_definition_fini(definition);
	return status;
}

static void lustre_config_dump(struct lustre_configs *conf)
{
	if (conf == NULL) {
		LERROR("Lustre config: empty config");
		return;
	}
}

int lustre_config_get_string(const oconfig_item_t *ci, char **ret_string)
{
	char *string;

	if ((ci->values_num != 1) ||
	    (ci->values[0].type != OCONFIG_TYPE_STRING)) {
		LERROR("lustre_config_get_string: The %s option requires "
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

static int lustre_config_get_int (const oconfig_item_t *ci, int *ret_value) /* {{{ */
{
	if ((ci == NULL) || (ret_value == NULL))
		return EINVAL;

	if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_NUMBER))
	{
		LERROR ("cf_util_get_int: The %s option requires "
				"exactly one numeric argument.", ci->key);
		return -1;
	}

	*ret_value = (int) ci->values[0].value.number;

	return 0;
}

static int lustre_config_common(const oconfig_item_t *ci,
				struct lustre_configs *conf)
{
	int i;
	int status = 0;
	char *definition_file;
	char *root_path = NULL;
	struct lustre_private_definition ld_private_definition =
				conf->lc_definition.ld_private_definition;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("DefinitionFile", child->key) == 0) {
			definition_file = NULL;
			status = lustre_config_get_string(child, &definition_file);
			if (status) {
				LERROR("Common: failed to get definition file");
				break;
			}

			status = lustre_definition_init(&conf->lc_definition,
							definition_file);
			free(definition_file);
			if (status) {
				LERROR("Common: failed to init definition");
			}
		}  else if (strcasecmp("RootPath", child->key) == 0) {
			/* in case this is specified mutiple times */
			free(root_path);
			root_path = NULL;
			status = lustre_config_get_string(child, &root_path);
			if (status)
				LERROR("Common: failed to init root path");
		} else if (ld_private_definition.ld_private_config) {
			status = ld_private_definition.ld_private_config(child,
									 conf);
		} else {
			LERROR("Common: The \"%s\" key is not allowed"
					"and will be ignored.", child->key);
		}
		if (status != 0)
			break;
	}

	if (root_path && !status) {
		if (conf->lc_definition.ld_inited)
			strncpy(conf->lc_definition.ld_root->le_subpath,
				root_path, MAX_NAME_LENGH);
		free(root_path);
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
		LERROR("Rule: type is not inited\n");
		return -1;
	}

	rule = calloc(1, sizeof (struct lustre_item_rule));
	if (rule == NULL) {
		LERROR("Rule: not enough memory");
		return -1;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Rule: failed to get value for \"%s\"",
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
				LERROR("Rule: failed to get find rule of \"%s\"",
				      value);
				status = -EINVAL;
				free(value);
				break;
			}
			free(value);
		} else if (strcasecmp ("Match", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string (child, &value);
			if (status) {
				LERROR("Rule:failed to get value for \"%s\"",
				      child->key);
				break;
			}
			if (strlen(value) > MAX_NAME_LENGH) {
				LERROR("Rule: value \"%s\" is too long",
				      value);
				status = -EINVAL;
				free(value);
				break;
			}
			strncpy(rule->lir_string, value, MAX_NAME_LENGH);
			status = lustre_compile_regex(&rule->lir_regex,
						      value);
			free(value);
			if (status) {
				LERROR("Rule: failed to compile regex");
				break;
			}
			rule->lir_regex_inited = 1;
		} else {
      			LERROR("Rule: The \"%s\" key is not allowed inside "
          		      "<Item /> blocks and will be ignored.",
          		      child->key);
          	}
		if (status != 0)
			break;
	}

	if (status) {
		lustre_item_rule_free(rule);
	} else {
		lustre_item_rule_add(item, rule);
	}

	return (status);
}

void lustre_item_type_extend_field_add(struct lustre_item_type_extend *ext,
		struct lustre_item_type_extend_field *ext_field)
{
	list_add_tail(&ext_field->litef_linkage, &ext->lite_fields);
	ext_field->litef_ext = ext;
	ext->lite_field_number++;
}

static int lustre_config_extended_field(const oconfig_item_t *ci,
				struct lustre_item_type_extend *ext,
				struct lustre_item_type *type)
{
	struct lustre_item_type_extend_field *ext_field = NULL;
	struct lustre_item_type_extend_field *field = NULL;
	char *value;
	int i;
	int status = 0;

	ext_field = calloc(1, sizeof (struct lustre_item_type_extend_field));
	if (ext_field == NULL) {
		LERROR("Extended field parse: out of memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ext_field->litef_linkage);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Index", child->key) == 0) {
			status = lustre_config_get_int(child,
						&ext_field->litef_index);
			if (status) {
				LERROR("Extended field: failed to get value"
					" for \"%s\"", child->key);
				break;
			}
			if (ext_field->litef_index - 1 !=
				ext->lite_field_number) {
				LERROR("Extended field: invalid Index: %d",
				       ext_field->litef_index);
				status = -EINVAL;
				break;
			}
		} else if (strcasecmp("Name", child->key) == 0) {
			field = lustre_item_extend_field_find(type, child->key);
			if (field != NULL) {
				LERROR("Extended field: field \"%s\" already"
				       " existed", child->key);
				status = -EINVAL;
				break;
			}
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Extended field: failed to get value"
					" for \"%s\"", child->key);
				break;
			}
			if (strlen(value) >= sizeof(ext_field->litef_name)) {
				LERROR("Extended field: length of name \"%s\""
				       " overflow, upper limit is: %lu",
				        value,
					sizeof(ext_field->litef_name) - 1);
				free(value);
				break;
			}
			strncpy(ext_field->litef_name, value, MAX_NAME_LENGH);
			free(value);
		} else {
			LERROR("Extended field: unknow value \"%s\"",
					child->key);
			break;
		}
	}

	if (status) {
		free(ext_field);
	} else {
		lustre_item_type_extend_field_add(ext, ext_field);
	}

	return status;
}

static void lustre_item_type_extend_add(struct lustre_item_type *type,
		struct lustre_item_type_extend *ext)
{
	list_add_tail(&ext->lite_linkage, &type->lit_extends);
	ext->lite_item_type = type;
}

static int lustre_config_extended_parse(const oconfig_item_t *ci,
				struct lustre_item_type *type)
{
	int i, j;
	int status = 0;
	struct lustre_item_type_extend *extend;
	char *value;
	int found;

	extend = calloc(1, sizeof (struct lustre_item_type_extend));
	if (extend == NULL) {
		LERROR("Extended parse: not enough memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&extend->lite_fields);
	INIT_LIST_HEAD(&extend->lite_linkage);

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Extend parse: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}

			found = 0;
			for (j = 1; j <= type->lit_field_number; j++) {
				if (strcmp(type->lit_field_array[j]->lft_name,
					   value) == 0) {
					found = 1;
					extend->lite_field_index = j;
					break;
				}
			}

			if (!found) {
				LERROR("Extended parse: failed to find"
				       " extend of \"%s\"", value);
				status = -EINVAL;
				free(value);
				break;
			}

			free(value);
		} else if (strcasecmp("Pattern", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Extended parse: failed to get value"
				       " for \"%s\"", child->key);
				break;
			}
			if (strlen(value) > MAX_NAME_LENGH) {
				LERROR("Extended parse: value \"%s\" is too"
				       "long", value);
				status = -EINVAL;
				free(value);
				break;
			}
			strncpy(extend->lite_string, value, MAX_NAME_LENGH);
			status = lustre_compile_regex(&extend->lite_regex,
						      value);
			free(value);
			if (status) {
				LERROR("Extended parse: failed to compile"
				       " regex");
				break;
			}
		} else if (strcasecmp("ExtendedField", child->key) == 0) {
			status = lustre_config_extended_field(child, extend, type);
			if (status) {
				LERROR("Extended parse: failed to parse"
				       " extended field");
				break;
			}
		} else {
			LERROR("Extended parse: invalid key \"%s\"",
			       child->key);
			status = -EINVAL;
		}
	}

	if (status) {
		lustre_item_type_extend_free(extend);
	} else {
		lustre_item_type_extend_add(type, extend);
	}

	return status;
}

static int lustre_config_item_filter(const oconfig_item_t *ci,
				struct lustre_item *item)
{
	struct lustre_item_filter *filter = NULL;
	struct lustre_item_type	*type = NULL;
	char	*value = NULL;
	int 	i = 0, status = 0;
	int 	found = 0, j = 0;

	type = item->li_type;
	if (type == NULL) {
		LERROR("Filter: type is not inited");
		return -EINVAL;
	}

	for (i = 0;i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Field", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Filter: failed to get value for \"%s\"",
				child->key);
				break;
			}

			filter = calloc(1, sizeof(struct lustre_item_filter));
			if (filter == NULL) {
				LERROR("Filter: not enough memory");
				status = -ENOMEM;
				free(value);
				break;
			}
			INIT_LIST_HEAD(&filter->lif_linkage);

			found = 0;
			for (j = 1; j <= type->lit_field_number; j++) {
				if (strcmp(value, type->lit_field_array[j]->lft_name) == 0) {
					found = 1;
					filter->lif_field_index = j;
					break;
				}
			}
			if (!found) {
				LERROR("Filter: failed to find field of \"%s\"",
				      value);
				free(filter);
				free(value);
				status = -EINVAL;
				break;
			}

			strncpy(filter->lif_string, value, MAX_NAME_LENGH);
			lustre_item_filter_add(item, filter);
			free(value);
		} else {
			LERROR("Item: The \"%s\" key is not allowed inside "
				"<Filter /> blocks and will be ignored.",
				child->key);
		}
	}

	return status;
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

struct lustre_item *lustre_item_alloc()
{
	struct lustre_item *item;

	item = calloc(1, sizeof (struct lustre_item));
	if (item == NULL) {
		LERROR("Item: not enough memory");
		return NULL;
	}
	INIT_LIST_HEAD(&item->li_rules);
	INIT_LIST_HEAD(&item->li_filters);
	item->li_query_interval = 1;
	return item;
}

void lustre_item_add(struct lustre_item *item)
{
	struct lustre_item_type *type;
	struct lustre_entry *entry;

	type = item->li_type;
	entry = type->lit_entry;
	list_add_tail(&item->li_linkage, &type->lit_items);

	if (list_empty(&type->lit_active_linkage)) {
		list_add_tail(&type->lit_active_linkage,
			      &entry->le_active_item_types);
	}
	lustre_entry_activate(entry);
}

static int lustre_config_item(const oconfig_item_t *ci,
			      struct lustre_configs *conf)
{
	int i;
	int status = 0;
	struct lustre_item *item;
	char *value;

	if (!conf->lc_definition.ld_inited) {
		LERROR("Item: definition is not inited yet");
		return -1;
	}

	item = lustre_item_alloc();
	if (item == NULL) {
		LERROR("Item: failed to alloc item");
		return -1;
	}
	item->li_definition = &conf->lc_definition;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Type", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string (child, &value);
			if (status) {
				LERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
			item->li_type = lustre_item_type_find(
				conf->lc_definition.ld_root,
				value);
			if (item->li_type == NULL) {
				LERROR("Item: failed to get type for \"%s\"",
				       value);
				status = -1;
				free(value);
				break;
			}
			free(value);
		} else if (strcasecmp("Rule", child->key) == 0) {
			status = lustre_config_item_rule(child, item);
			if (status) {
				LERROR("Item: failed to parse rule");
				break;
			}
		} else if (strcasecmp("Query_interval", child->key) == 0) {
			status = lustre_config_get_int(child,
				&item->li_query_interval);
			if (status) {
				LERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
			if (item->li_query_interval <= 0) {
				status = -EINVAL;
				LERROR("Item: query interval should be "
				       "positive, %d", item->li_query_interval);
				break;
			}
		} else if (strcasecmp("Filter", child->key) == 0) {
			status = lustre_config_item_filter (child, item);
			if (status) {
				LERROR("Item: failed to get value for \"%s\"",
				       child->key);
				break;
			}
		} else {
      			LERROR("Item: The \"%s\" key is not allowed inside "
          		      "<Rule /> blocks and will be ignored.",
          		      child->key);
          	}
		if (status != 0)
			break;
	}

	if (status) {
		lustre_item_free(item);
	} else {
		lustre_item_add(item);
	}

	return (status);
}

static int lustre_config_option(const oconfig_item_t *ci,
				struct lustre_field_type *field)
{
	int i;
	int flag = 0;
	struct lustre_submit_option *option = NULL;
	char string[1024];
	int inited = 0;
	int status = 0;
	char *value;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Name", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Field option parse: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}
			status = lustre_option_name_extract(value,
							    &field->lft_submit,
							    &flag,
							    &option);
			if (status) {
				LERROR("XML: unkown option");
				break;
			}
			free(value);
		} else if (strcasecmp("Value", child->key) == 0) {
			if (inited != 0) {
				LERROR("Field option: more than one type");
				status = -1;
				break;
			}

			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Field option: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}
			strncpy(string, value, 1024);
			free(value);
			inited = 1;
		} else {
			LERROR("Field option: invalid key \"%s\"",
			       child->key);
			status = -EINVAL;
		}
	}

	if (status) {
		return status;
	}

	if (flag == 0 || option == NULL) {
		LERROR("Field option: option has no name");
		return -1;
	}

	lustre_option_init(option, string);
	return 0;
}

static int lustre_config_field_parse(const oconfig_item_t *ci,
				     struct lustre_item_type *type)
{
	int i, j;
	int status = 0;
	char *value;
	struct lustre_field_type *field = NULL;

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("Field", child->key) == 0) {
			if (field != NULL) {
				status = -1;
				LERROR("Field option parse: multiple field "
				       "found");
				break;
			}

			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("Field option parse: failed to get value"
				       " of \"%s\"", child->key);
				break;
			}

			for (j = 1; j <= type->lit_field_number; j++) {
				if (strcmp(type->lit_field_array[j]->lft_name,
					   value) == 0) {
					field = type->lit_field_array[j];
					break;
				}
			}

			if (field == NULL) {
				LERROR("Field option parse: failed to find"
				       " field of \"%s\"", value);
				status = -EINVAL;
				free(value);
				break;
			}

			free(value);
		} else if (strcasecmp("Option", child->key) == 0) {
			if (field == NULL) {
				status = -1;
				LERROR("Field option parse: no field "
				       "found");
				break;
			}

			status = lustre_config_option(child, field);
			if (status) {
				LERROR("Field option parse: failed to parse"
				       " option");
				break;
			}
		} else {
			LERROR("Field option parse: invalid key \"%s\"",
			       child->key);
			status = -EINVAL;
		}
	}

	return status;
}

static int lustre_config_item_type(const oconfig_item_t *ci,
			      struct lustre_configs *conf)
{
	int i;
	int status = 0;
	struct lustre_item_type *type = NULL;
	char *value;

	if (!conf->lc_definition.ld_inited) {
		LERROR("ItemType: definition is not inited yet");
		return -1;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp("Type", child->key) == 0) {
			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("ItemType: failed to get value for"
				       " \"%s\"", child->key);
				break;
			}

			type = lustre_item_type_find(
					conf->lc_definition.ld_root,
					value);
			if (type == NULL) {
				LERROR("ItemType: failed to get type"
				       " for \"%s\"", value);
				status = -1;
				free(value);
				break;
			}
			free(value);
		} else if (strcasecmp("ExtendedParse", child->key) == 0) {
			if (type == NULL) {
				LERROR("ItemType: wrong config file"
				       " need to specify item type");
				status = -1;
				break;
			}

			status = lustre_config_extended_parse(child, type);
			if (status) {
				LERROR("ItemType: failed to do extented parse");
				break;
			}
		} else if (strcasecmp("TsdbTags", child->key) == 0) {
			if (type == NULL) {
				LERROR("ItemType: wrong config file"
				       " need to specify item type");
				status = -1;
				break;
			}

			value = NULL;
			status = lustre_config_get_string(child, &value);
			if (status) {
				LERROR("ItemType: failed to get value"
				       " for \"%s\"", child->key);
				break;
			}

			if (strlen(value) >= sizeof(type->lit_ext_tags)) {
				LERROR("ItemType: length of \"%s\" is"
				       " overflow, upper limit is: %lu",
				       value,
				       sizeof(type->lit_ext_tags) - 1);
				status = -EINVAL;
				free(value);
				break;
			}
			strncpy(type->lit_ext_tags, value,
				MAX_TSDB_TAGS_LENGTH);
			free(value);
		} else if (strcasecmp("FieldOption", child->key) == 0) {
			if (type == NULL) {
				LERROR("ItemType: wrong config file"
				       " need to specify item type");
				status = -1;
				break;
			}

			status = lustre_config_field_parse(child, type);
			if (status) {
				LERROR("ItemType: failed to do extented parse");
				break;
			}
		}
	}

	if (status && type != NULL) {
		lustre_item_type_extend_destroy(type);
	}

	return status;
}

void lustre_config_free(struct lustre_configs *conf)
{
	assert(conf);
	if (conf->lc_definition.ld_private_definition.ld_private_fini)
		conf->lc_definition.ld_private_definition.ld_private_fini(conf);
	lustre_definition_fini(&conf->lc_definition);

	free(conf);
}

struct lustre_configs *lustre_config(oconfig_item_t *ci,
			struct lustre_private_definition *ld_private_definition)
{
	int i;
	int status = 0;
	struct lustre_configs *config;

	config = calloc(1, sizeof (struct lustre_configs));
	if (config == NULL) {
		LERROR("not enough memory\n");
		return NULL;
	}

	if (ld_private_definition)
		config->lc_definition.ld_private_definition =
			*ld_private_definition;

	if (ld_private_definition && ld_private_definition->ld_private_init) {
		status = ld_private_definition->ld_private_init(config);
		if (status < 0)
			goto out;
	}

	for (i = 0; i < ci->children_num; i++)
	{
		oconfig_item_t *child = ci->children + i;

		if (strcasecmp ("Common", child->key) == 0) {
			status = lustre_config_common(child, config);
		} else if (strcasecmp ("Item", child->key) == 0) {
			status = lustre_config_item(child, config);
		} else if (strcasecmp ("ItemType", child->key) == 0) {
			status = lustre_config_item_type(child, config);
		} else {
			LERROR("Lustre: Ignoring unknown "
					"configuration option: \"%s\"\n",
			      child->key);
		}
		if (status) {
			LERROR("Lustre: failed to parse configure\n");
			goto out;
		}
	}

	lustre_config_dump(config);
	//lustre_entry_dump_active(config->lc_definition.ld_root, 0);

out:
	if (status != 0) {
		lustre_config_free(config);
		config = NULL;
	}
	return config;
}

#define MAX_INDENT 80

#define lustre_config_print_line(fp, indent, format, ...)    \
do {                                                         \
    char _buf[MAX_INDENT];                                   \
    int _i;                                                  \
    for (_i = 0; _i < MAX_INDENT && _i < indent; _i++) {     \
        _buf[_i] = ' ';                                      \
    }                                                        \
    _buf[_i] = '\0';                                         \
    fprintf(fp, "%s"format"\n", _buf, ##__VA_ARGS__);            \
} while(0)

static void lustre_rule_print(FILE *fp, int indent,
			      struct lustre_item_rule *rule,
			      struct lustre_item_type *type)
{
	lustre_config_print_line(fp, indent, "<Rule>");
	indent++;
	lustre_config_print_line(fp, indent, "Field \"%s\"",
		type->lit_field_array[rule->lir_field_index]->lft_name);
	lustre_config_print_line(fp, indent, "Match \"%s\"",
				 rule->lir_string);
	indent--;
	lustre_config_print_line(fp, indent, "</Rule>");
}

static void lustre_item_print(FILE *fp, int indent,
			      struct lustre_item *item)
{
	struct lustre_item_type *type = item->li_type;
	struct lustre_item_rule *rule;

	lustre_config_print_line(fp, indent, "<Item>");
	indent++;
	lustre_config_print_line(fp, indent, "Type \"%s\"",
				 type->lit_type_name);
	list_for_each_entry(rule,
			    &item->li_rules,
			    lir_linkage) {
		lustre_rule_print(fp, indent, rule, type);
	}
	indent--;
	lustre_config_print_line(fp, indent, "</Item>");
}

static void lustre_item_type_print(FILE *fp, int indent,
				   struct lustre_item_type *type)
{
	struct lustre_item *item;

	assert(!list_empty(&type->lit_items));
	list_for_each_entry(item,
			    &type->lit_items,
			    li_linkage) {
		lustre_item_print(fp, indent, item);
	}
}

static void lustre_active_entry_print(FILE *fp, int indent,
				      struct lustre_entry *entry)
{
	struct lustre_item_type *type;
	struct lustre_entry *child;

	assert(entry->le_active);
	assert(entry->le_mode == S_IFREG || entry->le_mode == S_IFDIR);
	if (entry->le_mode == S_IFREG) {
		assert(list_empty(&entry->le_active_children));
		assert(list_empty(&entry->le_children));
		list_for_each_entry(type,
				    &entry->le_active_item_types,
				    lit_active_linkage) {
			lustre_item_type_print(fp, indent, type);
		}
	} else {
		assert(list_empty(&entry->le_active_item_types));
		assert(list_empty(&entry->le_item_types));
		list_for_each_entry(child,
		                    &entry->le_active_children,
		                    le_active_linkage) {
			lustre_active_entry_print(fp, indent, child);
		}
	}
}

static void lustre_config_print(struct lustre_configs *conf, FILE *fp)
{
	int indent = 0;

	lustre_config_print_line(fp, indent, "<Plugin \"lustre\">");
	indent++;
	lustre_config_print_line(fp, indent, "<Common>");
	indent++;
	lustre_config_print_line(fp, indent,
			 "DefinitionFile \"%s\"",
			 conf->lc_definition.ld_filename);
	indent--;
	lustre_config_print_line(fp, indent, "</Common>");
	lustre_active_entry_print(fp, indent, conf->lc_definition.ld_root);
	indent--;
	lustre_config_print_line(fp, indent, "</Plugin>");
}

#define TMP_SUFFIX ".tmp"
#define SWAP_SUFFIX ".swap"
const char *config_plugin_start = "^[[:space:]]*<[[:space:]]*Plugin(.+)>";
const char *config_plugin_end = "^[[:space:]]*<[[:space:]]*/[[:space:]]*Plugin[[:space:]]*>";

#define CONFIG_NONE_LUSTRE 0
#define CONFIG_LUSTRE      1

static int lustre_replace_file(const char *oldfile, const char *newfile)
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

int lustre_config_save(struct lustre_configs *conf,
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
	int status = CONFIG_NONE_LUSTRE;
	regmatch_t fields[2];
	int nomatch;

	ret = lustre_compile_regex(&start_regex,
				   config_plugin_start);
	if (ret) {
		return -1;
	}

	ret = lustre_compile_regex(&end_regex,
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
		if (status == CONFIG_NONE_LUSTRE) {
			/* Not found Lustre plugin */
			int start;
			char *lustre;
			nomatch = regexec(&start_regex,
					      line,
					      2,
					      fields,
					      0);
			if (!nomatch) {
				start = fields[1].rm_so;
				lustre = strcasestr(line + start, "lustre");
				if (lustre != NULL) {
					status = CONFIG_LUSTRE;
					lustre_config_print(conf, tmp_fp);
					continue;
				}
			}
		} else if (status == CONFIG_LUSTRE) {
			/* Found Lustre plugin */
			nomatch = regexec(&end_regex,
					  line,
					  0,
					  NULL,
					  0);
			if (!nomatch) {
				status = CONFIG_NONE_LUSTRE;
				continue;
			}
		}

		if (status == CONFIG_NONE_LUSTRE) {
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

	lustre_replace_file(config_file, tmp_file);

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
