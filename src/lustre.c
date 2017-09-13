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
#include "lustre_read.h"

struct lustre_configs *lustre_config_g = NULL;

static int lustre_read(void)
{
	struct list_head path_head;

	if (lustre_config_g == NULL) {
		ERROR("lustre plugin is not configured properly");
		return -1;
	}

	if (!lustre_config_g->lc_definition.ld_root->le_active)
		return 0;

	lustre_config_g->lc_definition.ld_query_times++;
	INIT_LIST_HEAD(&path_head);
	return lustre_entry_read(lustre_config_g->lc_definition.ld_root,
				 "/",
				 &path_head);
}

static int lustre_config_internal(oconfig_item_t *ci)
{
	lustre_config_g = lustre_config(ci, NULL);
	if (lustre_config_g == NULL) {
		ERROR("failed to configure lustre");
		return 0;
	}
	return 1;
}

static int lustre_shutdown()
{
	if (lustre_config_g)
		lustre_definition_fini(&lustre_config_g->lc_definition);

	return 0;
}

void module_register (void)
{
	plugin_register_complex_config("lustre", lustre_config_internal);
	plugin_register_read("lustre", lustre_read);
	plugin_register_shutdown ("lustre", lustre_shutdown);
} /* void module_register */
