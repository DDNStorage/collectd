/**
 * collectd - src/filedata.c
 * Copyright (C) 2016 DataDirect Networks
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
 **/

#include <regex.h>
#include "collectd.h"
#include "utils/common/common.h"
#include "plugin.h"
#include "list.h"
#include "filedata_read.h"

static unsigned int filedata_seq = 0;

static int filedata_read(user_data_t *user_data)
{
	struct filedata_configs *filedata_configs = user_data->data;

	if (filedata_configs == NULL) {
		ERROR("filedata plugin is not configured properly");
		return -1;
	}

	if (!filedata_configs->fc_definition.fd_root->fe_active)
		return 0;

	filedata_configs->fc_definition.fd_query_times++;
	return filedata_entry_read(filedata_configs->fc_definition.fd_root,
				   "/");
}

static int filedata_shutdown(struct filedata_configs * filedata_configs)
{
	if (filedata_configs)
		filedata_definition_fini(&filedata_configs->fc_definition);
	return 0;
}

static int filedata_config_internal(oconfig_item_t *ci)
{
	struct filedata_configs *filedata_configs;
	user_data_t ud;
	char callback_name[3*DATA_MAX_NAME_LEN];
	int rc;

	filedata_configs = filedata_config(ci, NULL);
	if (filedata_configs == NULL) {
		ERROR("failed to configure filedata");
		return -1;
	}

	memset (&ud, 0, sizeof (ud));
	ud.data = filedata_configs;
	ud.free_func = (void *)filedata_shutdown;

	memset (callback_name, 0, sizeof (callback_name));
	snprintf(callback_name, sizeof (callback_name),
		 "filedata/%u", filedata_seq);
	filedata_seq++;

	rc = plugin_register_complex_read (/* group = */ NULL,
				/* name      = */ callback_name,
				/* callback  = */ filedata_read,
				/* interval  = */ 0,
				/* user_data = */ &ud);
	if (rc) {
		filedata_shutdown(filedata_configs);
		return rc;
	}
	return 0;
}


void module_register (void)
{
	plugin_register_complex_config("filedata", filedata_config_internal);
} /* void module_register */
