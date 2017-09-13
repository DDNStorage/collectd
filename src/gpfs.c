/**
 * collectd - src/gpfs.c
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

#include <string.h>
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "lustre_config.h"
#include "lustre_read.h"

struct lustre_configs *gpfs_config_g;

#define START_FILE_SIZE (1048576)
#define MAX_FILE_SIZE   (1048576 * 1024)
#define GPFS_CMD_FILE "/tmp/gpfs_cmd_file_XXXXXX"
/* TODO: configurable path of command */
#define GPFS_MMPMON_PREFIX "/usr/lpp/mmfs/bin/mmpmon -p -i "
#define GPFS_MAX_LENGTH (1024)

static int gpfs_read_file(const char *path, char **buf, ssize_t *data_size)
{
	char cmd_file[sizeof(GPFS_CMD_FILE) + 1];
	char cmd[GPFS_MAX_LENGTH];
	char mmpmon[GPFS_MAX_LENGTH];
	int max_size = sizeof(mmpmon) - 1;
	int bufsize = START_FILE_SIZE;
	char *filebuf;
	int fd;
	FILE *fp;
	ssize_t len;
	ssize_t offset = 0;
	int ret = 0;
	int ret2 = 0;

	filebuf = malloc(bufsize);
	if (filebuf == NULL) {
		ERROR("failed to allocate memory");
		return -1;
	}

	/* Create temporary file */
	strncpy(cmd_file, GPFS_CMD_FILE, sizeof(cmd_file));
	fd = mkstemp(cmd_file);
	if (fd < 0) {
		ERROR("failed to create temporary file \"%s\"", cmd_file);
		ret = -1;
		goto out_free;
	}

	/* Prepare mmpmon system command */
	assert(sizeof(mmpmon) > strlen(GPFS_MMPMON_PREFIX) + strlen(cmd_file));
	strncpy(mmpmon, GPFS_MMPMON_PREFIX, max_size);
	max_size -= strlen(GPFS_MMPMON_PREFIX);
	strncat(mmpmon, cmd_file, max_size);
	max_size -= strlen(cmd_file);

	/* Prepare request command, skipping leading / */
	snprintf(cmd, sizeof(cmd), "%s\n", path + 1);

	/* Write request command to temporary file */
	len = write(fd, cmd, strlen(cmd));
	close(fd);
	if (len != strlen(cmd)) {
		ret = -1;
		ERROR("failed to write command file, len = %ld\n", len);
		goto out_unlink;
	}

	INFO("gpfs command: \"%s\", "
	     "content: \"%s\"", mmpmon, cmd);
	/* Execute the command */
	fp = popen(mmpmon, "r");
	if (fp == NULL) {
		ERROR("failed to run command: \"%s\", "
		      "content: \"%s\"\n", mmpmon, cmd);
		goto out_unlink;
	}

	while (fgets(filebuf + offset, bufsize - offset, fp)
	       != NULL) {
		offset += strlen(filebuf + offset);
		if (bufsize <= offset + 1) {
			char *p;

			INFO("buffer size(%d) is not enough, offset: %ld",
			     bufsize, offset);
			bufsize *= 2;
			if (bufsize > MAX_FILE_SIZE) {
				ERROR("too much output(%d), skipping",
				      bufsize);
				ret = -1;
				goto out_close;
			}
			p = realloc(filebuf, bufsize);
			if (p == NULL) {
				ERROR("not enough memory");
				ret = -1;
				goto out_close;
			}
			filebuf = p;
		}
	}
	INFO("mmpmon output: \"%s\", length %ld", filebuf, offset);
out_close:
	pclose(fp);
out_unlink:
	ret2 = unlink(cmd_file);
	if (ret2)
		ERROR("failed to unlink file %s\n", cmd_file);
out_free:
	if (ret || ret2) {
		free(filebuf);
	} else {
		*buf = filebuf;
		*data_size = offset;
	}
	return ret == 0 ? ret2 : ret;
}

static int gpfs_read(void)
{
	struct list_head path_head;

	if (gpfs_config_g == NULL) {
		ERROR("gpfs plugin is not configured properly");
		return -1;
	}

	if (!gpfs_config_g->lc_definition.ld_root->le_active)
		return 0;

	gpfs_config_g->lc_definition.ld_query_times++;
	INIT_LIST_HEAD(&path_head);
	return lustre_entry_read(gpfs_config_g->lc_definition.ld_root, "/",
				 &path_head);
}

static int gpfs_config_internal(oconfig_item_t *ci)
{
	gpfs_config_g = lustre_config(ci, NULL);
	if (gpfs_config_g == NULL) {
		ERROR("failed to configure gpfs");
		return 0;
	}
	gpfs_config_g->lc_definition.ld_read_file = gpfs_read_file;
	return 1;
}

void module_register(void)
{
	plugin_register_complex_config("gpfs", gpfs_config_internal);
	plugin_register_read("gpfs", gpfs_read);
} /* void module_register */
