/**
 * collectd - src/filedata_common.h
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

#ifdef FILEDATA_TOOL
#include <stdio.h>

#define FERROR(format, ...)                                                \
do {                                                                       \
    fprintf(stderr, "%s:%d:%s(): "                                         \
            format"\n", __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__); \
} while (0)
#define FINFO FERROR
#else /* !FILEDATA_TOOL */
#include "plugin.h"
#define FERROR ERROR
#define FINFO  INFO
#endif /* !FILEDATA_TOOL */

