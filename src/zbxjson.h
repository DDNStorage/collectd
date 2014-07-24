#ifndef ZABBIX_ZJSON_H
#define ZABBIX_ZJSON_H

#include <stdarg.h>

#define ZBX_PROTO_TAG_DATA		"data"
#define ZBX_PROTO_TAG_HOST		"host"
#define ZBX_PROTO_TAG_KEY		"key"
#define ZBX_PROTO_TAG_REQUEST		"request"
#define ZBX_PROTO_TAG_VALUE		"value"
#define ZBX_PROTO_VALUE_SENDER_DATA		"sender data"

typedef enum {
	ZBX_JSON_TYPE_UNKNOWN = 0,
	ZBX_JSON_TYPE_STRING,
	ZBX_JSON_TYPE_INT,
	ZBX_JSON_TYPE_ARRAY,
	ZBX_JSON_TYPE_OBJECT,
	ZBX_JSON_TYPE_NULL
}
zbx_json_type_t;

typedef enum {
	ZBX_JSON_EMPTY = 0,
	ZBX_JSON_COMMA
}
zbx_json_status_t;

#define ZBX_JSON_STAT_BUF_LEN 4096

struct zbx_json {
	char			*buffer;
	char			buf_stat[ZBX_JSON_STAT_BUF_LEN];
	size_t			buffer_allocated;
	size_t			buffer_offset;
	size_t			buffer_size;
	zbx_json_status_t	status;
	int			level;
};

void zbx_json_init(struct zbx_json *j, size_t allocate);
void zbx_json_clean(struct zbx_json *j);
void zbx_json_free(struct zbx_json *j);
void zbx_json_addobject(struct zbx_json *j, const char *name);
void zbx_json_addarray(struct zbx_json *j, const char *name);
void zbx_json_addstring(struct zbx_json *j,
			   const char *name,
			   const char *string,
			   zbx_json_type_t type);
void zbx_json_adduint64(struct zbx_json *j, const char *name, uint64_t value);
int zbx_json_close(struct zbx_json *j);

#endif /* ZABBIX_ZJSON_H */
