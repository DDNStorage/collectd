#include "collectd.h"
#include "liboconfig/oconfig.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"
#include "zbxjson.h"
#include <stdio.h>

#define MAX_ID_LEN	21

char zbx_num2hex(unsigned char c)
{
	if (c >= 10)
		return c + 0x57; /* a-f */
	else
		return c + 0x30; /* 0-9 */
}

static void __zbx_json_realloc(struct zbx_json *j, size_t need)
{
	int	realloc = 0;

	if (NULL == j->buffer) {
		if (need > sizeof(j->buf_stat)) {
			j->buffer_allocated = need;
			j->buffer = malloc(j->buffer_allocated);
		} else {
			j->buffer_allocated = sizeof(j->buf_stat);
			j->buffer = j->buf_stat;
		}
		return;
	}

	while (need > j->buffer_allocated) {
		if (0 == j->buffer_allocated)
			j->buffer_allocated = 1024;
		else
			j->buffer_allocated *= 2;
		realloc = 1;
	}

	if (1 == realloc) {
		if (j->buffer == j->buf_stat) {
			j->buffer = NULL;
			j->buffer = malloc(j->buffer_allocated);
			memcpy(j->buffer, j->buf_stat, sizeof(j->buf_stat));
		} else {
			free(j->buffer);
			j->buffer = malloc(j->buffer_allocated);
		}
	}
}

void zbx_json_init(struct zbx_json *j, size_t allocate)
{
	assert(j);

	j->buffer = NULL;
	j->buffer_allocated = 0;
	j->buffer_offset = 0;
	j->buffer_size = 0;
	j->status = ZBX_JSON_EMPTY;
	j->level = 0;
	__zbx_json_realloc(j, allocate);
	*j->buffer = '\0';

	zbx_json_addobject(j, NULL);
}

void zbx_json_clean(struct zbx_json *j)
{
	assert(j);

	j->buffer_offset = 0;
	j->buffer_size = 0;
	j->status = ZBX_JSON_EMPTY;
	j->level = 0;
	*j->buffer = '\0';

	zbx_json_addobject(j, NULL);
}

void zbx_json_free(struct zbx_json *j)
{
	assert(j);

	if (j->buffer != j->buf_stat)
		free(j->buffer);
}

static size_t __zbx_json_stringsize(const char *string, zbx_json_type_t type)
{
	size_t		len = 0;
	const char	*sptr;
	char		buffer[] = {"null"};

	for (sptr = (NULL != string ? string : buffer); '\0' != *sptr; sptr++) {
		switch (*sptr) {
		case '"':  /* quotation mark */
		case '\\': /* reverse solidus */
		case '/':  /* solidus */
		case '\b': /* backspace */
		case '\f': /* formfeed */
		case '\n': /* newline */
		case '\r': /* carriage return */
		case '\t': /* horizontal tab */
			len += 2;
			break;
		default:
			if (0 != iscntrl(*sptr))
				len += 6;
			else
				len++;
		}
	}

	if (NULL != string && ZBX_JSON_TYPE_STRING == type)
		len += 2; /* "" */

	return len;
}

static char *__zbx_json_insstring(char *p,
			const char *string,
			zbx_json_type_t type)
{
	const char	*sptr;
	char		buffer[] = {"null"};

	if (NULL != string && ZBX_JSON_TYPE_STRING == type)
		*p++ = '"';

	for (sptr = (NULL != string ? string : buffer); '\0' != *sptr; sptr++) {
		switch (*sptr) {
		case '"':		/* quotation mark */
			*p++ = '\\';
			*p++ = '"';
			break;
		case '\\':		/* reverse solidus */
			*p++ = '\\';
			*p++ = '\\';
			break;
		case '/':		/* solidus */
			*p++ = '\\';
			*p++ = '/';
			break;
		case '\b':		/* backspace */
			*p++ = '\\';
			*p++ = 'b';
			break;
		case '\f':		/* formfeed */
			*p++ = '\\';
			*p++ = 'f';
			break;
		case '\n':		/* newline */
			*p++ = '\\';
			*p++ = 'n';
			break;
		case '\r':		/* carriage return */
			*p++ = '\\';
			*p++ = 'r';
			break;
		case '\t':		/* horizontal tab */
			*p++ = '\\';
			*p++ = 't';
			break;
		default:
			if (0 != iscntrl(*sptr)) {
				*p++ = '\\';
				*p++ = 'u';
				*p++ = '0';
				*p++ = '0';
				*p++ = zbx_num2hex((*sptr >> 4) & 0xf);
				*p++ = zbx_num2hex(*sptr & 0xf);
			} else
				*p++ = *sptr;
		}
	}

	if (NULL != string && ZBX_JSON_TYPE_STRING == type)
		*p++ = '"';

	return p;
}

static void __zbx_json_addobject(struct zbx_json *j,
				 const char *name,
				 int object)
{
	size_t	len = 2; /* brackets */
	char	*p, *psrc, *pdst;
	int	i;

	assert(j);

	if (ZBX_JSON_COMMA == j->status)
		len++; /* , */

	if (0 != j->level)
		len++;
	len += j->level;

	if (NULL != name) {
		len += __zbx_json_stringsize(name, ZBX_JSON_TYPE_STRING);
		len += 1; /* : */
	}

	__zbx_json_realloc(j, j->buffer_size + len + 1/*'\0'*/);

	psrc = j->buffer + j->buffer_offset;
	pdst = j->buffer + j->buffer_offset + len;

	memmove(pdst, psrc, j->buffer_size - j->buffer_offset + 1/*'\0'*/);

	p = psrc;

	if (ZBX_JSON_COMMA == j->status)
		*p++ = ',';

	if (0 != j->level)
		*p++ = '\n';
	for (i = 0; i < j->level; i++)
		*p++ = '\t';

	if (NULL != name) {
		p = __zbx_json_insstring(p, name, ZBX_JSON_TYPE_STRING);
		*p++ = ':';
	}

	*p++ = object ? '{' : '[';
	*p = object ? '}' : ']';

	j->buffer_offset = p - j->buffer;
	j->buffer_size += len;
	j->level++;
	j->status = ZBX_JSON_EMPTY;
}

void zbx_json_addobject(struct zbx_json *j, const char *name)
{
	__zbx_json_addobject(j, name, 1);
}

void zbx_json_addarray(struct zbx_json *j, const char *name)
{
	__zbx_json_addobject(j, name, 0);
}

void zbx_json_addstring(struct zbx_json *j,
						const char *name,
						const char *string,
						zbx_json_type_t type)
{
	size_t	len = 0;
	char	*p, *psrc, *pdst;
	int	i;

	assert(j);

	if (ZBX_JSON_COMMA == j->status)
		len++; /* , */

	if (NULL != name) {
		len += 1 + j->level;
		len += __zbx_json_stringsize(name, ZBX_JSON_TYPE_STRING);
		len += 1; /* : */
	}
	len += __zbx_json_stringsize(string, type);

	__zbx_json_realloc(j, j->buffer_size + len + 1/*'\0'*/);

	psrc = j->buffer + j->buffer_offset;
	pdst = j->buffer + j->buffer_offset + len;

	memmove(pdst, psrc, j->buffer_size - j->buffer_offset + 1/*'\0'*/);

	p = psrc;

	if (ZBX_JSON_COMMA == j->status)
		*p++ = ',';

	if (NULL != name) {
		*p++ = '\n';
		for (i = 0; i < j->level; i++)
			*p++ = '\t';
		p = __zbx_json_insstring(p, name, ZBX_JSON_TYPE_STRING);
		*p++ = ':';
	}
	p = __zbx_json_insstring(p, string, type);

	j->buffer_offset = p - j->buffer;
	j->buffer_size += len;
	j->status = ZBX_JSON_COMMA;
}

void zbx_json_adduint64(struct zbx_json *j, const char *name, uint64_t value)
{
	char buffer[MAX_ID_LEN];

	snprintf(buffer, sizeof(buffer), "%"PRIu64, value);
	zbx_json_addstring(j, name, buffer, ZBX_JSON_TYPE_INT);
}

int zbx_json_close(struct zbx_json *j)
{
	if (1 == j->level) {
		ERROR("Json: cannot close top level object");
		return -1;
	}

	j->level--;
	j->buffer_offset++;
	j->status = ZBX_JSON_COMMA;

	return 0;
}
