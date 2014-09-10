#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "zbxjson.h"
#include "utils_cache.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <pthread.h>

static char	*zbx_server = NULL;
static char	*zbx_hostname = NULL;
unsigned short	zbx_server_port = 10051;

#define ZBX_SERVER_DEFAULT	"127.0.0.1"
#define ZBX_HOSTNAME_DEFAULT	"localhost"

#define ZBX_CONN_TIMEO	5

#define ZBX_TCP_HEADER_DATA		"ZBXD"
#define ZBX_TCP_HEADER_VERSION		"\1"
#define ZBX_TCP_HEADER	(ZBX_TCP_HEADER_DATA ZBX_TCP_HEADER_VERSION)
#define ZBX_TCP_HEADER_LEN		5

#define ZBX_VALUE_MAX_LEN	64
static const char *config_keys[] = {
	"ServerActive",
	"Hostname"
};

static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static int zbx_tcp_send(int fd, const char *data)
{
	ssize_t status = 0;
	uint64_t len = 0;

	/* write header */
	status = swrite(fd, ZBX_TCP_HEADER, ZBX_TCP_HEADER_LEN);
	if (status < 0) {
		ERROR("zabbix: write header to server failed: %s",
		      strerror(errno));
		return status;
	}

	/* write data length */
	len = strlen(data);
	len = htole64(len);
	status = swrite(fd, (char *)&len, sizeof(len));
	if (status < 0) {
		ERROR("zabbix: write to server failed: %s", strerror(errno));
		return status;
	}

	/* write data */
	status = swrite(fd, data, len);
	if (status < 0) {
		ERROR("zabbix: write to server failed: %s", strerror(errno));
		return status;
	}

	return 0;
}

static int zbx_tcp_connect(char *ip, unsigned short port, int timeo)
{
	struct sockaddr_in servaddr_in;
	int		fd = 0;
	struct timeval	timeout;
	int		status = 0;

	servaddr_in.sin_family = AF_INET;
	servaddr_in.sin_addr.s_addr = inet_addr(ip);
	servaddr_in.sin_port = htons(port);

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ERROR("zabbix: create socket failed: %s", strerror(errno));
		return -1;
	}

	if (0 != timeo) {
		timeout.tv_sec = timeo;
		timeout.tv_usec = 0;
		status = setsockopt(fd,
				    SOL_SOCKET,
				    SO_RCVTIMEO,
				    (struct timeval *)&timeout,
				    sizeof(timeout));
		if (status < 0)
			WARNING("zabbix: set rcvtimeo failed: %s",
				strerror(errno));

		status = setsockopt(fd,
				    SOL_SOCKET,
				    SO_SNDTIMEO,
				    (const char *)&timeout,
				    sizeof(timeout));
		if (status < 0)
			WARNING("zabbix: set sndtimeo failed: %s",
				strerror(errno));
	}

	status = connect(fd,
			 (struct sockaddr *)&servaddr_in,
			 sizeof(servaddr_in));
	if (status < 0) {
		ERROR("zabbix: connect fd failed: %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static void zbx_send_to_server(struct zbx_json *json)
{
	int status = 0;
	int fd = 0;

	if (zbx_server == NULL)
		zbx_server = ZBX_SERVER_DEFAULT;

	if (zbx_hostname == NULL)
		zbx_hostname = ZBX_HOSTNAME_DEFAULT;

	fd = zbx_tcp_connect(zbx_server,
			     zbx_server_port,
			     ZBX_CONN_TIMEO);
	if (fd < 0) {
		ERROR("zabbix: send quit, connect to %s:%d failed",
		      zbx_server, zbx_server_port);
		return ;
	}

	status = zbx_tcp_send(fd, json->buffer);
	if (status < 0) {
		ERROR("zabbix: Send data to server failed");
		close(fd);
		return ;
	}

	close(fd);
}

static void zbx_dispatch_to_server(char *key, char *key_value)
{
	struct zbx_json json;

	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);
	zbx_json_addstring(&json,
			   ZBX_PROTO_TAG_REQUEST,
			   ZBX_PROTO_VALUE_SENDER_DATA,
			   ZBX_JSON_TYPE_STRING);
	zbx_json_addarray(&json, ZBX_PROTO_TAG_DATA);

	zbx_json_addobject(&json, NULL);
	zbx_json_addstring(&json,
			   ZBX_PROTO_TAG_HOST,
			   zbx_hostname,
			   ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json,
			   ZBX_PROTO_TAG_KEY,
			   key,
			   ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json,
			   ZBX_PROTO_TAG_VALUE,
			   key_value,
			   ZBX_JSON_TYPE_STRING);
	zbx_json_close(&json);

	zbx_send_to_server(&json);
	INFO("zabbix: send key: %s value: %s to server",
	     key, key_value);
	zbx_json_free(&json);
}

static int zbx_vl_to_key(char *buffer, size_t buffer_size,
	value_list_t const *vl)
{
	char *pos = NULL;
	char *end = buffer + buffer_size;
	int len = 0;

	len += strlen(vl->plugin) +
	       strlen(vl->plugin_instance) +
	       strlen(vl->type) +
	       strlen(vl->type_instance) + 4;

	if (len > buffer_size) {
		ERROR("zabbix: key len %d is too long", len);
		return -EINVAL;
	}

	pos = buffer;
	if (vl->plugin[0] != '\0') {
		pos += snprintf(pos, end - pos, "%s", vl->plugin);
	}

	if (vl->plugin_instance[0] != '\0') {
		pos += snprintf(pos, end - pos, ".%s", vl->plugin_instance);
	}

	if (vl->type[0] != '\0') {
		pos += snprintf(pos, end - pos, ".%s", vl->type);
	}

	if (vl->type_instance[0] != '\0') {
		pos += snprintf(pos, end - pos, ".%s", vl->type_instance);
	}

	return 0;
}

static int zbx_write(const data_set_t *ds,
		const value_list_t *vl,
		user_data_t __attribute__((unused)) *user_data)
{
	int		i = 0;
	char	key[DATA_MAX_NAME_LEN];
	char	value[ZBX_VALUE_MAX_LEN];
	int	status;
	gauge_t *rate;

	if (ds->ds_num != 1) {
		ERROR ("zabbix: The \"%s\" type (data set) has more than one "
		       "data source. This is currently not supported by this plugin. "
		       "Sorry.", ds->type);
		return (EINVAL);
	}

	rate = uc_get_rate(ds, vl);
	if (rate == NULL) {
		char ident[6 * DATA_MAX_NAME_LEN];
		FORMAT_VL (ident, sizeof (ident), vl);
		ERROR ("zabbix: Unable to read the current rate of \"%s\".",
		       ident);
		return (ENOENT);
	}

	if (isnan(rate[0])) {
		sfree(rate);
		return 0;
	}

	status = zbx_vl_to_key(key, sizeof(key), vl);
	if (status) {
		sfree(rate);
		return status;
	}

	switch(ds->ds[i].type) {
	case DS_TYPE_GAUGE:
		snprintf(value, sizeof(value), "%f", vl->values[i].gauge);
		break;
	case DS_TYPE_DERIVE:
	case DS_TYPE_COUNTER:
	case DS_TYPE_ABSOLUTE:
		snprintf(value, sizeof(value), "%f", rate[0]);
		break;
	default:
		sfree(rate);
		return -EINVAL;
	}

	INFO("zabbix: key: %s value: %s", key, value);
	zbx_dispatch_to_server(key, value);

	sfree(rate);
	return 0;
}

int zbx_parse_serveractive(char *str,
			   char **host,
			   unsigned short *port)
{
	char	*r = NULL;
	int	p = 0;

	r = strchr(str, ':');
	if (r == NULL) {
		ERROR("zabbix: Invalid value: %s, must be like ip:port",
		      str);
		return -EINVAL;
	}

	p = atoi(r + 1);
	if (p < 0) {
		ERROR("zabbix: Port must > 0, now is: %d", p);
		return -EINVAL;
	}
	*port = p;

	*r = '\0';
	*host = strdup(str);
	if (*host == NULL) {
		ERROR("Out of memory");
		return -ENOMEM;
	}

	return 0;
}

static int zbx_config(const char *key, const char *value)
{
	char *serveractive = NULL;
	int  status = 0;

	if (strcasecmp("ServerActive", key) == 0) {
		if (zbx_server != NULL) {
			WARNING("zabbix: ServerActive: %s:%u already existed",
				zbx_server, zbx_server_port);
			return 0;
		}
		serveractive = strdup(value);
		status = zbx_parse_serveractive(serveractive,
						&zbx_server,
						&zbx_server_port);
		if (status) {
			ERROR("zabbix: Parse serveractive failed");
			free(serveractive);
			return -EINVAL;
		}
		INFO("zabbix: server %s:%u", zbx_server, zbx_server_port);
		free(serveractive);
	} else if (strcasecmp("Hostname", key) == 0) {
		if (NULL != zbx_hostname) {
			WARNING("zabbix: Hostname: %s already existed",
				zbx_server);
			return 0;
		}
		zbx_hostname = strdup(value);
		INFO("zabbix: hostname %s", zbx_hostname);
	} else {
		ERROR("zabbix: plugin config error, key: %s value: %s",
		      key, value);
		return -EINVAL;
	}

	return 0;
}

void module_register(void)
{
	plugin_register_config("zabbix", zbx_config,
			       config_keys, config_keys_num);
	plugin_register_write("zabbix", zbx_write, NULL);
}
