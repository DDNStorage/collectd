#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "syslog.h"
#include "collectd.h"
#include "filedata_config.h"
#include "filedata_read.h"
#include "filedata_common.h"
#include <pthread.h>
#include <sys/types.h>
#include <regex.h>
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <ctype.h>
#include <pwd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>

#define SSH_MAX_COMMAND_SIZE (1024)
#define DEFAULT_RECV_BUFSIZE 512
#define SSH_RESULTS_BUFSIZE 4096
#define SSH_BUFSIZE	50
#define MAX_PATH_LENGTH	4096
#define MAX_IP_ADDRESS_LENGTH 128
#define ERROR_FORMAT ("ERROR: FAILED TO EXECUTE REMOTE COMMAND: ")
#define MIN_CONNECTION_INTERVAL 2
#define MAX_CONNECTION_INTERVAL 60
#define DEFAULT_IPC_PATH	"/tmp"

/* per server configuration */
struct ssh_server_host {
	char *host_name;
	char *user_name;
	char *user_password;
	char *ipc_dir;
	char *terminator;

	char *sshkey_passphrase;
	char *public_keyfile;
	char *private_keyfile;
	char *known_hosts;

	struct list_head host_linkage;
};

struct ssh_configs {
	pthread_t bg_tid;
	pthread_mutex_t ssh_lock;
	pthread_cond_t  cond_t;

	void *context;
	void *requester;

	struct list_head hosts_link_head;
	struct ssh_server_host *active_host; /* for failover purpose */
	int bg_running:1;
};

struct ssh_entry {
	struct ssh_configs	*ssh_configs;
	struct list_head	ssh_linkage;
};

LIST_HEAD(ssh_link_head);

static int check_config_path(const char *path)
{
	int ret;

	if (path[0] != '/') {
		FERROR("ssh plugin: %s might be a relative path, please use absolute path",
			path);
		return -EINVAL;
	}

	ret = access(path, F_OK);
	if (ret) {
		FERROR("ssh plugin: failed to access %s, %s", path, strerror(errno));
		return -errno;
	}
	return 0;
}

static int verify_knownhost(struct ssh_configs *ssh_configs,
			    LIBSSH2_SESSION *session)
{
	const char *fingerprint;
	struct libssh2_knownhost *host;
	int check;
	int ret;
	size_t len;
	int type;
	LIBSSH2_KNOWNHOSTS *nh;
	struct ssh_server_host *server_host = ssh_configs->active_host;
	const char *hostname = server_host->host_name;

	/* No host file imply StrictHostKeyChecking=no */
	if (!server_host->known_hosts)
		return 0;

	nh = libssh2_knownhost_init(session);
	if (!nh)
		return -errno;

	/*
	 * libssh2_knownhost_readfile() might return errors if
	 * it find some unspported format, howerver we ignore
	 * errors for two reasons:
	 *
	 * 1) It might have parsed supported format, target host might
	 * be there. it could try further.
	 * 2) skip unsupported format to walkaround it.
	 *
	 */
	ret = libssh2_knownhost_readfile(nh, server_host->known_hosts,
					 LIBSSH2_KNOWNHOST_FILE_OPENSSH);
	if (ret < 0)
		FERROR("ssh plugin: ignored libssh2_knownhost_readfile return ret: %d", ret);

	fingerprint = libssh2_session_hostkey(session, &len, &type);
	if (fingerprint) {
#if LIBSSH2_VERSION_NUM >= 0x010206
		/* introduced in 1.2.6 */
		check = libssh2_knownhost_checkp(nh, hostname, 22,
						 fingerprint, len,
						 LIBSSH2_KNOWNHOST_TYPE_PLAIN|
						 LIBSSH2_KNOWNHOST_KEYENC_RAW,
						 &host);
#else
		/* 1.2.5 or older */
		check = libssh2_knownhost_check(nh, hostname,
						fingerprint, len,
						LIBSSH2_KNOWNHOST_TYPE_PLAIN|
						LIBSSH2_KNOWNHOST_KEYENC_RAW,
						&host);
#endif
		libssh2_knownhost_free(nh);
		switch (check) {
		case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
			FERROR("ssh plugin: something prevented the check to be made");
			return -EPERM;
		case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
		case LIBSSH2_KNOWNHOST_CHECK_MATCH:
			return 0;
		case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
			FERROR("ssh plugin: host was found, but keys didn't match");
			return -EPERM;
		default:
			FERROR("ssh plugin: unknonwn host checks errors");
			return -EPERM;
		}
		return 0;
	}

	libssh2_knownhost_free(nh);
	return 0;
}

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
	struct timeval timeout;
	int rc;
	fd_set fd;
	int dir;
	fd_set *writefd = NULL;
	fd_set *readfd = NULL;

	timeout.tv_sec = 0;
	timeout.tv_usec = 500000;

	FD_ZERO(&fd);
	FD_SET(socket_fd, &fd);

	/* now make sure we wait in the correct direction */
	dir = libssh2_session_block_directions(session);
	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		readfd = &fd;
	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		writefd = &fd;

	rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
	return rc;
}

static int execute_remote_processes(LIBSSH2_SESSION *session,
				    LIBSSH2_CHANNEL *channel,
				    int sock, char *command,
				    int command_len,
				    void **result, int *result_len,
				    char *end_string)
{
	int rc;
	char buffer[256];
	unsigned int nbytes = 0;
	unsigned int pre_nbytes = 0;
	char *p;
	const char numfds = 1;
	struct pollfd pfds[numfds];
	int len;
	int retry = 0;
	int total_retry = (int)CDTIME_T_TO_TIME_T(plugin_get_interval()) << 1;
	int count = 0;


	/* Prepare to use poll */
	memset(pfds, 0, sizeof(struct pollfd) * numfds);
	pfds[0].fd = sock;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

	len = strlen(command);
	/* adjust command format */
	command[len] = '\n';

	nbytes = 0;
	memset(*result, 0, *result_len);
	for ( ; ; ) {
		do {
			rc = libssh2_channel_write(channel, command + nbytes,
						   strlen(command) - nbytes);
			if (rc > 0)
				nbytes += rc;
		} while (rc > 0 && nbytes < strlen(command));
		if (rc == LIBSSH2_ERROR_EAGAIN && pre_nbytes != nbytes)
			waitsocket(sock, session);
		else
			break;
		pre_nbytes = nbytes;
	}
	if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
		/* errno is 0 in this case */
		FERROR("ssh plugin: libssh2_channel_write error: %d", rc);
		return rc;
	}

	/* Polling on socket and stdin while we are
	 * not ready to read from it */
	rc = poll(pfds, numfds, -1);
	if (rc < 0)
		return rc;

	if (!pfds[0].revents & POLLIN)
		return 0;

	nbytes = 0;
	pre_nbytes = 0;
	count = 0;
	for ( ; ; ) {
		/* loop until we block */
		do {
			memset(buffer, 0, sizeof(buffer));
			rc = libssh2_channel_read(channel, buffer,
						  sizeof(buffer));
			if (rc > 0 && nbytes + rc >= *result_len) {
				*result_len += *result_len;
				p = realloc(*result, *result_len);
				if (!p)
					return -ENOMEM;
				*result = p;
			}
			if (rc > 0) {
				memcpy((char *)(*result) + nbytes,
					buffer, rc);
				nbytes += rc;
			}
		} while (rc > 0);

		if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
			FERROR("ssh plugin: libssh2_channel_read error: %s",
				strerror(errno));
			return rc;
		} else if (rc == 0) {
			break;
		}

		/*
		 * We break out in following case:
		 * 1. could not read more, end of string matched
		 * 2. we could not read more if timeout happen.
		 */
		p = *result;
		if (pre_nbytes == nbytes &&
		    end_string && nbytes > strlen(end_string) << 1 &&
		    strstr(p + nbytes - strlen(end_string) - 1, end_string)) {
			FINFO("ssh plugin: tried: %d times to match ssh terminator: %s",
			       count, end_string);
			break;
		} else if (pre_nbytes == nbytes && retry < total_retry) {
			waitsocket(sock, session);
			retry++;
			count++;
		} else if (pre_nbytes != nbytes) {
			waitsocket(sock, session);
			retry = 0;
			count++;
		} else {
			FERROR("ssh plugin: timeout but without "
				"ssh terminator found, considering enlarge timeout or check terminator?");
			return -ETIMEDOUT;
		}
		pre_nbytes = nbytes;
	}

	return nbytes;
}

static void send_keepalive_if_needed(void *zmq_socket, LIBSSH2_SESSION *session)
{
	zmq_pollitem_t items[1];
	int next_seconds = 0;
	int ret;

	while (zmq_socket && session) {
		items[0].socket = zmq_socket;
		items[0].events = ZMQ_POLLIN;
		ret = zmq_poll(items, 1, 10000);
		if (ret == 0) {
			DEBUG("ssh plugin: send keepalive messages after 10s timeout");
			ret = libssh2_keepalive_send(session, &next_seconds);
			if (ret)
				FERROR("ssh plugin: ignored keepalive error: %d", ret);
		} else {
			if (ret < 0)
				FERROR("ssh plugin: zmq_poll return error: %d", ret);
			break;
		}
	}

}

static int zmq_msg_recv_once(zmq_msg_t *request, void *responder,
			     int flags, char **buf, int *len,
			     LIBSSH2_SESSION *session)
{
	int ret = 0;
	int msg_len = 0;
	int more;
	size_t more_size = sizeof(more);
	char *ptr;
	int new_len;
	int data_len;

	if (*buf == NULL) {
		*buf = calloc(1, *len);
		if (!*buf)
			return -ENOMEM;
	} else {
		memset(*buf, 0, *len);
	}

	while (1) {
		ret = zmq_msg_init(request);
		if (ret < 0) {
			FERROR("ssh plugin: zmq_msg_init failed");
			goto free_mem;
		}

		/* send keepalive messages if necessary */
		send_keepalive_if_needed(responder, session);
#ifdef HAVE_ZMQ_NEW_VER
		ret = zmq_msg_recv(request, responder, 0);
#else
		ret = zmq_recv(responder, request, 0);
#endif
		if (ret < 0) {
			zmq_msg_close(request);
			FERROR("ssh plugin: zmq_msg_recv failed");
			goto free_mem;
		}

		data_len = zmq_msg_size(request);
		msg_len += data_len;
		/* keep more space for later use */
		new_len = *len;
		while (new_len < msg_len + 1)
			new_len *= 2;
		if (new_len > *len) {
			ptr = realloc(*buf, new_len);
			if (!ptr) {
				ret = -ENOMEM;
				zmq_msg_close(request);
				goto free_mem;
			}
			*buf = ptr;
			memset(*buf + *len, 0, new_len - *len);
			*len = new_len;
		}
		memcpy(*buf + msg_len - data_len,
			(char *)zmq_msg_data(request), data_len);
		ret = zmq_getsockopt(responder, ZMQ_RCVMORE, &more,
				     &more_size);
		zmq_msg_close(request);
		if (ret < 0) {
			FERROR("ssh plugin: zmq_getsockopt failed");
			msg_len = ret;
			goto free_mem;
		} else if (!more) {
			break;
		}
	}
	return msg_len;
free_mem:
	free(*buf);
	*buf = NULL;
	return ret;
}

/*
 * There are two ways to authenticate.
 * 1.Public key, users should always use this way.
 * 2.Password, dangerous to store password inside configurations.
 */
static int ssh_userauth_connection(LIBSSH2_SESSION *session,
				   struct ssh_configs *ssh_configs)
{
	int rc;
	struct ssh_server_host *server_host = ssh_configs->active_host;

	while ((rc = libssh2_userauth_publickey_fromfile(session,
		server_host->user_name,
		server_host->public_keyfile,
		server_host->private_keyfile,
		server_host->sshkey_passphrase)) == LIBSSH2_ERROR_EAGAIN);
	if (rc == 0)
		return 0;
	if (!server_host->user_password)
		return -EPERM;
	while ((rc = libssh2_userauth_password(session, server_host->user_name,
		server_host->user_password)) == LIBSSH2_ERROR_EAGAIN);
	if (rc == 0)
		return 0;
	return -EPERM;
}

static void exit_client_zmq_connection(struct ssh_configs *ssh_configs)
{
	if (ssh_configs->requester) {
		zmq_close(ssh_configs->requester);
		ssh_configs->requester = NULL;
	}
	if (ssh_configs->context) {
#ifdef HAVE_ZMQ_NEW_VER
		zmq_ctx_destroy(ssh_configs->context);
#else
		zmq_term(ssh_configs->context);
#endif
		ssh_configs->context = NULL;
	}
}


static int init_client_zmq_connection(struct ssh_configs *ssh_configs)
{
	int ret;
	char str[SSH_BUFSIZE];
	struct ssh_server_host *server_host = ssh_configs->active_host;

	/* init zeromq client here */
#ifdef HAVE_ZMQ_NEW_VER
	ssh_configs->context = zmq_ctx_new();
#else
	ssh_configs->context = zmq_init(1);
#endif
	if (!ssh_configs->context) {
		FERROR("ssh plugin: failed to create context, %s",
			strerror(errno));
		return -errno;
	}
	ssh_configs->requester = zmq_socket(ssh_configs->context,
					     ZMQ_REQ);
	if (!ssh_configs->requester) {
		FERROR("ssh plugin: failed to create socket, %s",
			strerror(errno));
		ret = -errno;
		goto failed;
	}
	snprintf(str, SSH_BUFSIZE, "ipc:///%s/%s.ipc",
		      server_host->ipc_dir ? : DEFAULT_IPC_PATH,
		      server_host->host_name);
	ret = zmq_connect(ssh_configs->requester, str);
	if (ret) {
		FERROR("ssh plugin: zmq client failed to connect, %s",
			strerror(errno));
		goto failed;
	}
	return 0;
failed:
	exit_client_zmq_connection(ssh_configs);
	return ret;
}

static int ssh_setup_socket(struct ssh_configs *ssh_configs)
{
	int rc;
	int sock;
	unsigned long hostaddr;
	struct sockaddr_in sin;
	struct ssh_server_host *server_host = ssh_configs->active_host;

	rc = libssh2_init(0);
	if (rc) {
		FERROR("ssh plugin: failed to call libssh2_init, %s",
			strerror(errno));
		return rc;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		FERROR("ssh plugin: failed to socket, %s", strerror(errno));
		rc = -1;
		goto failed1;
	}

	hostaddr = inet_addr(server_host->host_name);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = hostaddr;
	if (connect(sock, (struct sockaddr *)(&sin),
			sizeof(struct sockaddr_in)) != 0) {
		FERROR("ssh plugin: failed to connect, %s",
			strerror(errno));
		rc = -1;
		goto failed2;
	}
	return sock;

failed2:
	shutdown(sock, 2);
	close(sock);
failed1:
	libssh2_exit();
	return rc;
}

static void ssh_cleanup_socket(int sock)
{
	shutdown(sock, 2);
	close(sock);
	libssh2_exit();
}

static LIBSSH2_SESSION *
ssh_setup_session(struct ssh_configs *ssh_configs, int sock)
{
	LIBSSH2_SESSION *session;
	int rc;

	/* Create a session instance */
	session = libssh2_session_init();
	if (!session) {
		FERROR("ssh plugin: libssh2_session_init failed");
		return NULL;
	}

	/* tell libssh2 we want it all done non-blocking */
	libssh2_session_set_blocking(session, 0);

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and Mac layers.
	 */
	while ((rc = libssh2_session_handshake(session, sock))
			== LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		FERROR("ssh plugin: failed to establish ssh session, %s",
			strerror(errno));
		goto free_session;
	}

	/* verify the server's identity */
	rc = verify_knownhost(ssh_configs, session);
	if (rc < 0) {
		FERROR("ssh plugin: failed to verify knownhost: %s",
			strerror(errno));
		goto disconnect_session;
	}

	/* Authenticate ourselves */
	rc = ssh_userauth_connection(session, ssh_configs);
	if (rc) {
		FERROR("ssh plugin: error authenticating with password, %d",
			rc);
		goto disconnect_session;
	}
	return session;

disconnect_session:
	libssh2_session_disconnect(session, NULL);
free_session:
	libssh2_session_free(session);
	return NULL;
}

void ssh_cleanup_session(LIBSSH2_SESSION *session)
{
	libssh2_session_disconnect(session, NULL);
	libssh2_session_free(session);
}

static LIBSSH2_CHANNEL *
ssh_setup_channel(LIBSSH2_SESSION * session, int sock)
{
	LIBSSH2_CHANNEL *channel;
	int rc;

	/* request a shell */
	while ((channel = libssh2_channel_open_session(session)) == NULL
		&& libssh2_session_last_error(session, NULL, NULL, 0)
			== LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock, session);
	if (!channel) {
		FERROR("ssh plugin: libssh2_channel_open_session failed: %s",
			strerror(errno));
		return NULL;
	}

	libssh2_channel_set_blocking(channel, 0);

	/* request a terminal with 'vanilla' terminal emulation */
	do {
		rc = libssh2_channel_request_pty(channel, "vanilla");
		if (rc == LIBSSH2_ERROR_EAGAIN)
			waitsocket(sock, session);
	} while (rc == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		FERROR("ssh plugin: rc: %d, failed to request ptyn: %s",
			rc, strerror(errno));
		goto failed;
	}

	/* open a shell on that pty */
	do {
		rc = libssh2_channel_shell(channel);
		if (rc == LIBSSH2_ERROR_EAGAIN)
			waitsocket(sock, session);
	} while (rc == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		FERROR("ssh plugin: failed to request shell on allocated pty: %s",
			strerror(errno));
		goto failed;
	}

	return channel;
failed:
	while ((rc = libssh2_channel_close(channel))
			== LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock, session);
	libssh2_channel_free(channel);
	return NULL;
}

void ssh_cleanup_channel(int sock, LIBSSH2_SESSION* session,
		    LIBSSH2_CHANNEL *channel)
{

	int rc;

	while ((rc = libssh2_channel_close(channel))
			== LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock, session);
	libssh2_channel_free(channel);
}

static int ssh_handle_request(struct ssh_configs *ssh_configs, int sock,
			      LIBSSH2_SESSION * session, LIBSSH2_CHANNEL *channel)
{
	zmq_msg_t request;
	zmq_msg_t reply;
	int rc = 0;
	void *context;
	void *responder;
	void *result;
	char *receive_buf = NULL;
	int receive_buf_len = DEFAULT_RECV_BUFSIZE;
	int result_len = SSH_RESULTS_BUFSIZE;
	char str[SSH_BUFSIZE];
	struct ssh_server_host *server_host = ssh_configs->active_host;

	receive_buf = calloc(receive_buf_len, 1);
	if (!receive_buf)
		return -ENOMEM;

	result = calloc(result_len, 1);
	if (!result) {
		rc = -ENOMEM;
		goto free_result;
	}

	/* we need keep ssh connection and start a zeromq server here. */
#ifdef HAVE_ZMQ_NEW_VER
	context = zmq_ctx_new();
#else
	context = zmq_init(1);
#endif
	if (!context) {
		FERROR("ssh plugin: failed to create context, %s",
			strerror(errno));
		goto free_result;
	}

	/* start server zmq */
	responder = zmq_socket(context, ZMQ_REP);
	if (!responder) {
		FERROR("ssh plugin: failed to create socket, %s",
			strerror(errno));
		goto term_zmq;
	}
	snprintf(str, SSH_BUFSIZE, "ipc:///%s/%s.ipc",
		      server_host->ipc_dir ? : DEFAULT_IPC_PATH,
		      server_host->host_name);
	rc = zmq_bind(responder, str);
	if (rc) {
		FERROR("ssh plugin: failed to bind %s, %s", str,
			strerror(errno));
		goto close_zmq;
	}

	rc = init_client_zmq_connection(ssh_configs);
	if (rc)
		goto unbind_zmq;

	pthread_mutex_lock(&ssh_configs->ssh_lock);
	ssh_configs->bg_running = 1;
	pthread_cond_signal(&ssh_configs->cond_t);
	pthread_mutex_unlock(&ssh_configs->ssh_lock);

	 /* pre-run to ignore login messages */
	rc = execute_remote_processes(session, channel, sock, receive_buf,
                                      receive_buf_len, &result, &result_len,
				      server_host->terminator);

	/* keepalive message sent every 10s */
	libssh2_keepalive_config(session, 0, 10);

	while (1) {
		/* Step 1: start a zeromq demon to listen request */
		rc = zmq_msg_recv_once(&request, responder, 0,
				       &receive_buf, &receive_buf_len,
				       session);
		if (rc < 0) {
			FERROR("ssh plugin: failed to receive message: ret: %d %s",
				rc, strerror(errno));
			goto cleanup_client_zmq;
		}
		/* Step 2: Filter listening request */

		/* Step 3: execute remote process */
		rc = execute_remote_processes(session, channel, sock,
					      receive_buf, receive_buf_len,
					      &result, &result_len,
					      server_host->terminator);
		if (rc < 0) {
			FERROR("ssh plugin: failed to execute remote command, rc %d, %s",
				rc, receive_buf);
			/* if we failed here, we need let sender know we failed here */
			memcpy(result, ERROR_FORMAT, strlen(ERROR_FORMAT));
			/* connectio have been broken */
			if (rc == -EIDRM)
				break;
			rc =  strlen(ERROR_FORMAT);
		}

		/* Step 4: return results to collectd */
		zmq_msg_init_size(&reply, rc);
		memset(zmq_msg_data(&reply), 0, rc);
		memcpy(zmq_msg_data(&reply), result, rc);
#ifdef HAVE_ZMQ_NEW_VER
		rc = zmq_msg_send(&reply, responder, 0);
#else
		rc = zmq_send(responder, &reply, 0);
#endif
		zmq_msg_close(&reply);
		if (rc < 0) {
			FERROR("ssh plugin: failed to send results to collector, %s",
				strerror(errno));
			break;
		}
	}
cleanup_client_zmq:
	exit_client_zmq_connection(ssh_configs);
unbind_zmq:
#ifdef HAVE_ZMQ_NEW_VER
	zmq_unbind(responder, str);
#endif
close_zmq:
	zmq_close(responder);
term_zmq:
#ifdef HAVE_ZMQ_NEW_VER
	zmq_ctx_destroy(context);
#else
	zmq_term(context);
#endif
free_result:
	if (!ssh_configs->bg_running) {
		pthread_mutex_lock(&ssh_configs->ssh_lock);
		pthread_cond_signal(&ssh_configs->cond_t);
		pthread_mutex_unlock(&ssh_configs->ssh_lock);
	}
	free(result);
	free(receive_buf);
	return rc;
}

static void *ssh_connection_thread(void *arg)
{
	struct ssh_configs *ssh_configs = (struct ssh_configs *)
					    arg;
	struct ssh_server_host *server_host = ssh_configs->active_host;
	int sock;
	LIBSSH2_SESSION * session = NULL;
	LIBSSH2_CHANNEL *channel = NULL;
	int conn_interval = MIN_CONNECTION_INTERVAL;
	int rc;
	struct ssh_server_host *first_host = server_host;

	while (1) {
		sock = ssh_setup_socket(ssh_configs);
		if (sock < 0)
			goto restart;

		session = ssh_setup_session(ssh_configs, sock);
		if (!session) {
			ssh_cleanup_socket(sock);
			goto restart;
		}

		channel = ssh_setup_channel(session, sock);
		if (!channel) {
			ssh_cleanup_session(session);
			ssh_cleanup_socket(sock);
			goto restart;
		}

		/* reset conn interval once connection succeed */
		conn_interval = MIN_CONNECTION_INTERVAL;

		rc = ssh_handle_request(ssh_configs, sock, session, channel);
		if (rc) {
			ssh_cleanup_channel(sock, session, channel);
			ssh_cleanup_session(session);
			ssh_cleanup_socket(sock);
		}
restart:

		/* Try next failover node */
		if (server_host->host_linkage.next != &ssh_configs->hosts_link_head)
			server_host = list_entry(server_host->host_linkage.next,
						 struct ssh_server_host, host_linkage);
		else
			server_host = first_host;

		FERROR("ssh plugin: restart ssh connection background thread, "
			"sleep %d seconds, try host: %s", conn_interval,
			server_host->host_name);

		ssh_configs->active_host = server_host;
		/* let's relax a bit and drink coffee */
		sleep(conn_interval);
		/* connection only enlarged when we tried all failver nodes */
		if (ssh_configs->active_host == first_host &&
		    conn_interval <= MAX_CONNECTION_INTERVAL / 2)
			conn_interval *= 2;
		else if (ssh_configs->active_host == first_host)
			conn_interval = MAX_CONNECTION_INTERVAL;

		pthread_mutex_lock(&ssh_configs->ssh_lock);
		if (!ssh_configs->bg_running) {
			ssh_configs->bg_running = 1;
			pthread_cond_signal(&ssh_configs->cond_t);
		}
		pthread_mutex_unlock(&ssh_configs->ssh_lock);
	}

	return NULL;
}

static int ssh_check_host_conf(struct ssh_server_host *server_host)
{

	if (!server_host->host_name) {
		FERROR("ssh plugin: ServerHost: HostName is missing");
		return -EINVAL;
	}

	if (!server_host->user_name) {
		FERROR("ssh plugin: ServerHost: UserName is missing for host: %s",
			server_host->host_name);
		return -EINVAL;
	}
	if (!server_host->terminator) {
		FERROR("ssh plugin: ServerHost: SshTerminator is missing for host: %s",
			server_host->host_name);
		return -EINVAL;
	}
	if (!server_host->public_keyfile &&
	    server_host->private_keyfile) {
		FERROR("ssh plugin: ServerHost: PublicKeyfile missed but PrivateKeyfile "
			"set for host: %s", server_host->host_name);
		return -EINVAL;
	}
	if (server_host->public_keyfile &&
	    !server_host->private_keyfile) {
		FERROR("ssh plugin: ServerHost: PrivateKeyfile set but PublicKeyfile "
			"missed for host: %s", server_host->host_name);
		return -EINVAL;
	}
	if (!server_host->public_keyfile && !server_host->private_keyfile
	    && !server_host->user_password) {
		FERROR("ssh plugin: ServerHost: Neither UserPassword nor PublicKeyfile/PrivateKeyfile"
			"set for host: %s", server_host->host_name);
		return -EINVAL;
	}

	return 0;
}

static int ssh_plugin_init(struct ssh_configs *ssh_configs)
{
	int ret;
	pthread_t tid;
	struct ssh_server_host *server_host;

	pthread_mutex_init(&ssh_configs->ssh_lock, NULL);
	pthread_cond_init(&ssh_configs->cond_t, NULL);

	/* sanity check here */
	list_for_each_entry(server_host, &ssh_configs->hosts_link_head,
			    host_linkage) {
		ret = ssh_check_host_conf(server_host);
		if (ret)
			return -EINVAL;
	}

	/* create thread that run in the background */
	ret = pthread_create(&tid, NULL, ssh_connection_thread,
			     (void *)ssh_configs);
	if (ret < 0) {
		FERROR("ssh plugin: failed to create thread, %s",
			strerror(errno));
		return -errno;
	}
	pthread_mutex_lock(&ssh_configs->ssh_lock);
	pthread_cond_wait(&ssh_configs->cond_t,
			  &ssh_configs->ssh_lock);
	pthread_mutex_unlock(&ssh_configs->ssh_lock);
	if (!ssh_configs->bg_running) {
		FERROR("ssh plugin: background thread have been terminated");
		return -1;
	}
	ret = pthread_detach(tid);
	if (ret < 0) {
		FERROR("ssh plugin: failed to pthread_detach, %s",
			strerror(errno));
		pthread_kill(tid, SIGKILL);
		return -1;
	}
	ssh_configs->bg_tid = tid;
	return 0;
}

static int ssh_read_file(const char *path, char **buf, ssize_t *data_size,
			 void *fd_private_data)
{
	int ret;
	zmq_msg_t request;
	zmq_msg_t reply;
	char *receive_buf = NULL;
	int receive_buf_len = DEFAULT_RECV_BUFSIZE;
	char cmd[SSH_MAX_COMMAND_SIZE];
	struct ssh_configs *ssh_configs = (struct ssh_configs *)fd_private_data;
	if (!ssh_configs->bg_running) {
		FERROR("ssh plugin: background thread have been terminated");
		return -EIO;
	}
	zmq_msg_init_size(&request, SSH_MAX_COMMAND_SIZE);
	/* Step1 get command string, skipping leading / */
	memset(cmd, 0, SSH_MAX_COMMAND_SIZE);
	snprintf(cmd, SSH_MAX_COMMAND_SIZE, "%s", path + 1);

	/*
	 * Step2 send ssh command to server.
	 */
	memset(zmq_msg_data(&request), 0, SSH_MAX_COMMAND_SIZE);
	memcpy(zmq_msg_data(&request), cmd, strlen(cmd));
#ifdef HAVE_ZMQ_NEW_VER
	ret = zmq_msg_send(&request, ssh_configs->requester, 0);
#else
	ret = zmq_send(ssh_configs->requester, &request, 0);
#endif
	if (ret < 0) {
		FERROR("ssh plugin: failed to send msg, %s",
			strerror(errno));
		return ret;
	}
	zmq_msg_close(&request);

	/*
	 * Step3 get ssh results
	 *
	 * Case1: got expected results.
	 * Case2: got error results(error format?)
	 * Case3: we could not receive anything, timeout happen.
	 */
	ret = zmq_msg_recv_once(&reply, ssh_configs->requester, 0,
				&receive_buf, &receive_buf_len, NULL);
	if (ret < 0) {
		FERROR("ssh plugin: failed to receive msg, %s",
			strerror(errno));
		return ret;
	}
	/* Step4 Filter results */
	if (!strncmp(receive_buf, ERROR_FORMAT, strlen(ERROR_FORMAT))) {
		FERROR("ssh plugin: %s", receive_buf);
		return -EIO;
	}
	/* Step5 Copy results */
	*buf = receive_buf;
	if (!*buf) {
		ret = -ENOMEM;
		goto failed;
	}
	*data_size = ret;
	ret = 0;
failed:
	return ret;
}

static int ssh_read(user_data_t *user_data)
{
	struct list_head path_head;
	struct filedata_configs *ssh_configss = user_data->data;

	if (ssh_configss == NULL) {
		FERROR("ssh plugin is not configured properly");
		return -1;
	}

	if (!ssh_configss->fc_definition.fd_root->fe_active) {
		FERROR("ssh plugin: root entry of ssh plugin is not activated");
		return 0;
	}

	ssh_configss->fc_definition.fd_query_times++;
	INIT_LIST_HEAD(&path_head);
	return filedata_entry_read(ssh_configss->fc_definition.fd_root, "/",
				   &path_head);
}

static int check_server_host(const char *host)
{
	int status;
	regex_t reg;
	const char *pattern = "^\\w+([-+.]\\w)*@\\w+([-.]\\w+)*$";

	return 0;
	regcomp(&reg, pattern, REG_EXTENDED);
	status = regexec(&reg, host, 0, NULL, 0);
	regfree(&reg);
	if (status == 0)
		return 0;
	return -EINVAL;
}


static int ssh_config_init(struct filedata_configs *lc)
{
	struct ssh_configs *ssh_configs;

	ssh_configs = calloc(1, sizeof(struct ssh_configs));
	if (!ssh_configs)
		return -ENOMEM;

	INIT_LIST_HEAD(&ssh_configs->hosts_link_head);
	lc->fc_definition.fd_private_definition.fd_private_data = (void *)ssh_configs;
	return 0;
}

static int host2ip(const char *host, char **ip)
{
	struct hostent *he;
	struct in_addr ip_addr;
	char *IP;

	IP = calloc(1, MAX_IP_ADDRESS_LENGTH);
	if (!IP)
		return -ENOMEM;
	he = gethostbyname(host);
	if (!he) {
		free(IP);
		return -h_errno;
	}
	memcpy(&ip_addr, he->h_addr_list[0], 4);
	inet_ntop(AF_INET, &ip_addr,
		  IP, MAX_IP_ADDRESS_LENGTH);
	*ip = IP;
	return 0;
}

static int parse_server_host(struct ssh_server_host *server_host,
			     char *value)
{
	int ret;

	ret = check_server_host(value);
	if (ret) {
		FERROR("ssh plugin: ignore invalid host: %s", value);
		return ret;
	}

	ret = host2ip(value, &server_host->host_name);
	if (ret)
		FERROR("ssh plugin: failed to parse host: %s to ip", value);

	return ret;
}

static void ssh_config_free_serverhost(struct ssh_server_host *server_host)
{
	if (server_host) {
		free(server_host->host_name);
		free(server_host->user_name);
		free(server_host->public_keyfile);
		free(server_host->private_keyfile);
		free(server_host->known_hosts);
		free(server_host->user_password);
		free(server_host->sshkey_passphrase);
		free(server_host->ipc_dir);
		free(server_host->terminator);
		free(server_host);
	}
}

static int ssh_config_item_serverhost(oconfig_item_t *ci,
				      struct filedata_configs *conf)
{
	int i;
	char *value;
	int ret = 0;
	DIR *dir;

	struct ssh_configs *ssh_configs = (struct ssh_configs *)
					filedata_get_private_data(conf);
	struct ssh_server_host *server_host = calloc(1,
				sizeof(struct ssh_server_host));
	if (!server_host) {
		FERROR("ssh plugin: failed to allocate memory for server host");
		return -ENOMEM;
	}

	for (i = 0; i < ci->children_num; i++) {
		oconfig_item_t *child = ci->children + i;

		value = NULL;
		ret = filedata_config_get_string(child, &value);
		if (ret) {
			FERROR("ssh plugin: failed to get value for: %s",
			       value);
			break;
		}
		if (strcasecmp("HostName", child->key) == 0) {
			free(server_host->host_name);
			ret = parse_server_host(server_host, value);
			free(value);
			if (ret)
				break;
		} else if (strcasecmp("UserName", child->key) == 0) {
			free(server_host->user_name);
			server_host->user_name = value;
		} else if (strcasecmp("KnownhostsFile", child->key) == 0) {
			free(server_host->known_hosts);
			server_host->known_hosts = value;
			ret = check_config_path(value);
			if (ret)
				break;
		} else if (strcasecmp("PublicKeyfile", child->key) == 0) {
			free(server_host->public_keyfile);
			ret = check_config_path(value);
			server_host->public_keyfile = value;
			if (ret)
				break;
		} else if (strcasecmp("PrivateKeyfile", child->key) == 0) {
			free(server_host->private_keyfile);
			server_host->private_keyfile = value;
			ret = check_config_path(value);
			if (ret)
				break;
		} else if (strcasecmp("UserPassword", child->key) == 0) {
			free(server_host->user_password);
			server_host->user_password = value;
		} else if (strcasecmp("SshKeyPassphrase", child->key) == 0) {
			free(server_host->sshkey_passphrase);
			server_host->sshkey_passphrase = value;
		} else if (strcasecmp("SshTerminator", child->key) == 0) {
			free(server_host->terminator);
			server_host->terminator = value;
		} else if (strcasecmp("IpcDir", child->key) == 0) {
			free(server_host->ipc_dir);
			dir = opendir(value);
			if (!dir) {
				FERROR("ssh plugin: failed to opendir %s",
					server_host->ipc_dir);
				break;
			} else {
				closedir(dir);
			}
			server_host->ipc_dir = value;
		} else if (strcasecmp("ZeromqPort", child->key) == 0) {
			FERROR("ssh plugin: ZeromqPort is deprecated, ignore it");
		} else {
			free(value);
			FERROR("ssh plugin: Common, The \"%s\" key is not allowed"
					"and will be ignored.", child->key);
		}
	}

	if (ret == 0) {
		list_add_tail(&server_host->host_linkage,
			      &ssh_configs->hosts_link_head);
		FERROR("add host to tail : %s", server_host->host_name);
		if (!ssh_configs->active_host)
			ssh_configs->active_host = server_host;
	} else {
		ssh_config_free_serverhost(server_host);
	}

	return ret;
}

static int ssh_config_private(oconfig_item_t *ci,
			      struct filedata_configs *conf)
{
	int ret = 0;

	if (strcasecmp("ServerHost", ci->key) == 0)
		ret = ssh_config_item_serverhost(ci, conf);
	else
		FERROR("ssh plugin: Common, The \"%s\" key is not allowed"
			"and will be ignored.", ci->key);
	return ret;
}

static void ssh_config_fini(struct filedata_configs *lc)
{
	struct ssh_server_host *server_host, *tmp;
	struct ssh_configs *ssh_configs = (struct ssh_configs *)
				filedata_get_private_data(lc);
	if (!ssh_configs)
		return;
	exit_client_zmq_connection(ssh_configs);
	if (ssh_configs->bg_tid && ssh_configs->bg_running)
		pthread_kill(ssh_configs->bg_tid, SIGKILL);

	list_for_each_entry_safe(server_host, tmp,
			    &ssh_configs->hosts_link_head, host_linkage) {
		list_del_init(&server_host->host_linkage);
		ssh_config_free_serverhost(server_host);
	}
}

static int ssh_config_internal(oconfig_item_t *ci)
{
	struct filedata_private_definition fd_private_definition;
	struct filedata_configs *ssh_configss;
	struct ssh_configs *ssh_configs;
	user_data_t ud;
	char callback_name[3*DATA_MAX_NAME_LEN];
	int rc;

	fd_private_definition.fd_private_init = ssh_config_init;
	fd_private_definition.fd_private_config = ssh_config_private;
	fd_private_definition.fd_private_fini = ssh_config_fini;
	ssh_configss = filedata_config(ci, &fd_private_definition);
	if (ssh_configss == NULL) {
		FERROR("ssh plugin: failed to configure ssh");
		return -EINVAL;
	}

	ssh_configss->fc_definition.fd_read_file = ssh_read_file;
	ssh_configs = (struct ssh_configs *)filedata_get_private_data(ssh_configss);

	struct ssh_entry *ssh_entry = malloc(sizeof(struct ssh_entry));
	if (!ssh_entry) {
		FERROR("ssh plugin: failed allocate memory for ssh_entry");
		return -ENOMEM;
	}
	ssh_entry->ssh_configs = ssh_configs;
	list_add_tail(&ssh_entry->ssh_linkage, &ssh_link_head);

	memset (&ud, 0, sizeof (ud));
	ud.data = ssh_configss;
	ud.free_func = (void *)ssh_config_fini;

	memset (callback_name, 0, sizeof (callback_name));
	snprintf(callback_name, sizeof (callback_name),
		 "ssh/%s", ssh_configs->active_host->host_name);

	rc = plugin_register_complex_read (/* group = */ NULL,
				/* name      = */ callback_name,
				/* callback  = */ ssh_read,
				/* interval  = */ 0,
				/* user_data = */ &ud);
	if (rc) {
		ssh_config_fini(ssh_configss);
		return rc;
	}
	return 0;
}

static int ssh_plugin_init_once(void)
{
	struct ssh_entry *ssh_entry;
	int rc;
	int total = 0;
	int failed = 0;

	/* should be safe */
	list_for_each_entry(ssh_entry, &ssh_link_head, ssh_linkage)
	{
		rc = ssh_plugin_init(ssh_entry->ssh_configs);
		if (rc) {
			FERROR("ssh plugin: failed to init ssh plugin for host: %s",
				ssh_entry->ssh_configs->active_host->host_name);
			failed++;
			continue;
		}
		total++;
	}
	if (total == failed)
		return -1;

	return 0;

}

void module_register(void)
{
	plugin_register_complex_config("ssh", ssh_config_internal);
	plugin_register_init ("ssh", ssh_plugin_init_once);
} /* void module_register */
