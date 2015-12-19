#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "syslog.h"
#include "collectd.h"
#include "lustre_config.h"
#include "lustre_read.h"
#include "lustre_common.h"
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

static pthread_mutex_t ssh_lock;
static pthread_cond_t  cond_t;
struct lustre_configs *ssh_config_gs;

#define SSH_MAX_COMMAND_SIZE (1024)
#define DEFAULT_RECV_BUFSIZE 512
#define SSH_RESULTS_BUFSIZE 4096
#define SSH_BUFSIZE	50
#define MAX_PATH_LENGTH	4096
#define MAX_IP_ADDRESS_LENGTH 128
#define ERROR_FORMAT ("ERROR: FAILED TO EXECUTE REMOTE COMMAND: ")

struct ssh_configs {
	pthread_t bg_tid;
	void *context;
	void *requester;
	char *server_host;
	char *user_name;
	char *user_password;
	char *zeromq_port;

	/* this can be null */
	char *sshkey_passphrase;
	char *public_keyfile;
	char *private_keyfile;
	char *known_hosts;
	int bg_running: 1;
};

static int check_config_path(const char *path)
{
	int ret;

	if (path[0] != '/') {
		LERROR("ssh plugin: %s might be a relative path, please use absolute path",
			path);
		return -EINVAL;
	}

	ret = access(path, F_OK);
	if (ret) {
		LERROR("ssh plugin: failed to access %s, %s", path, strerror(errno));
		return -errno;
	}
	return 0;
}

static int verify_knownhost(LIBSSH2_SESSION *session, const char *hostname)
{
	const char *fingerprint;
	struct libssh2_knownhost *host;
	int check;
	int ret;
	size_t len;
	int type;
	LIBSSH2_KNOWNHOSTS *nh;
	struct ssh_configs *ssh_config_g = (struct ssh_configs *)
			lustre_get_private_data(ssh_config_gs);

	nh = libssh2_knownhost_init(session);
	if (!nh)
		return -errno;
	ret = libssh2_knownhost_readfile(nh, ssh_config_g->known_hosts,
					 LIBSSH2_KNOWNHOST_FILE_OPENSSH);
	if (ret < 0)
		return ret;
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
		switch (check) {
		case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
			LERROR("ssh plugin: something prevented the check to be made");
			return -EPERM;
		case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
		case LIBSSH2_KNOWNHOST_CHECK_MATCH:
			return 0;
		case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
			LERROR("ssh plugin: host was found, but keys didn't match");
			return -EPERM;
		default:
			LERROR("ssh plugin: unknonwn host checks errors");
			return -EPERM;
		}
		return 0;
	}
	libssh2_knownhost_free(nh);
	return -errno;
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
				    int extra_len)
{
	int rc;
	char buffer[256];
	unsigned int nbytes = 0;
	unsigned int pre_nbytes = 0;
	char *p;
	const char numfds = 1;
	struct pollfd pfds[numfds];
	int len;

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
		LERROR("ssh plugin: libssh2_channel_write error: %s",
			strerror(errno));
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
			LERROR("ssh plugin: libssh2_channel_read error: %s",
				strerror(errno));
			return rc;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN && pre_nbytes != nbytes)
			waitsocket(sock, session);
		else
			break;
		pre_nbytes = nbytes;
	}
	/* filter output here */
	len = strlen(command) + 1;
	if (extra_len && nbytes > len + extra_len) {
		/* clear command parts */
		memmove(*result, *result + len, nbytes - len);
		memset(*result + nbytes - len, 0, len);

		/* clear end string like '[localhost@build]$' */
		memmove(*result, *result, nbytes - len - extra_len);
		memset(*result + nbytes - len - extra_len, 0, extra_len);
		return nbytes - len - extra_len;
	}
	memset(*result, 0, *result_len);
	return nbytes;
}

static int zmq_msg_recv_once(zmq_msg_t *request, void *responder,
			     int flags, char **buf, int *len)
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
			LERROR("ssh plugin: zmq_msg_init failed");
			goto free_mem;
		}
#ifdef HAVE_ZMQ_NEW_VER
		ret = zmq_msg_recv(request, responder, 0);
#else
		ret = zmq_recv(responder, request, 0);
#endif
		if (ret < 0) {
			zmq_msg_close(request);
			LERROR("ssh plugin: zmq_msg_recv failed");
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
			LERROR("ssh plugin: zmq_getsockopt failed");
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
				   struct ssh_configs *ssh_config_g)
{
	int rc;

	while ((rc = libssh2_userauth_publickey_fromfile(session,
		ssh_config_g->user_name,
		ssh_config_g->public_keyfile,
		ssh_config_g->private_keyfile,
		ssh_config_g->sshkey_passphrase)) == LIBSSH2_ERROR_EAGAIN);
	if (rc == 0)
		return 0;
	if (!ssh_config_g->user_password)
		return -EPERM;
	while ((rc = libssh2_userauth_password(session, ssh_config_g->user_name,
		ssh_config_g->user_password)) == LIBSSH2_ERROR_EAGAIN);
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


static int init_client_zmq_connection(struct ssh_configs *ssh_config_g)
{
	int ret;
	char str[SSH_BUFSIZE];

	/* init zeromq client here */
#ifdef HAVE_ZMQ_NEW_VER
	ssh_config_g->context = zmq_ctx_new();
#else
	ssh_config_g->context = zmq_init(1);
#endif
	if (!ssh_config_g->context) {
		LERROR("ssh plugin: failed to create context, %s",
			strerror(errno));
		return -errno;
	}
	ssh_config_g->requester = zmq_socket(ssh_config_g->context,
					     ZMQ_REQ);
	if (!ssh_config_g->requester) {
		LERROR("ssh plugin: failed to create socket, %s",
			strerror(errno));
		ret = -errno;
		goto failed;
	}
	snprintf(str, SSH_BUFSIZE, "tcp://localhost:%s",
		 ssh_config_g->zeromq_port);
	ret = zmq_connect(ssh_config_g->requester, str);
	if (ret) {
		LERROR("ssh plugin: zmq client failed to connect, %s",
			strerror(errno));
		goto failed;
	}
	return 0;
failed:
	exit_client_zmq_connection(ssh_config_g);
	return ret;
}

static void *ssh_connection_thread(void *arg)
{
	zmq_msg_t request;
	zmq_msg_t reply;
	struct ssh_configs *ssh_config_g = (struct ssh_configs *)
			lustre_get_private_data(ssh_config_gs);
	int rc = 0;
	void *context;
	void *responder;
	void *result;
	char str[SSH_BUFSIZE];
	char *receive_buf = NULL;
	int receive_buf_len = DEFAULT_RECV_BUFSIZE;
	unsigned long hostaddr;
	int sock;
	struct sockaddr_in sin;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel = NULL;
	int result_len = SSH_RESULTS_BUFSIZE;
	int extra_len = 0;
	int loop = 0;
	int need_restart = 0;

restart:
	loop++;
	receive_buf = calloc(receive_buf_len, 1);
	if (!receive_buf)
		return NULL;

	snprintf(str, SSH_BUFSIZE, "tcp://*:%s", ssh_config_g->zeromq_port);
	rc = libssh2_init(0);
	if (rc) {
		LERROR("ssh plugin: failed to call libssh2_init, %s",
			strerror(errno));
		return NULL;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		LERROR("ssh plugin: failed to socket, %s", strerror(errno));
		goto exit_ssh;
	}
	hostaddr = inet_addr(ssh_config_g->server_host);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = hostaddr;
	if (connect(sock, (struct sockaddr *)(&sin),
			sizeof(struct sockaddr_in)) != 0) {
		LERROR("ssh plugin: failed to connect, %s",
			strerror(errno));
		if (errno == ECONNREFUSED)
			need_restart = 1;
		goto close_sock;
	}

	/* Create a session instance */
	session = libssh2_session_init();
	if (!session) {
		LERROR("ssh plugin: libssh2_session_init failed");
		goto shutdown_sock;
	}
	/* tell libssh2 we want it all done non-blocking */
	libssh2_session_set_blocking(session, 0);

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and Mac layers.
	 */
	while ((rc = libssh2_session_handshake(session, sock))
			== LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		LERROR("ssh plugin: failed to establish ssh session, %s",
			strerror(errno));
		goto free_session;
	}

	result = calloc(result_len, 1);
	if (!result)
		goto disconnect_session;

	/* verify the server's identity */
	if (verify_knownhost(session, ssh_config_g->server_host) < 0) {
		LERROR("ssh plugin: failed to verify knownhost: %s",
			strerror(errno));
		goto free_result;
	}

	/* Authenticate ourselves */
	rc = ssh_userauth_connection(session, ssh_config_g);
	if (rc) {
		LERROR("ssh plugin: error authenticating with password, %d",
			rc);
		goto free_result;
	}

	/* we need keep ssh connection and start a zeromq server here. */
#ifdef HAVE_ZMQ_NEW_VER
	context = zmq_ctx_new();
#else
	context = zmq_init(1);
#endif
	if (!context) {
		LERROR("ssh plugin: failed to create context, %s",
			strerror(errno));
		goto free_result;
	}

	/* request a shell */
	while ((channel = libssh2_channel_open_session(session)) == NULL
		&& libssh2_session_last_error(session, NULL, NULL, 0)
			== LIBSSH2_ERROR_EAGAIN)
		waitsocket(sock, session);
	if (!channel) {
		LERROR("ssh plugin: libssh2_channel_open_session failed: %s",
			strerror(errno));
		goto free_result;
	}

	libssh2_channel_set_blocking(channel, 0);

	/* request a terminal with 'vanilla' terminal emulation */
	do {
		rc = libssh2_channel_request_pty(channel, "vanilla");
		if (rc == LIBSSH2_ERROR_EAGAIN)
			waitsocket(sock, session);
	} while (rc == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		LERROR("ssh plugin: rc: %d, failed to request ptyn: %s",
			rc, strerror(errno));
		goto free_result;
	}

	/* open a shell on that pty */
	do {
		rc = libssh2_channel_shell(channel);
		if (rc == LIBSSH2_ERROR_EAGAIN)
			waitsocket(sock, session);
	} while (rc == LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		LERROR("ssh plugin: failed to request shell on allocated pty: %s",
			strerror(errno));
		goto free_result;
	}

	/* start server zmq */
	responder = zmq_socket(context, ZMQ_REP);
	if (!responder) {
		LERROR("ssh plugin: failed to create socket, %s",
			strerror(errno));
		goto term_zmq;
	}
	rc = zmq_bind(responder, str);
	if (rc) {
		LERROR("ssh plugin: failed to bind %s, %s", str,
			strerror(errno));
		goto close_zmq;
	}
	rc = init_client_zmq_connection(ssh_config_g);
	if (rc)
		goto unbind_zmq;

	pthread_mutex_lock(&ssh_lock);
	ssh_config_g->bg_running = 1;
	pthread_cond_signal(&cond_t);
	pthread_mutex_unlock(&ssh_lock);

	/* pre-run to ignore login messages */
	rc = execute_remote_processes(session, channel, sock, receive_buf,
				      receive_buf_len, &result, &result_len, 0);
	if (rc < 0)
		LERROR("ssh plugin: failed to pre-run null command");

	/* calculate extra len here */
	rc = execute_remote_processes(session, channel, sock, receive_buf,
				      receive_buf_len, &result, &result_len, 0);
	if (rc > 0)
		extra_len = rc / 2;

	while (1) {
		/* Step 1: start a zeromq demon to listen request */
		rc = zmq_msg_recv_once(&request, responder, 0,
				       &receive_buf, &receive_buf_len);
		if (rc < 0) {
			LERROR("ssh plugin: failed to receive message: ret: %d %s",
				rc, strerror(errno));
			goto cleanup_client_zmq;
		}
		/* Step 2: Filter listening request */

		/* Step 3: execute remote process */
		rc = execute_remote_processes(session, channel, sock,
					      receive_buf, receive_buf_len,
					      &result, &result_len, extra_len);
		if (rc < 0) {
			LERROR("ssh plugin: failed to execute remote command, rc %d, %s",
				rc, receive_buf);
			/* if we failed here, we need let sender know we failed here */
			memcpy(result, ERROR_FORMAT, strlen(ERROR_FORMAT));
			strncat(result, strerror(-rc),
				result_len - strlen(ERROR_FORMAT));
			if (rc == -EIDRM) {
				need_restart = 1;
				break;
			}
		}

		/* Step 4: return results to collectd */
		zmq_msg_init_size(&reply, result_len);
		memset(zmq_msg_data(&reply), 0, result_len);
		memcpy(zmq_msg_data(&reply), result, result_len);
#ifdef HAVE_ZMQ_NEW_VER
		rc = zmq_msg_send(&reply, responder, 0);
#else
		rc = zmq_send(responder, &reply, 0);
#endif
		zmq_msg_close(&reply);
		if (rc < 0) {
			LERROR("ssh plugin: failed to send results to collector, %s",
				strerror(errno));
			break;
		}
	}
cleanup_client_zmq:
	exit_client_zmq_connection(ssh_config_g);
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
	free(result);
	if (channel) {
		while ((rc = libssh2_channel_close(channel))
				== LIBSSH2_ERROR_EAGAIN)
			waitsocket(sock, session);
		libssh2_channel_free(channel);
	}
disconnect_session:
	libssh2_session_disconnect(session, NULL);
free_session:
	libssh2_session_free(session);
shutdown_sock:
	shutdown(sock, 2);
close_sock:
	close(sock);
exit_ssh:
	if (!ssh_config_g->bg_running) {
		pthread_mutex_lock(&ssh_lock);
		pthread_cond_signal(&cond_t);
		pthread_mutex_unlock(&ssh_lock);
	}
	free(receive_buf);
	libssh2_exit();
	/* avoid looping forever */
	if (need_restart && loop < 10) {
		need_restart = 0;
		LERROR("ssh plugin: restart ssh connection background thread, count: %d",
			loop);
		/* let's relax a bit and drink coffee */
		sleep(3);
		goto restart;
	}
	ssh_config_g->bg_running = 0;
	pthread_exit(NULL);
	return NULL;
}

static int ssh_plugin_init(void)
{
	int ret;
	pthread_t tid;
	struct ssh_configs *ssh_config_g;

	pthread_mutex_init(&ssh_lock, NULL);
	pthread_cond_init(&cond_t, NULL);
	if (!ssh_config_gs)
		return -EINVAL;
	ssh_config_g = (struct ssh_configs *)
			lustre_get_private_data(ssh_config_gs);
	if (!ssh_config_g->server_host || !ssh_config_g->user_name
	    || !ssh_config_g->known_hosts) {
		LERROR("ssh plugin: server_host,server name or knownhosts configs are missing");
		return -EINVAL;
	}
	if (!ssh_config_g->public_keyfile &&
	    ssh_config_g->private_keyfile) {
		LERROR("ssh plugin: keyfiles need to be given in pair, or both missing");
		return -EINVAL;
	}
	if (ssh_config_g->public_keyfile &&
	    !ssh_config_g->private_keyfile) {
		LERROR("ssh plugin: keyfiles need to be set in pair, or both missing");
		return -EINVAL;
	}
	if (!ssh_config_g->public_keyfile && !ssh_config_g->private_keyfile
	    && !ssh_config_g->user_password) {
		LERROR("ssh plugin: both password and keyfiles are missing");
		return -EINVAL;
	}
	/* create thread that run in the background */
	ret = pthread_create(&tid, NULL, ssh_connection_thread, NULL);
	if (ret < 0) {
		LERROR("ssh plugin: failed to create thread, %s",
			strerror(errno));
		return -errno;
	}
	pthread_mutex_lock(&ssh_lock);
	pthread_cond_wait(&cond_t, &ssh_lock);
	pthread_mutex_unlock(&ssh_lock);
	if (!ssh_config_g->bg_running) {
		LERROR("ssh plugin: background thread have been terminated");
		return -1;
	}
	ret = pthread_detach(tid);
	if (ret < 0) {
		LERROR("ssh plugin: failed to pthread_detach, %s",
			strerror(errno));
		pthread_kill(tid, SIGKILL);
		return -1;
	}
	ssh_config_g->bg_tid = tid;
	return 0;
}

static int ssh_read_file(const char *path, char **buf, ssize_t *data_size)
{
	int ret;
	zmq_msg_t request;
	zmq_msg_t reply;
	char *receive_buf = NULL;
	int receive_buf_len = DEFAULT_RECV_BUFSIZE;
	char cmd[SSH_MAX_COMMAND_SIZE];
	struct ssh_configs *ssh_config_g = (struct ssh_configs *)
			lustre_get_private_data(ssh_config_gs);
	if (!ssh_config_g->bg_running) {
		LERROR("ssh plugin: background thread have been terminated");
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
	ret = zmq_msg_send(&request, ssh_config_g->requester, 0);
#else
	ret = zmq_send(ssh_config_g->requester, &request, 0);
#endif
	if (ret < 0) {
		LERROR("ssh plugin: failed to send msg, %s",
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
	ret = zmq_msg_recv_once(&reply, ssh_config_g->requester, 0,
				&receive_buf, &receive_buf_len);
	if (ret < 0) {
		LERROR("ssh plugin: failed to receive msg, %s",
			strerror(errno));
		return ret;
	}
	/* Step4 Filter results */
	if (!strncmp(receive_buf, ERROR_FORMAT, strlen(ERROR_FORMAT))) {
		LERROR("ssh plugin: %s", receive_buf);
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

static int ssh_read(void)
{
	struct list_head path_head;

	if (ssh_config_gs == NULL) {
		LERROR("ssh plugin is not configured properly");
		return -1;
	}

	if (!ssh_config_gs->lc_definition.ld_root->le_active) {
		LERROR("ssh plugin: root entry of ssh plugin is not activated");
		return 0;
	}

	ssh_config_gs->lc_definition.ld_query_times++;
	INIT_LIST_HEAD(&path_head);
	return lustre_entry_read(ssh_config_gs->lc_definition.ld_root, "/",
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

static int check_zeromq_port(const char *zeromq_port)
{
	unsigned long value;
	char *ptr_parse_end = NULL;

	value = strtoul(zeromq_port, &ptr_parse_end, 0);
	if (ptr_parse_end && *ptr_parse_end != '\0') {
		LERROR("ssh plugin: %s is not a vaild numeric value",
			zeromq_port);
		return -EINVAL;
	}
	/*
	 * if we pass a negative number to strtoull, it will return an
	 * unexpected number to us, so let's do the check ourselves.
	 */
	if (zeromq_port[0] == '-') {
		LERROR("ssh plugin: %s: negative value is invalid",
			zeromq_port);
		return -EINVAL;
	}
	if (value < 1 || value >= 65536) {
		LERROR("ssh plugin: %lu is out of range [1, 65535]", value);
		return -ERANGE;
	}
	return 0;
}

static int ssh_config_init(struct lustre_configs *lc)
{
	void *result;

	result = calloc(1, sizeof(struct ssh_configs));
	if (!result)
		return -ENOMEM;
	lc->lc_definition.ld_private_definition.ld_private_data = result;
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
	if (!he)
		return -h_errno;
	memcpy(&ip_addr, he->h_addr_list[0], 4);
	inet_ntop(AF_INET, &ip_addr,
		  IP, MAX_IP_ADDRESS_LENGTH);
	*ip = IP;
	return 0;
}

static int ssh_config_private(oconfig_item_t *ci,
			      struct lustre_configs *conf)
{
	int ret = 0;
	char *value = NULL;
	struct ssh_configs *ssh_configs = (struct ssh_configs *)
					lustre_get_private_data(conf);

	ret = lustre_config_get_string(ci, &value);
	if (ret) {
		LERROR("ssh plugin: failed to get string");
		return ret;
	}
	if (strcasecmp("ServerHost", ci->key) == 0) {
		free(ssh_configs->server_host);
		ret = check_server_host(value);
		if (!ret)
			ret = host2ip(value, &ssh_configs->server_host);
		/*
		 * we don't free @value in error here, let it
		 * be handled by ssh_config_fini(), otherwise
		 * we need assign null to avoid double free in
		 * ssh_config_fini().
		 */
		if (ret) {
			ssh_configs->server_host = value;
			LERROR("ssh plugin: invalid server host");
		} else {
			free(value);
		}
	} else if (strcasecmp("UserName", ci->key) == 0) {
		free(ssh_configs->user_name);
		ssh_configs->user_name = value;
	} else if (strcasecmp("KnownhostsFile", ci->key) == 0) {
		free(ssh_configs->known_hosts);
		ssh_configs->known_hosts = value;
		ret = check_config_path(value);
	} else if (strcasecmp("PublicKeyfile", ci->key) == 0) {
		free(ssh_configs->public_keyfile);
		ret = check_config_path(value);
		ssh_configs->public_keyfile = value;
	} else if (strcasecmp("PrivateKeyfile", ci->key) == 0) {
		free(ssh_configs->private_keyfile);
		ssh_configs->private_keyfile = value;
		ret = check_config_path(value);
	} else if (strcasecmp("UserPassword", ci->key) == 0) {
		free(ssh_configs->user_password);
		ssh_configs->user_password = value;
	} else if (strcasecmp("SshKeyPassphrase", ci->key) == 0) {
		free(ssh_configs->sshkey_passphrase);
		ssh_configs->sshkey_passphrase = value;
	} else if (strcasecmp("ZeromqPort", ci->key) == 0) {
		free(ssh_configs->zeromq_port);
		ret = check_zeromq_port(value);
		ssh_configs->zeromq_port = value;
	} else {
		free(value);
		LERROR("ssh plugin: Common, The \"%s\" key is not allowed"
				"and will be ignored.", ci->key);
	}
	return ret;

}

static void ssh_config_fini(struct lustre_configs *lc)
{
	struct ssh_configs *ssh_configs = (struct ssh_configs *)
				lustre_get_private_data(lc);
	if (!ssh_configs)
		return;
	exit_client_zmq_connection(ssh_configs);
	if (ssh_configs->bg_tid && ssh_configs->bg_running)
		pthread_kill(ssh_configs->bg_tid, SIGKILL);
	free(ssh_configs->server_host);
	free(ssh_configs->user_name);
	free(ssh_configs->public_keyfile);
	free(ssh_configs->private_keyfile);
	free(ssh_configs->known_hosts);
	free(ssh_configs->user_password);
	free(ssh_configs->sshkey_passphrase);
	free(ssh_configs->zeromq_port);
}

static int ssh_config_internal(oconfig_item_t *ci)
{
	struct lustre_private_definition ld_private_definition;

	ld_private_definition.ld_private_init = ssh_config_init;
	ld_private_definition.ld_private_config = ssh_config_private;
	ld_private_definition.ld_private_fini = ssh_config_fini;
	ssh_config_gs = lustre_config(ci, &ld_private_definition);
	if (ssh_config_gs == NULL) {
		LERROR("ssh plugin: failed to configure ssh");
		return -EINVAL;
	}

	ssh_config_gs->lc_definition.ld_read_file = ssh_read_file;
	return 1;
}

void module_register(void)
{
	plugin_register_complex_config("ssh", ssh_config_internal);
	plugin_register_init("ssh", ssh_plugin_init);
	plugin_register_read("ssh", ssh_read);
} /* void module_register */
