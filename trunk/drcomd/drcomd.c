#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "drcomd.h"
#include "client_daemon.h"
#include "log.h"

#define DRCOM_VERSION	"1.4.0"

int status = 0;
int sigusr1_pipe[2] = {-1,-1};
pthread_t th_watchport = 0, th_keepalive = 0;

static void usage(void)
{
	puts("drcomd, daemon part of the drcomc-drcomcd client-daemon programs\n\n"
		 "	usage: drcomd [ -n | --nodaemon ]\n");

	exit(EXIT_FAILURE);
}

static void daemonize(void)
{
	pid_t pid, sid;
	int fd;

	pid = fork();
	if(pid > 0)
		exit(0);
	if(pid < 0){
		logerr("fork of daemon failed: %s", strerror(errno));
		exit(-1);
	}

	fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		if (fd != STDIN_FILENO)
			dup2(fd, STDIN_FILENO);
		if (fd != STDOUT_FILENO)
			dup2(fd, STDOUT_FILENO);
		if (fd != STDERR_FILENO)
			dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
	if (fd < 0)
		logerr("fatal, could not open /dev/null: %s", strerror(errno));

	chdir("/");
	umask(022);

	/* become session leader */
	sid = setsid();
	dbg("our session is %d", sid);
}

static void load_kernel_module(void)
{
/*
	int r;
	char s[50];

	strcpy(s, "/sbin/kextload drcom.kext");
	r = system(s);
	if (r) {
		fprintf(stderr, "drcomd: Error loading drcom module\n");
		exit(EXIT_FAILURE);
	}
 */
}

static void do_one_client(int s, struct drcom_handle *h)
{
	struct drcomcd_hdr cd_hdr;
	int s2;
	fd_set	rfds;
	struct timeval t;
	int r;

	s2 = accept(s, NULL, NULL);
	if (s2 == -1 && errno != EINTR) {
		logerr("daemon: accept failed: %s", strerror(errno));
		return;
	}

	FD_ZERO(&rfds);
	FD_SET(s2, &rfds);
	t.tv_sec = 2;
	t.tv_usec = 0;
	r = select(s2+1, &rfds, NULL, NULL, &t);
	if(r<=0){
		logerr("accepted, but no data\n");
		goto error;
	}

	if(!FD_ISSET(s2, &rfds)){
		goto error;
	}

	r = safe_recv(s2, &cd_hdr, sizeof(struct drcomcd_hdr));
	if (r != sizeof(struct drcomcd_hdr)){
		logerr("daemon: recv: %s", strerror(errno));
		goto error;
	}
	if (cd_hdr.signature != DRCOM_SIGNATURE) {
		logerr("Unknown signature\n");
		goto error;
	}

	switch (cd_hdr.type) {
	case DRCOMCD_LOGIN:
		do_command_login(s2, h);
		break;
	case DRCOMCD_LOGOUT:
		do_command_logout(s2, h);
		break;
	case DRCOMCD_PASSWD:
		do_command_passwd(s2, h);
		break;
	default:
		break;
	}

error:
	close(s2);
	return;
}
 
static int init_daemon_socket(void)
{
	int s, r;
	struct sockaddr_un un_daemon;

	memset(&un_daemon, 0x00, sizeof(struct sockaddr_un));
	un_daemon.sun_family = AF_UNIX;
	/* use abstract namespace */
	strncpy(&un_daemon.sun_path[1], DRCOMCD_SOCK, sizeof(un_daemon.sun_path)-1);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s == -1) {
		logerr("drcomd: Socket creation failed: %s\n", strerror(errno));
		return -1;
	}
	/* this ensures only one copy running */
	r = bind(s, (struct sockaddr *) &un_daemon, sizeof(un_daemon));
	if (r) {
		logerr("drcomd: Bind failed: %s\n", strerror(errno));
		return -1;
	}
	r = listen(s, 1);
	if (r) {
		logerr("drcomd: Listen failed: %s\n", strerror(errno));
		return -1;
	}

	return s;
}

static void drcomd_daemon(struct drcom_handle *h)
{
	int s;
	int r;

	s = init_daemon_socket();
	if(s < 0)
		exit(-1);

	if(setup_sig_handlers()<0){
		logerr("sig handlers not setup, exit.\n");
		exit(1);
	}

	loginfo("drcomd %s started.\n", DRCOM_VERSION);

	while (1) {
		int maxfd;
		fd_set readfds;

		FD_ZERO(&readfds);
		FD_SET(s, &readfds);
		FD_SET(sigusr1_pipe[READ_END], &readfds);
		
		maxfd = s;
		if(maxfd < sigusr1_pipe[READ_END])
			maxfd = sigusr1_pipe[READ_END];

		unblock_sigusr1();
		r = select(maxfd+1, &readfds, NULL,NULL, NULL);
		if(r<0){
			if(errno != EINTR)
				logerr("signal caught\n");
			continue;
		}
		if(FD_ISSET(sigusr1_pipe[READ_END], &readfds)){
			char buf[256];
			int *sig = (int*)buf;

			read(sigusr1_pipe[READ_END], &buf, sizeof(buf));
			do_signals(h, *sig);
		}
		if(!FD_ISSET(s, &readfds))
			continue;

		block_sigusr1();
		do_one_client(s, h);
	}

	/* FIXME: 
	 * drcom_clean_up();
	 * drcom_destroy_handle();
	 * close_daemon_socket(); 
	 */
}

int main(int argc, char **argv)
{
	struct drcom_handle *h;
	int daemon = 1;
	int i;

	if(argc > 2)
		usage();

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];
		if (strcmp(arg, "--nodaemon") == 0 || strcmp(arg, "-n") == 0) {
			printf("%s: log to stderr.\n", argv[0]);
			daemon = 0;
		}
	}

	/* Initialize the handle for the lifetime of the daemon */
	h = drcom_create_handle();
	if(drcom_init(h)<0){
		logerr("conf file err\n");
		exit(-1);
	}

	load_kernel_module();

	if (daemon)
		daemonize();

	logging_init("drcomd", daemon);

	drcomd_daemon(h);

	logging_close();

	return 0;
}

