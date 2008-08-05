#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "client_daemon.h"
#include "utils.h"

#define logerr printf
#define loginfo printf

static void usage(void)
{
	puts("usage: \n");
	puts("  drcomc { login | logout | passwd \"newpasswd\" }\n");
}

static int send_command(int s, uint16_t command, void *ptr)
{
	struct drcomcd_hdr cd_hdr;
	struct drcomcd_login cd_login;
	struct drcomcd_logout cd_logout;
	struct drcomcd_passwd cd_passwd;
	void *data;
	int data_len;
	char *passwd;
	unsigned int passwd_len;
	ssize_t r;

	switch(command){
	case DRCOMCD_LOGIN:
		cd_login.authenticate = 1;
		cd_login.timeout = -1;
		data = &cd_login;
		data_len = sizeof(struct drcomcd_login);
		break;
	case DRCOMCD_LOGOUT:
		cd_logout.timeout = -1;
		data = &cd_logout;
		data_len = sizeof(struct drcomcd_logout);
		break;

	case DRCOMCD_PASSWD:
		passwd = (char*)ptr;
		passwd_len = strlen(passwd);

		if(passwd_len > sizeof(cd_passwd.newpasswd)){
			logerr("New Passwd too long");
			return -1;
		}

		memset(cd_passwd.newpasswd, 0, sizeof(cd_passwd.newpasswd));
		strncpy(cd_passwd.newpasswd, passwd, passwd_len);
		cd_passwd.timeout = -1;
		data = &cd_passwd;
		data_len = sizeof(struct drcomcd_passwd);
		break;

	default:
		logerr("wrong command");
		return -1;
	}

	cd_hdr.signature = DRCOM_SIGNATURE;
	cd_hdr.type = command;

	r = safe_send(s, &cd_hdr, sizeof(struct drcomcd_hdr));
	if (r != sizeof(struct drcomcd_hdr)) 
		return -1;

	r = safe_send(s, data, data_len);
	if (r != data_len) 
		return -1;

	return 0;
}

static int recv_acknowledge(int s)
{
	struct drcomcd_hdr dc_hdr;
	ssize_t r;
	char *buf;

	do {
		r = safe_recv(s, &dc_hdr, sizeof(struct drcomcd_hdr));
		if (r != sizeof(struct drcomcd_hdr))
			return -1;

		if (dc_hdr.signature != DRCOM_SIGNATURE){
			logerr("signature error");
			return -1;
		}
		
		if(dc_hdr.msg_len == 0)
			continue;

		buf = (char*)malloc(dc_hdr.msg_len);
		if(buf == NULL){
			logerr("malloc failed");
			return -1;
		}

		r = safe_recv(s, buf, dc_hdr.msg_len);
		if(r != dc_hdr.msg_len){
			logerr("mismatch acknowledge len");
			return -1;
		}

		buf[dc_hdr.msg_len] = '\0';

		loginfo(buf);

		free(buf);
	} while (!dc_hdr.is_end);

	/* the last header matters */
	if(dc_hdr.type != DRCOMCD_SUCCESS)
		return -1;

	return 0;
}

static int init_socket(void)
{
	int s, r;
	struct sockaddr_un un_daemon;

	memset(&un_daemon, 0x00, sizeof(struct sockaddr_un));
	un_daemon.sun_family = AF_UNIX;
	/* abstract namespace */
	strncpy(&un_daemon.sun_path[1], DRCOMCD_SOCK, sizeof(un_daemon.sun_path)-1);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s == -1) {
		perror("drcomc: Socket creation");
		return -1;
	}

	r = connect(s, (struct sockaddr *) &un_daemon, sizeof(un_daemon));
	if (r) {
		perror("drcomc: Connect");
		return -1;
	}

	return s;
}

int main(int argc, char **argv)
{
	int s;
	uint16_t command;
	char *p = NULL;
	int r;

	if (argc < 2 || argc > 3)
		usage();

	if (!strcmp("login", argv[1]) && argc == 2){
		command = DRCOMCD_LOGIN;
	}else if (!strcmp("logout", argv[1]) && argc == 2){
		command = DRCOMCD_LOGOUT;
	}else if (!strcmp("passwd", argv[1]) && argc == 3){
		command = DRCOMCD_PASSWD;
		p = argv[2];
	}else{
		usage();
		exit(1);
	}

	s = init_socket();
	if (s < 0) 
		exit(1);

	r = send_command(s, command, p);
	if(r != 0)
		goto error_exit;

	printf("\n");
	r = recv_acknowledge(s);
	printf("\n");
	
error_exit:
	close(s);

	return r;
}

