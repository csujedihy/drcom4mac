#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <signal.h>

#include "drcom.h"

void signal_func(int signum)
{
	printf("SIGUSR1 signal is received.\n");
}

int main()
{
	int retval;
    int server_fd, control_fd;
    struct sockaddr_in server_addr;   

	signal(SIGUSR1, signal_func);

	control_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (control_fd < 0)
	{
		printf("socket(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	
	size_t buflen = sizeof(struct drcom_set_params_opt) + sizeof(struct exclude_entry);
	char * buf = malloc(buflen);
	struct drcom_set_params_opt * params_opt_ptr = (struct drcom_set_params_opt *) buf;
	params_opt_ptr->exclude_count = 1;
	inet_pton(AF_INET, "142.150.238.15", &(params_opt_ptr->exclude_list[0].addr));
	inet_pton(AF_INET, "255.255.255.255", &(params_opt_ptr->exclude_list[0].mask));	
	retval = setsockopt(control_fd, IPPROTO_UDP, DRCOM_SO_SET_PARAMS, buf, buflen);
//	if (retval < 0 && errno != 42)
//	{
//		free(buf);
//		printf("setsockopt(DRCOM_SO_SET_PARAMS): %s, errno = %d\n", strerror(errno), errno);
//		close(control_fd);
//		return -1;
//	}	
	free(buf);
		
	struct drcom_set_auth_opt auth_opt;
	auth_opt.cmd = DRCOM_AUTH_MODE_ON;
	auth_opt.pid = getpid();
	auth_opt.autologout = true;
	memset(auth_opt.auth_data, 'A', DRCOM_AUTH_DATA_LEN);
	
	retval = setsockopt(control_fd, IPPROTO_UDP, DRCOM_SO_SET_AUTH, &auth_opt, sizeof(auth_opt));
//	if (retval < 0 && errno != 42)
//	{
//		printf("setsockopt(DRCOM_SO_SET_AUTH): %s, errno = %d\n", strerror(errno), errno);
//		close(control_fd);
//		return -1;
//	}
	
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9988);
    inet_pton(AF_INET, "142.150.238.15", &server_addr.sin_addr);
//	printf("ntohl = %lu\n", ntohl(server_addr.sin_addr.s_addr));

	server_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (server_fd < 0)
	{
		printf("socket(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
		
    retval = connect(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (retval < 0)
	{
		printf("connect(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	int i;
    for (i = 0; i < 5; i++)
    {		
		char buf[40];
		snprintf(buf, sizeof(buf), "This is package %d. ", i+1);
		retval = send(server_fd, buf, strlen(buf), 0);
		if (retval < 0)
		{
			printf("send() %s, errno = %d\n", strerror(errno), errno);
			break;
		}		
		sleep(1);
    }
	
	sleep(10);

	retval = shutdown(server_fd, SHUT_RDWR);
	if (retval < 0)
	{
		printf("shutdown(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
    retval = close(server_fd);
	if (retval < 0)
	{
		printf("close(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	auth_opt.cmd = DRCOM_AUTH_MODE_OFF;
	auth_opt.pid = 0;
	auth_opt.autologout = false;
	memset(auth_opt.auth_data, 0, 16);

	retval = setsockopt(control_fd, IPPROTO_UDP, DRCOM_SO_SET_AUTH, &auth_opt, sizeof(auth_opt));
//	if (retval < 0 && errno != 42)
//	{
//		printf("setsockopt(DRCOM_SO_SET_AUTH): %s, errno = %d\n", strerror(errno), errno);
//		close(control_fd);
//		return -1;
//	}
	close(control_fd);	
	
    return  0;
}
