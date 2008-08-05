#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

int main()
{
	int retval;
    int server_fd;
    struct sockaddr_in server_addr;    

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9988);
    inet_pton(AF_INET, "142.150.238.15", &server_addr.sin_addr);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0)
	{
		printf("socket(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
    retval = bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (retval < 0)
	{
		printf("bind(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
    retval = listen(server_fd, 0);
	if (retval < 0)
	{
		printf("listen(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
    while (1)
    {
		int client_fd;
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);

        client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &addr_len);
		if (client_fd < 0)
		{
			printf("accept(): %s, errno = %d\n", strerror(errno), errno);
			break;
		}
		printf("conneted.\n");
		char buf[40];
		while (1)
		{
			retval = recv(client_fd, buf, sizeof(buf) - 1, 0);
			if (retval == 0)
			{
				break;
			}
			else if (retval < 0)
			{
				printf("recv() %s, errno = %d\n", strerror(errno), errno);
				break;
			}					
			buf[retval] = 0;			
			printf("data: %s\n", buf);				
		}
		printf("disconneted.\n");
		close(client_fd);
    }
	
	retval = close(server_fd);
	if (retval < 0)
	{
		printf("close(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
    return  0;
}
