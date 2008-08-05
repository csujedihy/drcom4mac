#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if.h>
#include <linux/sockios.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <net/if.h>
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

ssize_t safe_send(int s, const void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t n = len;
	ssize_t r;

	while(n > 0){
		r = send(s, p, n, 0);
		if(r == -1){
			if(errno == EAGAIN || errno == EINTR){
				/*
				 * are we sure no bytes had been sent?
				 * if not, we may need return -1 directly 
				 */
				continue;
			} else
				return -1;
		}

		n -= r;
		p += r;
	}

	return p - (char *)buf;
}

ssize_t safe_recv(int fd, void *buff, size_t size)
{
	char *p = buff;
	fd_set readfds;
	int n, copied = 0;
	struct timeval t;

	/*
	 *  linux modifies t when returning from select(), 
	 *  which is what we want. so we place this here 
	 */
	t.tv_sec = 30;
	t.tv_usec =0;

	while(size > 0){
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		n = select(fd+1, &readfds, NULL, NULL, &t);
		if(n < 0){
			if(errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if(n == 0)
			return 0;
		if(FD_ISSET(fd, &readfds)){
			n = recv(fd, p, size, 0);
			if(n<=0)
				return n;
			copied += n;
			size -= n;
			p += n;
		}
	}

	return copied;
}

int get_interface_ipaddr(char *name, u_int32_t *addr)
{
        int r;
	int s;
        struct ifreq ifr;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s<0){
		return s;
	}

        strncpy(ifr.ifr_name, name, IFNAMSIZ);
        r = ioctl(s, SIOCGIFADDR, &ifr);
        if (r != 0) {
                r = errno;
                goto err;
        }

        *addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

err:
        close(s);
        return r;
}

