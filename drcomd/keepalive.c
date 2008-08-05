/*
	libdrcom - Library for communicating with DrCOM 2133 Broadband Access Server
	Copyright (C) 2005 William Poetra Yoga Hadisoeseno <williampoetra@yahoo.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA	02111-1307	USA
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "drcomd.h"
#include "daemon_server.h"
#include "log.h"

static int drcom_keepalive(struct drcom_handle *h)
{
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;
	struct drcom_host_msg *host_msg = (struct drcom_host_msg *) h->keepalive;
	struct sockaddr_in servaddr_in;
	int r;

	memcpy(&servaddr_in, &socks->servaddr_in, sizeof(servaddr_in));

	while (1)
	{
		r = sendto(socks->sockfd, host_msg, sizeof(struct drcom_host_msg), 0,
			(struct sockaddr *) &servaddr_in,
			sizeof(struct sockaddr));
		if (r != sizeof(struct drcom_host_msg))
			goto err;

		sleep(10);
	}

err:
	logerr("keepalive: %s", strerror(errno));
	return -1;
}

void *daemon_keepalive(void *arg)
{
	block_sigusr1();
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	drcom_keepalive((struct drcom_handle *) arg);
	loginfo("keepalive returns\n");
	return NULL;
}

