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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>

#include "md5.h"

#include "drcomd.h"
#include "daemon_server.h"
#include "log.h"

static uint16_t _prepare_folded(struct drcom_info *info, struct drcom_host_msg *keepalive_skel)
{
	unsigned char buf[16 + 16], digest[16];
	int password_len, i;
	uint16_t folded;

	password_len = strlen(info->password);

	memcpy(digest, keepalive_skel->msg, 16);

	memcpy(buf, digest, 16);
	strncpy((char *) (buf + 16), info->password, 16);

	MD5(buf, 16 + password_len, digest);

	folded = 0;
	for (i = 0; i < 16; i += 2)
		folded += *((uint16_t *) (digest + i));

	return folded;
}

static int _respond(struct drcom_socks *socks, uint16_t folded, 
		struct drcom_host_msg *keepalive_skel, uint8_t *question)
{
	struct drcom_host_msg ans, *answer = &ans;
	struct sockaddr_in servaddr_in;
	unsigned char digest[16];
	uint16_t x;
	int r;

	memcpy(answer, keepalive_skel, sizeof(*answer));
	memcpy(&servaddr_in, &socks->servaddr_in, sizeof(servaddr_in));

	x = folded ^ *((uint16_t *) question);

	answer->msg[0] = (x & 0x00ff) + ((x & 0xff00) >> 1);

	answer->msg[1] = 0x01;

	answer->msg[2] = 0x14;
	answer->msg[3] = 0x00;
	answer->msg[4] = 0x07;
	answer->msg[5] = 0x0b;
	answer->msg[6] = question[0];
	answer->msg[7] = question[1];
	MD5((unsigned char *) answer, 1 + 1 + 1 + 4 + 2, digest);
	memcpy(answer->msg + 2, digest, 16);

	answer->msg[18] = 0xff;

	r = sendto(socks->sockfd, answer, sizeof(*answer), 0,
			 (struct sockaddr *) &servaddr_in,
			 sizeof(struct sockaddr));
	if (r != sizeof(*answer))
		return -1; /* error */

	return 0;
}

static int drcom_watchport(struct drcom_handle *h)
{
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;
	struct drcom_info *info = (struct drcom_info *) h->info;
	struct drcom_host_msg *keepalive_skel = (struct drcom_host_msg *) h->response;
	struct drcom_serv_msg s_msg, *serv_msg = &s_msg;
	uint16_t folded;
	int r;
	struct sockaddr_in servaddr_in;
	socklen_t fromlen;

	if(serv_msg == NULL)
		goto err;

	folded = _prepare_folded(info, keepalive_skel);

	memcpy(&servaddr_in, &socks->servaddr_in, sizeof(servaddr_in));
	fromlen = sizeof(servaddr_in);

	while (1) {
		/* cleanup the buffer first */
		memset(serv_msg, 0, sizeof(struct drcom_serv_msg));
		r = recvfrom(socks->sockfd, serv_msg, sizeof(struct drcom_serv_msg), 0,
				 (struct sockaddr *) &servaddr_in, &fromlen);
		if (r < 0)
		{
			logerr("watchport: recvfrom: %s", strerror(errno));
			goto err;
		}
		else if (r == 0)
		{
			loginfo("watchport: received nothing\n");
			continue; /* ignore r == 0 cases for now */
		}

		if (serv_msg->m != 'M')
		{
			loginfo("Unknown server packet(serv_msg->m==%u)\n", serv_msg->m);
			continue;
		}

		switch (serv_msg->mt)
		{
			case '8': 
				loginfo((char *) serv_msg->msg); 
				break;
			case '&': 
				r = _respond(socks, folded, keepalive_skel, serv_msg->msg);
				if (r < 0)
					goto err;
				break;
			default: 
				loginfo("Unknown message type.\n"); 
				break;
		}
	}

err:
	return -1;
}

void *daemon_watchport(void *arg)
{
	block_sigusr1();
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	drcom_watchport((struct drcom_handle *) arg);
	loginfo("watchport returns\n");
	return NULL;
}

