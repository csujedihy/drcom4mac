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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "drcomd.h"
#include "daemon_server.h"
#include "client_daemon.h"

#include "log.h"

struct drcom_handle *drcom_create_handle(void)
{
	struct drcom_handle *h;

	/*FIXME: check malloc failure */
	h = (struct drcom_handle *) malloc(sizeof(struct drcom_handle));
	h->conf = (struct drcom_conf *) malloc(sizeof(struct drcom_conf));
	h->socks = (struct drcom_socks *) malloc(sizeof(struct drcom_socks));
	h->info = (struct drcom_info *) malloc(sizeof(struct drcom_info));
	h->session = (struct drcom_session_info *) malloc(sizeof(struct drcom_session_info));
	h->host = (struct drcom_host *) malloc(sizeof(struct drcom_host));
	h->auth = (struct drcom_auth *) malloc(sizeof(struct drcom_auth));
	h->keepalive = (struct drcom_host_msg *) malloc(sizeof(struct drcom_host_msg));
	h->response = (struct drcom_host_msg *) malloc(sizeof(struct drcom_host_msg));

	return h;
}

int drcom_destroy_handle(struct drcom_handle *h)
{
	/* FIXME: check NULL pointer */
	if (h->conf && h->conf->except != NULL)
		free(h->conf->except);
	free(h->conf);
	free(h->socks);
	free(h->info);
	free(h->session);
	free(h->host);
	free(h->auth);
	free(h->keepalive);
	free(h->response);
	free(h);

	return 0;
}

struct drcom_session_info *drcom_get_session_info(struct drcom_handle *h)
{
	struct drcom_session_info *s = h->session;

	memcpy(s->auth, h->auth, sizeof(struct drcom_auth));
	s->hostip = h->info->hostip;
	s->servip = h->info->servip;
	s->hostport = h->info->hostport;
	s->servport = h->info->servport;
	s->dnsp = h->host->dnsp;
	s->dnss = h->host->dnss;

	return s;
}

int drcom_init(struct drcom_handle *h)
{
	struct drcom_conf *conf = (struct drcom_conf *) h->conf;
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;
	struct drcom_info *info = (struct drcom_info *) h->info;
	struct drcom_host *host = (struct drcom_host *) h->host;
	int r;

	/* Read config file and actually initialize host and info
		 with the config data */
	r = _readconf(conf, info, host);
	if (r)
		return r;

	/* Initialize sockets */

	socks->hostaddr_in.sin_family = AF_INET;
	socks->hostaddr_in.sin_port = htons(info->hostport);
	socks->hostaddr_in.sin_addr.s_addr = info->hostip;
	memset(socks->hostaddr_in.sin_zero, 0, sizeof(socks->hostaddr_in.sin_zero));

	socks->servaddr_in.sin_family = AF_INET;
	socks->servaddr_in.sin_port = htons(info->servport);
	socks->servaddr_in.sin_addr.s_addr = info->servip;
	memset(socks->servaddr_in.sin_zero, 0, sizeof(socks->servaddr_in.sin_zero));

	return 0;
}

int server_sock_init(struct drcom_handle *h)
{
	int r;
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;

	socks->sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (socks->sockfd == -1)
		return -1;

	{
	int on = 1;
	r = setsockopt(socks->sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
	if( r < 0 )
		return -1;
	}

	r = bind(socks->sockfd, 
			(struct sockaddr *)&socks->hostaddr_in, sizeof(struct sockaddr));
	if (r == -1)
		return -1;

	return 0;
}

void server_sock_destroy(struct drcom_handle *h)
{
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;

	if(socks->sockfd >= 0)
		close(socks->sockfd);
	socks->sockfd = -1;
}

void report_daemon_msg(int s2, const char *format, ...)
{
	va_list args;
	struct drcomcd_hdr dc_hdr;
	char msg[1024];
	int len;
	int r;

	if(s2 == -1)
		return;

	va_start(args, format);
	vsnprintf(msg, 1024, format, args);
	va_end(args);

	msg[1023] = '\0';
	len = strlen(msg)+1; /* include the last '\0' */

	memset(&dc_hdr, 0, sizeof(struct drcomcd_hdr));
	dc_hdr.signature = DRCOM_SIGNATURE;
	dc_hdr.type = DRCOMCD_MSG;
	dc_hdr.msg_len = len;
	dc_hdr.is_end = 0;

	/* header */
	r = safe_send(s2, &dc_hdr, sizeof(struct drcomcd_hdr));
	if (r != sizeof(struct drcomcd_hdr)){
		logerr("daemon: send: %s", strerror(errno));
		return;
	}

	/* message */
	r = safe_send(s2, msg, len);
	if (r != len){
		logerr("daemon: send: %s", strerror(errno));
		return;
	}
}


int report_server_msg(struct drcom_handle *h, char *msg, size_t len)
{
	struct msg_item *m;

	m = (struct msg_item*)malloc(sizeof(struct msg_item));
	if(m == NULL)
		return -1;

	memset(m, 0, sizeof(struct msg_item));

	m->msg = (unsigned char*)malloc(len);
	if(m->msg == NULL)
		goto err;

	m->msg_len = len;
	memcpy(m->msg, msg, len);

	m->next = h->msg_head;
	h->msg_head = m;

err:
	free(m);
	return -1;
}

void report_final_result(int s2, struct drcom_handle *h, int result)
{
	struct drcomcd_hdr dc_hdr;
	struct msg_item *msg;
	ssize_t r;

	memset(&dc_hdr, 0, sizeof(struct drcomcd_hdr));
	dc_hdr.signature = DRCOM_SIGNATURE;
	dc_hdr.type = DRCOMCD_MSG;

	while(h->msg_head != NULL){
		msg = h->msg_head;
		h->msg_head = msg->next;

		dc_hdr.is_end = 0;
		dc_hdr.msg_len = msg->msg_len;

		/* header */
		r = safe_send(s2, &dc_hdr, sizeof(struct drcomcd_hdr));
		if (r != sizeof(struct drcomcd_hdr)){
			logerr("daemon: send: %s", strerror(errno));
			return;
		}

		/* message */
		r = safe_send(s2, &msg->msg, msg->msg_len);
		if (r != msg->msg_len){
			logerr("daemon: send: %s", strerror(errno));
			return;
		}

		free(msg->msg);
		free(msg);
	}

	dc_hdr.type = result;
	dc_hdr.is_end = 1;
	dc_hdr.msg_len = 0;

	r = safe_send(s2, &dc_hdr, sizeof(struct drcomcd_hdr));
	if (r != sizeof(struct drcomcd_hdr)){
		logerr("daemon: send: %s", strerror(errno));
		return;
	}
}

