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
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>

#include "md5.h"

#include "drcomd.h"
#include "daemon_server.h"
#include "client_daemon.h"
#include "log.h"

static void _build_login_packet(struct drcom_login_packet *login_packet, 
			struct drcom_info *info, struct drcom_host *host, 
			struct drcom_challenge *challenge)
{
	char s[25];
	unsigned char t[22], d[16];
	int i, passwd_len;

	/* header */
	login_packet->host_header.pkt_type = PKT_LOGIN;
	login_packet->host_header.zero = 0;
	login_packet->host_header.len = strlen(info->username) + 
			sizeof(struct drcom_host_header);
	memset(t, 0, 22);
	memcpy(t, &login_packet->host_header.pkt_type, 2);
	memcpy(t + 2, &challenge->challenge, 4);
	passwd_len = strlen(info->password);
	strncpy((char *) (t + 6), info->password, 16);
	MD5((unsigned char *) t, passwd_len + 6, d);
	memcpy(login_packet->host_header.checksum, d, 16);

	/* username */
	memset(login_packet->username, 0, 36);
	strncpy(login_packet->username, info->username, 36);

	/* unknown, maybe just a signature? */
	login_packet->unknown0 = 0x18;

	/* mac */
	login_packet->mac_code = 1;
	memcpy(login_packet->mac_xor, info->mac, 6);
	for (i = 0; i < 6; ++i)
		login_packet->mac_xor[i] ^= login_packet->host_header.checksum[i];

	/* ok, first checksum */
	/* l already calculated */
	/* l = strlen(info->password); */
	s[0] = 0x01;
	memcpy(s + 1, info->password, passwd_len);
	memcpy(s + 1 + passwd_len, &challenge->challenge, 4);
	memset(s + 1 + passwd_len + 4, 0, 4);
	MD5((unsigned char *) s, 1 + passwd_len + 4 + 4, d);
	memcpy(login_packet->checksum1, d, 16);

	/* nic */
	login_packet->num_nic = 1;
	memcpy(login_packet->nic, info->nic, 16);

	/* second checksum */
	login_packet->checksum2_half[0] = 0x14;
	login_packet->checksum2_half[1] = 0x00;
	login_packet->checksum2_half[2] = 0x07;
	login_packet->checksum2_half[3] = 0x0b;
	MD5((unsigned char *) login_packet, 0x65, d);
	memcpy(login_packet->checksum2_half, d, 8);

	/* we've got a dog */
	login_packet->dog = 1;

	/* host info */
	memset(login_packet->zero1, 0, 4);
	memcpy(&login_packet->host_info, host, sizeof(struct drcom_host));
	memset(login_packet->zero2, 0, 96);

	/* wtf? */
	login_packet->unknown1 = 0x01;
	login_packet->unknown2 = 0x00;
	login_packet->unknown3[0] = 0x01;
	login_packet->unknown3[1] = 0x08;

	/* maybe we should use something random instead? */
/*
	memset(login_packet->unknown4, 0, 8);
*/
	login_packet->unknown4[0] = 0x00;
	login_packet->unknown4[1] = 0xf0;
	login_packet->unknown4[2] = 0x66;
	login_packet->unknown4[3] = 0x33;
	login_packet->unknown4[4] = 0x72;
	login_packet->unknown4[5] = 0x5b;
	login_packet->unknown4[6] = 0xc4;
	login_packet->unknown4[7] = 0x01;
/*
	memcpy(login_packet->unknown4, d + 8, 8);
*/

	return;
}

static inline void _build_authentication(struct drcom_auth *auth, struct drcom_acknowledgement *acknowledgement)
{
	memcpy(auth, &acknowledgement->auth_info, sizeof(struct drcom_auth));
}

static void _build_keepalive(struct drcom_host_msg *keepalive, struct drcom_login_packet *login_packet, struct drcom_acknowledgement *acknowledgement)
{
	keepalive->msgtype = 0xff;
	memset(keepalive->msg, 0, 19);
	memcpy(keepalive->msg, login_packet->host_header.checksum, 16);
	memcpy(&keepalive->auth_info, &acknowledgement->auth_info, sizeof(struct drcom_auth));
	return;
}

static void add_except_address(struct drcom_handle *h, unsigned char *pkt, int pkt_size)
{
	struct drcom_acknowledgement *ack = (struct drcom_acknowledgement *)pkt;
	struct except_tuple *tuple = ack->tuple;
	
	while ((unsigned char *)tuple + sizeof(struct except_tuple) <= pkt + pkt_size) {
		if (tuple->addr == 0)
			return;
		if (tuple->zero0 == 0x00000001)
			return;
		add_except(h->conf, tuple->addr, tuple->mask);
/*		loginfo("add except:%u.%u.%u.%u/%u.%u.%u.%u\n", NIPQUAD(tuple->addr), NIPQUAD(tuple->mask));
*/
		tuple++;
	}
}

static int drcom_login(int s2, struct drcom_handle *h, int timeout)
{
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;
	struct drcom_info *info = (struct drcom_info *) h->info;
	struct drcom_host *host = (struct drcom_host *) h->host;
	struct drcom_host_msg *response = (struct drcom_host_msg *) h->response;
	struct drcom_host_msg *keepalive = (struct drcom_host_msg *) h->keepalive;
	struct drcom_auth *auth = (struct drcom_auth *) h->auth;
	struct drcom_challenge *challenge;
	struct drcom_login_packet login_packet;
	struct drcom_acknowledgement *acknowledgement;
	int retry=0;
	unsigned char *pkt;
	int pkt_size;
	int ret;

	(void)timeout;

try_it_again_1:
	retry++;
	if(retry>3)
		return -1;
	if(_send_dialog_packet(socks, NULL, PKT_REQUEST)<0){
		report_daemon_msg(s2, "_send_dialog_packet(PKT_REQUEST) failed\n");
		return -1;
	}

	ret = _recv_dialog_packet(socks, &pkt, &pkt_size);
	if (ret < 0 || pkt_size < sizeof(struct drcom_challenge)) {
		if (pkt)
			free(pkt);
		report_daemon_msg(s2, "_recv_dialog_packet(PKT_CHALLENGE) failed\n");
		goto try_it_again_1;
	}
	
	challenge = (struct drcom_challenge *)pkt;
	if (challenge->serv_header.pkt_type != PKT_CHALLENGE) {
		free(pkt);
		report_daemon_msg(s2, "_recv_dialog_packet(PKT_CHALLENGE) returned non-challenge pkt\n");
		goto try_it_again_1;
	}

	/* Now the _real_ ip address of the server is known */
	info->servip = socks->servaddr_in.sin_addr.s_addr;

	_build_login_packet(&login_packet, info, host, challenge);

	free(pkt);

	retry=0;
try_it_again_2:
	retry++;
	if(retry>3)
		return -1;
	if(_send_dialog_packet(socks, &login_packet, PKT_LOGIN)<0){
		report_daemon_msg(s2, "_send_dialog_packet(PKT_LOGIN) failed\n");
		return -1;
	}

	ret = _recv_dialog_packet(socks, &pkt, &pkt_size);

	report_daemon_msg(s2, "received server ACK(pkt_size=%d)\n", pkt_size);

	if (ret < 0) {
		if (pkt)
			free(pkt);
		report_daemon_msg(s2, "_recv_dialog_packet(PKT_ACK_SUCCESS) failed\n");
		goto try_it_again_2;
	}

	acknowledgement = (struct drcom_acknowledgement *)pkt;
	if (acknowledgement->serv_header.pkt_type != PKT_ACK_SUCCESS) {
		free(pkt);
		report_daemon_msg(s2, "Server acknowledged failure\n");
		return -1;
	}

	add_except_address(h, pkt, pkt_size);
	_build_authentication(auth, acknowledgement);
	_build_keepalive(keepalive, &login_packet, acknowledgement);
	memcpy(response, keepalive, sizeof(*keepalive));
	report_daemon_msg(s2, "Login Succeeded\n");
	report_daemon_msg(s2, "You have used %u Minutes, and %uK bytes\n", 
		acknowledgement->time_usage, acknowledgement->vol_usage);

	free(pkt);

	return 0;
}

static void recv_initial_server_msg(struct drcom_handle *h)
{
	(void)h;
}

void do_command_login(int s2, struct drcom_handle *h)
{
	struct drcomcd_login cd_login;
	int r;

	r = safe_recv(s2, &cd_login, sizeof(struct drcomcd_login));
	if (r != sizeof(struct drcomcd_login)) {
		logerr("daemon: recv: %s", strerror(errno));
		return;
	}

	if(status != STATUS_IDLE){
		report_daemon_msg(s2, "Error, Already logged in\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	status = STATUS_BUSY;
	r = server_sock_init(h);
	if(r!=0){
		status = STATUS_IDLE;
		report_daemon_msg(s2, "Cannot create socket to server\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	r = drcom_login(s2, h, cd_login.timeout);
	if(r != 0){
		status = STATUS_IDLE;
		server_sock_destroy(h);
		report_daemon_msg(s2, "Login failed\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	status = STATUS_LOGGED_IN;

	recv_initial_server_msg(h);

	module_start_auth(h);

	pthread_create(&th_watchport,NULL,daemon_watchport, h);
	pthread_create(&th_keepalive,NULL,daemon_keepalive, h);

	report_final_result(s2, h, DRCOMCD_SUCCESS);
}


