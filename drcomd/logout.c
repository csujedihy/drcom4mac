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

static void _build_logout_packet(struct drcom_logout_packet *logout_packet, 
			struct drcom_info *info, struct drcom_challenge *challenge, 
			struct drcom_auth *auth)
{
	unsigned char t[22], d[16];
	int i, passwd_len;

	/* header */
	logout_packet->host_header.pkt_type = PKT_LOGOUT;
	logout_packet->host_header.zero = 0;
	logout_packet->host_header.len = strlen(info->username) + 
					sizeof(struct drcom_host_header);
	memset(t, 0, 22);
	memcpy(t, &logout_packet->host_header.pkt_type, 2);
	memcpy(t + 2, &challenge->challenge, 4);
	passwd_len = strlen(info->password);
	strncpy((char *) (t + 6), info->password, 16);
	MD5(t, passwd_len + 6, d);
	memcpy(logout_packet->host_header.checksum, d, 16);

	/* username */
	memset(logout_packet->username, 0, 36);
	strncpy(logout_packet->username, info->username, 36);

	/* unknown, maybe just a signature? */
	logout_packet->unknown0 = 0x18;

	/* mac */
	logout_packet->mac_code = 1;
	memcpy(logout_packet->mac_xor, info->mac, 6);
	for (i = 0; i < 6; ++i)
		logout_packet->mac_xor[i] ^= logout_packet->host_header.checksum[i];

	/* auth data */
	memcpy(&logout_packet->auth_info, auth, sizeof(struct drcom_auth));

	return;
}

int drcom_logout(int s2, struct drcom_handle *h, int timeout)
{
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;
	struct drcom_info *info = (struct drcom_info *) h->info;
	struct drcom_auth *auth = (struct drcom_auth *) h->auth;
	struct drcom_challenge *challenge;
	struct drcom_logout_packet logout_packet;
	struct drcom_acknowledgement *acknowledgement;
	int retry = 0;
	unsigned char *pkt;
	int pkt_size;
	int ret;

	(void)timeout;

try_it_again_1:
	retry++;
	if(retry > 3)
		return -1;
	_send_dialog_packet(socks, NULL, PKT_REQUEST);

	ret = _recv_dialog_packet(socks, &pkt, &pkt_size);
	if (ret < 0 || pkt_size < sizeof(struct drcom_challenge)) {
		if (pkt)
			free(pkt);
		report_daemon_msg(s2, "_recv_dialog_package(PKT_CHALLENGE) failed\n");
		goto try_it_again_1;
	}

	challenge = (struct drcom_challenge *)pkt;
	if (challenge->serv_header.pkt_type != PKT_CHALLENGE) {
		free(pkt);
		report_daemon_msg(s2, "_recv_dialog_package(PKT_CHALLENGE) returned non challenge pkt\n");
		goto try_it_again_1;
	}

	_build_logout_packet(&logout_packet, info, challenge, auth);

	free(pkt);

	retry = 0;
try_it_again_2:
	retry++;
	if(retry > 3)
		return -1;
	_send_dialog_packet(socks, &logout_packet, PKT_LOGOUT);

	ret = _recv_dialog_packet(socks, &pkt, &pkt_size);
	if (ret < 0 || pkt_size < sizeof(struct drcom_acknowledgement)) {
		if (pkt)
			free(pkt);
		report_daemon_msg(s2, "_recv_dialog_package(PKT_ACK_SUCCESS) failed\n");
		goto try_it_again_2;
	}

	acknowledgement = (struct drcom_acknowledgement *)pkt;
	if (acknowledgement->serv_header.pkt_type != PKT_ACK_SUCCESS){
		report_daemon_msg(s2, "Server acknowledged failure\n");
		free(pkt);
		return -1;
	}

	report_daemon_msg(s2, "Logout Succeeded\n");
	report_daemon_msg(s2, "You have used %u minutes, and %uK bytes\n", 
				acknowledgement->time_usage, acknowledgement->vol_usage);

	free(pkt);

	return 0;
}

void do_command_logout(int s2, struct drcom_handle *h)
{
	struct drcomcd_logout cd_logout;
	int r;

	r = safe_recv(s2, &cd_logout, sizeof(struct drcomcd_logout));
	if (r != sizeof(struct drcomcd_logout)) {
		logerr("daemon: recv: %s", strerror(errno));
		return;
	}

	if(status != STATUS_LOGGED_IN){
		report_daemon_msg(s2,"Error, Already logged out\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	status = STATUS_BUSY;
	/* Stop the threads here, since they might interfere with
	   the logout process */
	module_stop_auth();
	pthread_cancel(th_keepalive);
	pthread_cancel(th_watchport);
	pthread_join(th_keepalive, NULL);
	pthread_join(th_watchport, NULL);
	/* Now try to log out */
	r = drcom_logout(s2, h, cd_logout.timeout);
	if(r != 0){
		/* If logout failed, that means we are still logged in,
		   so re-create the threads and continue authentication */
		module_start_auth(h);
		pthread_create(&th_watchport, NULL, daemon_watchport, h);
		pthread_create(&th_keepalive, NULL, daemon_keepalive, h);

		status = STATUS_LOGGED_IN;
		report_daemon_msg(s2, "Logout failed\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	server_sock_destroy(h);

	status = STATUS_IDLE;

	report_final_result(s2, h, DRCOMCD_FAILURE);
}


