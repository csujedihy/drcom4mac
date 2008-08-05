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

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "md5.h"

#include "drcomd.h"
#include "daemon_server.h"
#include "client_daemon.h"

#include "log.h"

static void _build_passwd_packet(struct drcom_passwd_packet *passwd_packet, 
				struct drcom_info *info, 
				struct drcom_challenge *challenge, 
				char *newpassword)
{
	unsigned char s[32], t[22], d[16];
	int i, l;

	/* header */
	passwd_packet->host_header.pkt_type = PKT_PASSWORD_CHANGE;
	passwd_packet->host_header.zero = 0;
	passwd_packet->host_header.len = sizeof(struct drcom_passwd_packet);
	memset(t, 0, 22);
	memcpy(t, &passwd_packet->host_header.pkt_type, 2);
	memcpy(t + 2, &challenge->challenge, 4);
	l = strlen(info->password);
	strncpy((char *) (t + 6), info->password, 16);
	MD5(t, l + 6, d);
	memcpy(passwd_packet->host_header.checksum, d, 16);

	/* username */
	memset(passwd_packet->username, 0, 16);
	strncpy(passwd_packet->username, info->username, 16);

	memset(s, 0, 32);
	memcpy(s, passwd_packet->host_header.checksum, 16);
	l = strlen(info->password);
	strncpy((char *) (s + 16), info->password, 16);
	MD5(s, 16 + l, d);
	memcpy(passwd_packet->checksum1_xor, d, 16);
	for (i = 0; i < 16; ++i)
		passwd_packet->checksum1_xor[i] ^= newpassword[i];

	/* unknown */
	passwd_packet->unknown0 = 0x12;
	passwd_packet->unknown1 = 0x16;
	passwd_packet->unknown2 = 0x04;
	passwd_packet->unknown3 = 0x00;

	return;
}

static int drcom_passwd(int s2, struct drcom_handle *h, char *newpassword, int timeout)
{
	struct drcom_socks *socks = (struct drcom_socks *) h->socks;
	struct drcom_info *info = (struct drcom_info *) h->info;
	struct drcom_challenge *challenge;
	struct drcom_passwd_packet passwd_packet;
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
		report_daemon_msg(s2, "send(PKT_REQUEST) failed\n");
		return -1;
	}

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

	_build_passwd_packet(&passwd_packet, info, challenge, newpassword);

	free(pkt);

	retry=0;
try_it_again_2:
	retry++;
	if(retry>3)
		return -1;
	if(_send_dialog_packet(socks, &passwd_packet, PKT_PASSWORD_CHANGE)<0){
		report_daemon_msg(s2, "send(PKT_PASSWORD_CHANGE) failed\n");
		return -1;
	}

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

	if (acknowledgement->serv_header.pkt_type != PKT_ACK_SUCCESS){
		free(pkt);
		report_daemon_msg(s2, "Server acknowledged failure\n");
		return -1;
	}

	report_daemon_msg(s2, "Change passwd succeeded\n");

	free(pkt);

	return 0;
}

void do_command_passwd(int s2, struct drcom_handle *h)
{
	struct drcomcd_passwd cd_passwd;
	int r;

	r = safe_recv(s2, &cd_passwd, sizeof(struct drcomcd_passwd));
	if (r != sizeof(struct drcomcd_passwd)) {
		logerr("daemon: recv: %s", strerror(errno));
		return;
	}

	if(status != STATUS_IDLE){
		report_daemon_msg(s2, "BUSY, please logout first to change passwd\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	status = STATUS_BUSY;
	r = drcom_passwd(s2, h, cd_passwd.newpasswd, cd_passwd.timeout);
	if(r != 0){
		report_daemon_msg(s2, "Change passwd failed\n");
		report_final_result(s2, h, DRCOMCD_FAILURE);
		return;
	}

	report_final_result(s2, h, DRCOMCD_SUCCESS);
}


