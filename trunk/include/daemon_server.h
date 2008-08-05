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

#ifndef DAEMON_SERVER_H_
#define DAEMON_SERVER_H_

#include <netinet/in.h>

struct drcom_host
{
	char hostname[32];
	u_int32_t dnsp;
	u_int32_t dhcp;
	u_int32_t dnss;
	u_int32_t zero0[2];
	u_int32_t unknown0;
	u_int32_t winver_major;
	u_int32_t winver_minor;
	u_int32_t winver_build;
	u_int32_t unknown1;
	char servicepack[32];
} __attribute__ ((__packed__));

struct drcom_auth
{
	char drco[4];
	u_int32_t servip;
	u_int16_t servport;
	u_int32_t hostip;
	u_int16_t hostport;
} __attribute__ ((__packed__));

struct drcom_host_msg
{
	u_int8_t msgtype;
	u_int8_t msg[19];
	struct drcom_auth auth_info;
} __attribute__ ((__packed__));

struct drcom_serv_msg
{
	u_int8_t m;
	u_int8_t mt;
	u_int8_t msg[0x640 - 1 - 1];
} __attribute__ ((__packed__));

/* Types used internally */

struct drcom_host_header
{
	u_int16_t pkt_type;
	u_int8_t zero;
	u_int8_t len;
	u_int8_t checksum[16];
} __attribute__ ((__packed__));

struct drcom_serv_header
{
	u_int16_t pkt_type;
	u_int8_t zero;
	u_int8_t len;
} __attribute__ ((__packed__));

struct drcom_request
{
	struct drcom_host_header host_header;
} __attribute__ ((__packed__));

struct drcom_challenge
{
	struct drcom_serv_header serv_header;
	u_int32_t challenge;
} __attribute__ ((__packed__));

struct drcom_login_packet
{
	struct drcom_host_header host_header;
	char username[36];
	u_int8_t unknown0;
	u_int8_t mac_code;
	u_int8_t mac_xor[6];
	u_int8_t checksum1[16];
	u_int8_t num_nic;
	u_int32_t nic[4];
	u_int8_t checksum2_half[8];
	u_int8_t dog;
	u_int8_t zero1[4];
	struct drcom_host host_info;
	u_int8_t zero2[96];
	u_int8_t unknown1;
	u_int8_t unknown2;
	u_int8_t unknown3[2];
	u_int8_t unknown4[8];
} __attribute__ ((__packed__));

struct drcom_logout_packet
{
	struct drcom_host_header host_header;
	char username[36];
	u_int8_t unknown0;
	u_int8_t mac_code;
	u_int8_t mac_xor[6];
	struct drcom_auth auth_info;
} __attribute__ ((__packed__));

struct drcom_passwd_packet
{
	struct drcom_host_header host_header;
	char username[16];
	u_int8_t checksum1_xor[16];
	u_int32_t unknown0;
	u_int32_t unknown1;
	u_int32_t unknown2;
	u_int32_t unknown3;
} __attribute__ ((__packed__));

struct except_tuple {
	u_int32_t addr;
	u_int32_t mask;
	u_int32_t zero0;
} __attribute__ ((__packed__));

struct drcom_acknowledgement
{
	struct drcom_serv_header serv_header;
	u_int8_t status;
	u_int32_t time_usage;
	u_int32_t vol_usage;
	u_int8_t unknown0[10];
	struct drcom_auth auth_info;
	u_int8_t unknown1[8];
	struct except_tuple tuple[0];
} __attribute__ ((__packed__));

/* Functions used internally */

int _getaddr(char *, u_int32_t *);

/* Values for pkt_type */

#define PKT_REQUEST	 	0x0001
#define PKT_CHALLENGE	 	0x0002
#define PKT_LOGIN		0x0103
#define PKT_LOGOUT		0x0106
#define PKT_PASSWORD_CHANGE 	0x0109
#define PKT_ACK_SUCCESS		0x0004
#define PKT_ACK_FAILURE		0x0005

/* Some constants */

/*
#define DRCOM_SOCKS_LEN sizeof(struct drcom_socks)
#define DRCOM_INFO_LEN sizeof(struct drcom_info)
#define DRCOM_HOST_LEN sizeof(struct drcom_host)
#define DRCOM_AUTH_LEN sizeof(struct drcom_auth)
#define DRCOM_HOST_MSG_LEN sizeof(struct drcom_host_msg)
#define DRCOM_SERV_MSG_LEN sizeof(struct drcom_serv_msg)
*/
#endif

