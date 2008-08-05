/*
  libdrcom - Library for communicating with DrCOM 2133 Broadband Access Server
  Copyright (C) 2005 William Poetra Yoga Hadisoeseno <williampoetra@yahoo.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef DRCOMD_H_
#define DRCOMD_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <net/if.h>
#endif

#include "daemon_server.h"

/* Use a simple handle */
struct msg_item
{
	struct msg_item *next;
	ssize_t msg_len;
	unsigned char *msg;
};

/* Used by drcomcd to initialize drcom.o */

struct drcom_conf
{
  char username[36];
  char password[16];
  char device[IFNAMSIZ];
  u_int8_t mac[6];
  u_int8_t mac0[6];
  u_int32_t nic[4];
  u_int32_t dnsp;
  u_int32_t dnss;
  u_int32_t dhcp;
  u_int32_t hostip;
  u_int32_t servip;
  u_int16_t hostport;
  u_int16_t servport;
  char hostname[32];
  u_int32_t winver_major;
  u_int32_t winver_minor;
  u_int32_t winver_build;
  char servicepack[32];
  int  autologout;
  int except_count;
  struct exclude_entry *except;
};

struct drcom_socks
{
  int sockfd;
  struct sockaddr_in hostaddr_in;
  struct sockaddr_in servaddr_in;
};

struct drcom_info
{
  char username[36];
  char password[16];
  char device[IFNAMSIZ];
  u_int8_t mac[6];
  u_int32_t nic[4];
  u_int32_t hostip;
  u_int32_t servip;
  u_int16_t hostport;
  u_int16_t servport;
};

struct drcom_session_info
{
  uint8_t auth[sizeof(struct drcom_auth)];
  uint32_t hostip;
  uint32_t servip;
  uint16_t hostport;
  uint16_t servport;
  uint32_t dnsp;
  uint32_t dnss;
};

struct drcom_handle
{
  struct drcom_conf *conf;
  struct drcom_socks *socks;
  struct drcom_info *info;
  struct drcom_session_info *session;
  struct drcom_host *host;
  struct drcom_auth *auth;
  struct drcom_host_msg *keepalive;
  struct drcom_host_msg *response;
  struct msg_item *msg_head;
};

/* Log file */
#define DRCOMCD_LOG_FILE "/var/log/drcomcd"

#define DRCOM_CONF "/etc/drcom.conf"

#define READ_END        0
#define WRITE_END       1

extern int sigusr1_pipe[];

#define STATUS_IDLE             0
#define STATUS_LOGGED_IN        1
#define STATUS_BUSY             2

extern int status;

extern pthread_t th_watchport, th_keepalive;


/* Turn on debugging mode */
/* conflicts with linux kernel headers */
/*#define DRCOM_DEBUG*/

extern void do_command_login(int, struct drcom_handle *);
extern void do_command_logout(int, struct drcom_handle *);
extern void do_command_passwd(int, struct drcom_handle *);

extern void unblock_sigusr1(void);
extern void block_sigusr1(void);
extern void sigusr1_handler (int);
extern int setup_sig_handlers(void);
extern void do_signals(struct drcom_handle *, int);

extern int module_start_auth(struct drcom_handle *);
extern int module_stop_auth(void);

extern int drcom_logout(int, struct drcom_handle *, int);

extern void *daemon_watchport(void *);
extern void *daemon_keepalive(void *);

extern int server_sock_init(struct drcom_handle *);
extern void server_sock_destroy(struct drcom_handle *);

extern void report_daemon_msg(int, const char *, ...);
extern int report_server_msg(struct drcom_handle *, char *, size_t);
extern void report_final_result(int, struct drcom_handle *, int);

extern struct drcom_handle *drcom_create_handle(void);
extern int drcom_destroy_handle(struct drcom_handle *);
extern struct drcom_session_info *drcom_get_session_info(struct drcom_handle *);
extern int drcom_init(struct drcom_handle *);

extern int add_except(struct drcom_conf *conf, u_int32_t ip, u_int32_t mask);
extern int _readconf(struct drcom_conf *, struct drcom_info *, struct drcom_host *);

extern int _send_dialog_packet(struct drcom_socks *, void *, u_int16_t);
extern int _recv_dialog_packet(struct drcom_socks *, unsigned char **, int *);

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#endif

