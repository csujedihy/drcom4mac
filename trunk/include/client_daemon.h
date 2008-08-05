#ifndef CLIENT_DAEMON_H_
#define CLIENT_DAEMON_H_

#include <stdint.h>

/* Signature */
#define DRCOM_SIGNATURE 0xd4c0

/* The packet header */

struct drcomcd_hdr
{
	uint16_t signature; /* must be 0xd4c0 */
	uint16_t type; 	/* for header from daemon to client, type indicates success or not */
			/* for header from client to daemon, type indicates command to execute */
	ssize_t  msg_len; /* the string message length after this header */
	uint16_t is_end; /* is this packet the last header? */
};

/* drcomcd_hdr.type */
#define DRCOMCD_MSG	0x0000

#define DRCOMCD_LOGIN   0x0103
#define DRCOMCD_LOGOUT  0x0106
#define DRCOMCD_PASSWD  0x0109

#define DRCOMCD_SUCCESS 0x0004
#define DRCOMCD_FAILURE 0x0005


/* The data sent by drcomc */

struct drcomcd_login
{
  int authenticate;
  int timeout;
};

struct drcomcd_logout
{
  int timeout;
};

struct drcomcd_passwd
{
  char newpasswd[16];
  int timeout;
};


#define DRCOMCD_SOCK "/var/run/drcomcd"


extern ssize_t safe_recv(int, void *, size_t);
extern ssize_t safe_send(int, const void *, size_t);

#endif
