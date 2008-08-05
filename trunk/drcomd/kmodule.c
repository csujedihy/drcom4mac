#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "drcomd.h"
#include "daemon_kernel.h"

#include "log.h"

int module_start_auth(struct drcom_handle *h)
{
/*
	int sock;
	struct drcom_conf *conf = (struct drcom_conf*)h->conf;
	struct drcom_session_info *s;
	struct conn_param *cp;
        struct conn_auth_cmd cmd;
	int len, ret;

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
		logerr("socket create failure\n");
		return -1;
	}

	len = sizeof(struct e_address)*conf->except_count+sizeof(struct conn_param);
	cp = (struct conn_param *)malloc(len);
	if (cp==NULL){
		logerr("malloc failure\n");
		close(sock);
		return -1;
	}

	strncpy(cp->devname, conf->device, IFNAMSIZ);
	cp->e_count = conf->except_count;
	memcpy(cp->es, conf->except, cp->e_count*sizeof(struct e_address));

        ret = setsockopt(sock, IPPROTO_IP, CONN_SO_SET_PARAMS, cp, len);
        if (ret != 0) {
                logerr("setsockopt(CONN_SO_SET_PARAMS) failed\n");
		close(sock);
		free(cp);
                return -1;
        }

	free(cp);

	s = drcom_get_session_info(h);

        cmd.cmd = CONN_MODE_AUTH;
	cmd.pid = getpid();
	cmd.autologout = conf->autologout;
	memcpy(cmd.auth_data, s->auth, sizeof(struct drcom_auth));

        ret = setsockopt(sock, IPPROTO_IP, CONN_SO_SET_AUTH_CMD, &cmd, sizeof(struct conn_auth_cmd));
        if (ret != 0) {
                logerr("CONN_SO_SET_AUTH_CMD failed\n");
		close(sock);
                return -1;
        }

	close(sock);

	loginfo("daemon: Starting authentication...\n");
*/
	return 0;

}

int module_stop_auth(void)
{
/*
	int sock;
        struct conn_auth_cmd cmd;
	int ret;

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
		logerr("socket create failure\n");
		return -1;
	}

	cmd.cmd = CONN_MODE_NONE;
        ret = setsockopt(sock, IPPROTO_IP, CONN_SO_SET_AUTH_CMD, &cmd, sizeof(struct conn_auth_cmd));
        if (ret != 0) {
                logerr("CONN_SO_SET_AUTH_CMD failed\n");
		close(sock);
                return -1;
        }

	close(sock);

	loginfo("daemon: Stopping authentication...\n");
*/
	return -1;
}


