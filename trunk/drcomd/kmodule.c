#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include "drcomd.h"
#include "daemon_kernel.h"

#include "log.h"

int module_start_auth(struct drcom_handle *h)
{
	int retval = 0;
	int ctl_fd = 0;
	struct ctl_info ctl_info;
	struct sockaddr_ctl sc;
	
	struct drcom_conf *conf = (struct drcom_conf*)h->conf;
	struct drcom_session_info *s;
	struct drcom_set_params_opt * drcom_params_opt_ptr;
	struct drcom_set_auth_opt drcom_auth_opt;
	size_t len;
	
	ctl_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (ctl_fd < 0){
		logerr("socket(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	bzero(&ctl_info, sizeof(struct ctl_info));
	strcpy(ctl_info.ctl_name, MYBUNDLEID);
	retval = ioctl(ctl_fd, CTLIOCGINFO, &ctl_info);
	if (retval < 0) {
		logerr("ioctl(CTLIOCGINFO): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
	retval = connect(ctl_fd, (struct sockaddr *) &sc, sizeof(struct sockaddr_ctl));
	if (retval < 0)
	{
		logerr("connect(): %s, errno = %d\n", strerror(errno), errno);
		close(ctl_fd);
		return -1;
	}
	
	len = sizeof(struct exclude_entry)*conf->except_count + sizeof(struct drcom_set_params_opt);
	drcom_params_opt_ptr = (struct drcom_set_params_opt *)malloc(len);
	if (NULL == drcom_params_opt_ptr)
	{
		logerr("malloc() failed\n");
		close(ctl_fd);
		return -1;
	}
	
	drcom_params_opt_ptr->exclude_count = conf->except_count;
	memcpy(drcom_params_opt_ptr->exclude_list,
		conf->except,
		drcom_params_opt_ptr->exclude_count * sizeof(struct exclude_entry));
	
	retval = setsockopt(ctl_fd, SYSPROTO_CONTROL, DRCOM_CTL_PARAMS, drcom_params_opt_ptr, len);
	if (retval != 0) {
		logerr("setsockopt(DRCOM_CTL_PARAMS): %s, errno = %d\n", strerror(errno), errno);
		close(ctl_fd);
		free(drcom_params_opt_ptr);
		return -1;
	}	
	free(drcom_params_opt_ptr);
	
	s = drcom_get_session_info(h);
	
	drcom_auth_opt.cmd = DRCOM_AUTH_MODE_ON;
	drcom_auth_opt.pid = getpid();
	drcom_auth_opt.autologout = conf->autologout;
	memcpy(drcom_auth_opt.auth_data, s->auth, sizeof(struct drcom_auth));
	
	retval = setsockopt(ctl_fd, SYSPROTO_CONTROL, DRCOM_CTL_AUTH, &drcom_auth_opt, sizeof(drcom_auth_opt));
	if (retval != 0) {
		logerr("setsockopt(DRCOM_CTL_AUTH): %s, errno = %d\n", strerror(errno), errno);
		close(ctl_fd);
		return -1;
	}
	
	close(ctl_fd);
	
	loginfo("daemon: Starting authentication...\n");
	return 0;	
}

int module_stop_auth(void)
{
	int retval = 0;
	int ctl_fd = 0;
	struct ctl_info ctl_info;
	struct sockaddr_ctl sc;
	
	struct drcom_set_auth_opt drcom_auth_opt;
	
	ctl_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (ctl_fd < 0){
		logerr("socket(): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	bzero(&ctl_info, sizeof(struct ctl_info));
	strcpy(ctl_info.ctl_name, MYBUNDLEID);
	retval = ioctl(ctl_fd, CTLIOCGINFO, &ctl_info);
	if (retval < 0) {
		logerr("ioctl(CTLIOCGINFO): %s, errno = %d\n", strerror(errno), errno);
		return -1;
	}
	
	bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
	retval = connect(ctl_fd, (struct sockaddr *) &sc, sizeof(struct sockaddr_ctl));
	if (retval < 0)
	{
		logerr("connect(): %s, errno = %d\n", strerror(errno), errno);
		close(ctl_fd);
		return -1;
	}
		
	drcom_auth_opt.cmd = DRCOM_AUTH_MODE_OFF;
	
	retval = setsockopt(ctl_fd, SYSPROTO_CONTROL, DRCOM_CTL_AUTH, &drcom_auth_opt, sizeof(drcom_auth_opt));
	if (retval != 0) {
		logerr("setsockopt(DRCOM_CTL_AUTH): %s, errno = %d\n", strerror(errno), errno);
		close(ctl_fd);
		return -1;
	}
	
	close(ctl_fd);

	loginfo("daemon: Stopping authentication...\n");
	return -1;
}


