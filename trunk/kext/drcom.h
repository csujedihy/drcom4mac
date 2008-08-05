/*
 *  drcom.h
 *  drcom
 *
 *  Created by Zimu Liu on 04/08/08.
 *  Copyright 2008 iQua Research Group. All rights reserved.
 *
 */

#ifndef __DRCOM_H__
#define __DRCOM_H__

#define DRCOM_SO_BASE_CTL		(64+2048+64)

#define DRCOM_SO_SET_AUTH		DRCOM_SO_BASE_CTL
#define DRCOM_SO_SET_PARAMS		(DRCOM_SO_BASE_CTL+1)

#define DRCOM_AUTH_MODE_OFF		0
#define DRCOM_AUTH_MODE_ON		1

#define DRCOM_AUTH_DATA_LEN		16

#define DRCOM_AUTOLOGOUT_IDLE	(1 * 60) // in seconds

struct exclude_entry
{
	u_int32_t	addr;
	u_int32_t	mask;
};

struct drcom_set_params_opt
{
	// Number of entries in exclude list
	u_int32_t exclude_count;
	// Variable-length exclude list
	struct exclude_entry exclude_list[0];
};

struct drcom_set_auth_opt
{
	u_int8_t cmd;
	pid_t pid;
	u_int8_t autologout;
	u_int8_t auth_data[DRCOM_AUTH_DATA_LEN];
};

#endif