/*
	drcom.kext
		Mac OS X Kernel extentsion for communicating with
		DrCOM 2133 Broadband Access Server
		
	Copyright (C) 2008 Zimu Liu <zimu.liu@gmail.com>

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

#ifndef __DAEMON_KERNEL_H__
#define __DAEMON_KERNEL_H__

#define MYBUNDLEID				"edu.toronto.eecg.kext.drcom"

#define DRCOM_CTL_AUTH			1
#define DRCOM_CTL_PARAMS		2

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