#include <stdbool.h>
#include <stdarg.h>
#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kern_control.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/proc.h> 
#include <kern/assert.h>
#include <libkern/OSMalloc.h>
#include <netinet/in.h>

#include "drcom.h"

#define DEBUG

#define DRCOM_TCP_FILTER_HANDLE		0x2e33677d
#define DRCOM_UDP_FILTER_HANDLE		0x2e33677e

// Global variables without lock protection
static kern_ctl_ref g_drcom_ctl_ref = NULL;

static bool g_drcom_tcp_filter_registered = false;
static bool	g_drcom_tcp_unreg_started = false;
static bool	g_drcom_tcp_unreg_completed = false;

static bool g_drcom_udp_filter_registered = false;
static bool	g_drcom_udp_unreg_started = false;
static bool	g_drcom_udp_unreg_completed = false;

static bool g_active = false;

// R/W locks
static lck_grp_t * g_lock_grp = NULL;
static lck_rw_t * g_auth_mode_lock = NULL;
static lck_rw_t * g_params_lock = NULL;

// Protected by g_params_lock
static size_t g_exclude_num = 0;
static struct exclude_entry * g_exclude_list = NULL;

// Protected by g_auth_mode_lock
static u_int8_t g_auth_mode = DRCOM_AUTH_MODE_OFF;
static u_int8_t g_auth_data[DRCOM_AUTH_DATA_LEN] = {0};
static pid_t g_pid = 0;
static bool g_autologout = false;

/* =================================== */
#pragma mark Debug-related functions

#if defined(DEBUG)

#define dprintf(...)			drcom_printf(__VA_ARGS__)

static void
drcom_printf(const char *fmt, ...)
{
	va_list listp;
	char log_buffer[92];
	
	va_start(listp, fmt);
	
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
	printf("drcom.kext: %s\n", log_buffer);
	
	va_end(listp);
}

#define FIRST_OCTET(X) ((ntohl((X)) & 0xFF000000) >> 24)
#define SECOND_OCTET(X) ((ntohl((X)) & 0x00FF0000) >> 16)
#define THIRD_OCTET(X) ((ntohl((X)) & 0x0000FF00) >> 8)
#define FOURTH_OCTET(X) (ntohl((X)) & 0x000000FF)

static inline void dprint_sockaddr(const socket_t so, const struct sockaddr_in * sockaddr)
{
	dprintf("Socket so=0x%x: %03d.%03d.%03d.%03d:%d",
		so,
		FIRST_OCTET(sockaddr->sin_addr.s_addr),
		SECOND_OCTET(sockaddr->sin_addr.s_addr),
		THIRD_OCTET(sockaddr->sin_addr.s_addr),
		FOURTH_OCTET(sockaddr->sin_addr.s_addr),
		ntohs(sockaddr->sin_port));
}

#else	/* !defined(DEBUG) */

#define dprintf(...)

#endif	/* !defined(DEBUG) */

/* =================================== */
#pragma mark Private misc functions

static bool
is_excluded(const struct sockaddr_in * sockaddr)
{
	/*
	if ((sockaddr->sin_addr.s_addr == htonl(2392256015L)) &&
		(sockaddr->sin_port == htons(9988)))
		return false;	
	
	return true;
	 */
	
	__uint32_t ip = sockaddr->sin_addr.s_addr;
	
	lck_rw_lock_shared(g_params_lock);
	if (g_exclude_list)
	{
		// Compare IP address with entries in exclude list
		int i;	
		for (i = 0; i < g_exclude_num; i++) 
			if ((g_exclude_list[i].mask & ip) == g_exclude_list[i].addr)
			{
				lck_rw_unlock_shared(g_params_lock);
				return !true;			
			}
	}
	lck_rw_unlock_shared(g_params_lock);	
	return !false;	
}

/* =================================== */
#pragma mark Lock-related functions

static errno_t
init_lock_grp(void)
{
	errno_t result = 0;
	
	// Lock group should be initialized only once.
	assert(NULL == g_lock_grp);
	
	lck_grp_attr_t * lock_grp_attr = lck_grp_attr_alloc_init();
	if (NULL == lock_grp_attr)
	{
		dprintf("lck_grp_attr_alloc_init() failed");
		result = ENOMEM;
		goto out;
	}
	
	g_lock_grp = lck_grp_alloc_init("drcom", lock_grp_attr);
	if (NULL == g_lock_grp)
	{
		dprintf("lck_grp_alloc_init() failed");
		result = ENOMEM;
		goto out;
	}
	
out:
	if (lock_grp_attr)
		lck_grp_attr_free(lock_grp_attr);
	
	return result;
}

static void
release_lock_grp(void)
{
	if (g_lock_grp)
	{
		lck_grp_free(g_lock_grp);
		g_lock_grp = NULL;
	}		
}

static errno_t
alloc_lock(lck_rw_t ** lock_ptr)
{
	errno_t result = 0;	
	lck_attr_t * lock_attr = NULL;
	
	// Make sure g_lock_grp is not NULL
	assert(g_lock_grp);
	
	lock_attr = lck_attr_alloc_init();
	if (NULL == lock_attr)
	{
		dprintf("lck_attr_alloc_init() failed");
		result = ENOMEM;
		goto out;
	}
	
	*lock_ptr = lck_rw_alloc_init(g_lock_grp, lock_attr);
	if (NULL == *lock_ptr)
	{
		dprintf("lck_rw_alloc_init() failed");
		result = ENOMEM;
		goto out;
	}

out:
	if (lock_attr)
		lck_attr_free(lock_attr);
	
	return result;
}

static void
release_lock(lck_rw_t * lock)
{
	// Make sure g_lock_grp is not NULL
	assert(g_lock_grp);
	
	if (lock)
	{
		lck_rw_free(lock, g_lock_grp);
	}
}

static errno_t
init_locks()
{
	errno_t retval;
	retval = init_lock_grp();
	if (retval)
	{
		dprintf("init_lock_grp() failed (errno=%d)", retval);
		return retval;
	}
	
	retval = alloc_lock(&g_auth_mode_lock);
	if (retval)
	{
		dprintf("alloc_lock() failed (errno=%d)", retval);
		return retval;
	}	
	retval = alloc_lock(&g_params_lock);
	if (retval)
	{
		dprintf("alloc_lock() failed (errno=%d)", retval);
		return retval;
	}	
	
	return 0;	
}

static void
release_locks()
{
	if (g_auth_mode_lock)
		release_lock(g_auth_mode_lock);
	if (g_params_lock)
		release_lock(g_params_lock);
	g_auth_mode_lock = g_params_lock = NULL;
	
	release_lock_grp();	
}

/* =================================== */
#pragma mark Autologout timer 

static void
install_autologout_timer(void);

static void
autologout_timer_func()
{
	dprintf("autologout_timer_func() is triggered.");
	
	// Verify g_auth_mode_lock, in case it has been released.
	if (NULL == g_auth_mode_lock)
		return;
	
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_ON)
	{
		// Check the active flag
		if (g_active)
		{
			// Re-install a timer for the next period.
			install_autologout_timer();
			dprintf("Internet connection is active.");
		}
		else
		{
			// No active traffic over the past DRCOM_AUTOLOGOUT_IDLE seconds.
			proc_signal(g_pid, SIGUSR1);
			dprintf("Autologout signal has been sent.");
		}
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
}

static void
install_autologout_timer(void)
{
	// Setup a timer to periodically monitor the Internet traffic.
	struct timespec	ts;
	ts.tv_sec = DRCOM_AUTOLOGOUT_IDLE;
	ts.tv_nsec = 0;
	bsd_timeout(autologout_timer_func, NULL, &ts);
	
	// Clear the active flag
	// Note: g_active is not protected by any lock because we don't need a very
	// accurate traffic sensor.
	g_active = false;
}

static void
uninstall_autologout_timer(void)
{
	bsd_untimeout(autologout_timer_func, NULL);
}

/* =================================== */
#pragma mark Drcom TCP filter (authentication + traffic monitor)

struct drcom_cookie {
	bool ignored; // Indicator of Internet outbound socket 
	bool auth_done; // Indicate whether auth-package has been injected
	mbuf_t auth_mbuf_ref; // A reference to identify the authentication package
};

typedef struct drcom_cookie drcom_cookie_t;

static void
drcom_tcp_unregistered_func(sflt_handle handle)
{
	assert(DRCOM_TCP_FILTER_HANDLE == handle);
	g_drcom_tcp_unreg_completed = true;
	g_drcom_tcp_filter_registered = false;
	dprintf("Drcom TCP filter has been unregistered.");
}

static errno_t
drcom_tcp_attach_func(void ** cookie, socket_t so)
{
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Ignore all sockets.
		lck_rw_unlock_shared(g_auth_mode_lock);
		return -1;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	// Allocate cookie for this socket
	*cookie = _MALLOC(sizeof(drcom_cookie_t), M_TEMP, M_WAITOK | M_ZERO);
	if (NULL == *cookie)
	{
		dprintf("_MALLOC() failed");
		return ENOMEM;
	}
	
	drcom_cookie_t * drcom_cookie_ptr = (drcom_cookie_t *)(*cookie);
	
	// Ignore all sockets by default
	drcom_cookie_ptr->ignored = true;
		
	dprintf("Drcom TCP filter has been attached to a socket (so=0x%x)", so);
	return 0;
}

static void
drcom_tcp_detach_func(void * cookie, socket_t so)
{
	// No one but this function can free the cookie
	assert(cookie);
		
	// We can release cookie now
	_FREE(cookie, M_TEMP);
	
	dprintf("Drcom TCP filter has been detached from a socket (so=0x%x)", so);
}

static errno_t	
drcom_tcp_connect_out_func(
	void * cookie,
	socket_t so,
	const struct sockaddr * to)
{
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Ignore all sockets (this is the default behavior).
		lck_rw_unlock_shared(g_auth_mode_lock);
		return 0;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	assert(cookie);
	drcom_cookie_t * drcom_cookie_ptr = (drcom_cookie_t *)cookie;
	
	// Make sure address family is correct
	assert(to->sa_family == AF_INET);
	assert(sizeof(struct sockaddr_in) <= to->sa_len);	
	struct sockaddr_in * addr = (struct sockaddr_in *)to;	
	
	// Check whether this socket should be ignored according to its destination
	// IP address. Note: all sockets are ignored by default.
	if (!is_excluded(addr))
	{		
		// Authentication is required for this socket
		drcom_cookie_ptr->ignored = false;
		drcom_cookie_ptr->auth_done = false;
		drcom_cookie_ptr->auth_mbuf_ref = NULL;
			
		dprint_sockaddr(so, addr);
		dprintf("Authentication has been enabled for this socket (so=0x%x)", so);
	}
	
	return 0;
}

static errno_t
drcom_tcp_data_in_func(
	void * cookie,
	socket_t so, 
	const struct sockaddr * from,
	mbuf_t * data, 
	mbuf_t * control,
	sflt_data_flag_t flags)
{
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Bypass all inbound packages.
		lck_rw_unlock_shared(g_auth_mode_lock);
		return 0;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	assert(cookie);
	drcom_cookie_t * drcom_cookie_ptr = (drcom_cookie_t *)cookie;
	
	// Bypass all inbound packages in ignored sockets.
	if (drcom_cookie_ptr->ignored)
		return 0;
	
	dprintf("drcom_data_in_func() is triggered in monitored socket (so=0x%x)", so);
	
	// Set the active flag.
	g_active = true;
	
	return 0;
}

// The assumption that all packages should be processed serially is held.
static errno_t
drcom_tcp_data_out_func(
	void * cookie,
	socket_t so, 
	const struct sockaddr * to,
	mbuf_t * data, 
	mbuf_t * control,
	sflt_data_flag_t flags)
{
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Bypass all packages.
		lck_rw_unlock_shared(g_auth_mode_lock);
		return 0;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	assert(cookie);
	drcom_cookie_t * drcom_cookie_ptr = (drcom_cookie_t *)cookie;
	
	// Bypass all packages in ignored sockets.
	if (drcom_cookie_ptr->ignored)
		return 0;
	
	dprintf("drcom_data_out_func() is triggered in monitored socket (so=0x%x)", so);
	
	// Set the active flag.
	g_active = true;
	
	// Bypass authentication package.
	if (drcom_cookie_ptr->auth_mbuf_ref &&
		drcom_cookie_ptr->auth_mbuf_ref == *data)
		
	{
		drcom_cookie_ptr->auth_mbuf_ref = NULL;
		return 0;
	}		
	
	/*
	if (*data)
	{
		dprintf("data: type = %d, flags = 0x%04x, next = 0x%08x, len = %d",
				mbuf_type(*data), mbuf_flags(*data), mbuf_next(*data));
		
		mbuf_t iterator = *data;
		size_t total_len = 0;
		while (iterator)
		{
			total_len += mbuf_len(iterator);			
			iterator = mbuf_next(iterator);
		}
		char * buf = _MALLOC(total_len + 1, M_TEMP, M_WAITOK | M_ZERO);
		mbuf_copydata(*data, 0, total_len, buf);
		dprintf("raw data: %s", buf);
		_FREE(buf, M_TEMP);
		
	}
	 */
			
	if (drcom_cookie_ptr->auth_done)
	{
		// Authentication has been done; bypass subsequent packages.
		return 0;
	}
	
	// Use timeout error code by default.
	errno_t result = ETIMEDOUT;
	
	// Inject an authentication package immediately.	
	mbuf_t auth_data = NULL;
	mbuf_t auth_control = NULL;
	errno_t retval;
	
	// Allocate a mbuf chain for authentication data in blocking mode.
	// Note: default type and flags are fine; don't do further modification.
	retval = mbuf_allocpacket(MBUF_WAITOK, DRCOM_AUTH_DATA_LEN, 0, &auth_data);
	if (retval)
	{
		dprintf("mbuf_allocpacket() failed (errno=%d)", retval);
		goto fail;
	}
	 
	// Fill it with authentication data.
	retval = mbuf_copyback(auth_data, 0, DRCOM_AUTH_DATA_LEN, g_auth_data, MBUF_WAITOK);
	if (retval)
	{
		dprintf("mbuf_copyback() failed (errno=%d)", retval);
		goto fail;
	}
	
	// FIXME: Do we really need such control information to send authentication
	// package?	
	// Duplicate a copy of control's mbuf chain if necessary.
	// See below for explaination.
	/*
	if (*control)
	{
		retval = mbuf_dup(*control, MBUF_WAITOK, &auth_control);
		if (retval)
		{
			dprintf("mbuf_dup() failed.");
			goto fail;
		}
	}
	 */

	// Set a reference letting this filter bypass authentication package.
	drcom_cookie_ptr->auth_mbuf_ref = auth_data;
	
	dprintf("Authentication data is ready to be sent.");
	
	// Attention: sock_inject_data_out() always frees mbuf's for auth_data and
	// auth_control regardless of return value!
	// Authentication package is NOT an OOB package, so flags = 0.
	retval = sock_inject_data_out(so, to, auth_data, auth_control, 0);
	
	// Clear all references (see above).
	auth_data = auth_control = NULL;
	
	// Now we can check the return value.
	if (retval)
	{
		dprintf("sock_inject_data_out() failed (errno=%d)", retval);
	}
	else
	{
		dprintf("Authentication data has been sent for this socket (so=0x%x)", so);
		
		drcom_cookie_ptr->auth_done = true;
		result = 0;		
	}	
	
fail:
	if (auth_data)
		mbuf_freem(auth_data);
	if (auth_control)
		mbuf_freem(auth_control);

	return result;
}

/* Dispatch vector for drcom TCP filter */
const static struct sflt_filter drcom_tcp_filter = {
	DRCOM_TCP_FILTER_HANDLE,	/* sflt_handle */
	SFLT_GLOBAL,				/* sf_flags */
	MYBUNDLEID,					/* sf_name - cannot be nil else param err results */
	drcom_tcp_unregistered_func,/* sf_unregistered_func */
	drcom_tcp_attach_func,		/* sf_attach_func - cannot be nil else param err results */			
	drcom_tcp_detach_func,		/* sf_detach_func - cannot be nil else param err results */
	NULL,						/* sf_notify_func */
	NULL,						/* sf_getpeername_func */
	NULL,						/* sf_getsockname_func */
	drcom_tcp_data_in_func,		/* sf_data_in_func */
	drcom_tcp_data_out_func,	/* sf_data_out_func */
	NULL,						/* sf_connect_in_func */
	drcom_tcp_connect_out_func,	/* sf_connect_out_func */
	NULL,						/* sf_bind_func */
	NULL,						/* sf_setoption_func */
	NULL,						/* sf_getoption_func */
	NULL,						/* sf_listen_func */
	NULL						/* sf_ioctl_func */
};

static errno_t
install_drcom_tcp_filter()
{
	errno_t retval;
	
	if (g_drcom_tcp_filter_registered)
	{
		dprintf("Oops, drcom TCP filter has been installed.");
		return 0;		
	}

	if (g_drcom_tcp_unreg_started && !g_drcom_tcp_unreg_completed)
	{
		dprintf("Drcom TCP filter is being uninstalled; try again!");
		return EAGAIN;		
	}
	
	if (!g_drcom_tcp_filter_registered)
	{
		// register the filter with PF_INET domain, SOCK_STREAM type, TCP protocol
		retval = sflt_register(&drcom_tcp_filter, PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (retval == 0)
		{
			dprintf("Drcom TCP filter has been registered");
			g_drcom_tcp_filter_registered = true;
			g_drcom_tcp_unreg_started = false;
			g_drcom_tcp_unreg_completed = false;
		}		
		else
		{
			dprintf("sflt_register(drcom_tcp_filter) failed (errno=%d)", retval);
			return retval;
		}	
	}

	return 0;
}

static errno_t
uninstall_drcom_tcp_filter()
{
	errno_t retval;
	
	if (!g_drcom_tcp_filter_registered)
	{
		dprintf("Oops, drcom TCP filter hasn't been installed yet.");
		return 0;		
	}
	
	if (!g_drcom_tcp_unreg_started)
	{
		// start the unregistration process
		retval = sflt_unregister(DRCOM_TCP_FILTER_HANDLE);
		if (retval)
		{
			dprintf( "sflt_unregister(DRCOM_TCP_FILTER_HANDLE) failed (errno=%d)", retval);
			return retval;
		}
		else
		{
			// Indicate that we've started the unreg process.
			g_drcom_tcp_unreg_started = true;
		}		
	}

	if (!g_drcom_tcp_unreg_completed)
	{
		dprintf("Drcom TCP filter is being unregistered.");
		return EINPROGRESS;
	}	
	
	return 0;		
}

/* =================================== */
#pragma mark Drcom UDP filter (traffic monitor)

static void
drcom_udp_unregistered_func(sflt_handle handle)
{
	assert(DRCOM_UDP_FILTER_HANDLE == handle);
	g_drcom_udp_unreg_completed = true;
	g_drcom_udp_filter_registered = false;
	dprintf("Drcom UDP filter has been unregistered.");
}

static errno_t
drcom_udp_attach_func(void ** cookie, socket_t so)
{
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Ignore all sockets.
		lck_rw_unlock_shared(g_auth_mode_lock);
		return -1;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	dprintf("Drcom UDP filter has been attached to a socket (so=0x%x)", so);
	return 0;
}

static void
drcom_udp_detach_func(void * cookie, socket_t so)
{
	dprintf("Drcom UDP filter has been detached from a socket (so=0x%x)", so);
}

static errno_t
drcom_udp_data_in_func(
	void * cookie,
	socket_t so, 
	const struct sockaddr * from,
	mbuf_t * data, 
	mbuf_t * control,
	sflt_data_flag_t flags)
{
	if (NULL == from)
		return 0;
		
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Bypass all inbound packages.
		lck_rw_unlock_shared(g_auth_mode_lock);
		return 0;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	// Make sure address family is correct
	assert(from->sa_family == AF_INET);
	assert(sizeof(struct sockaddr_in) <= from->sa_len);	
	struct sockaddr_in * addr = (struct sockaddr_in *)from;	
	
	// Check whether this package should be ignored according to its source
	// IP address.
	if (!is_excluded(addr))
	{		
		// Set the active flag.
		g_active = true;
		
		dprintf("drcom_udp_data_in_func() is triggered in monitored socket (so=0x%x)", so);
	}
	
	return 0;
}

static errno_t
drcom_udp_data_out_func(
	void * cookie,
	socket_t so, 
	const struct sockaddr * to,
	mbuf_t * data, 
	mbuf_t * control,
	sflt_data_flag_t flags)
{
	if (NULL == to)
		return 0;
		
	// Check authentication mode
	lck_rw_lock_shared(g_auth_mode_lock);
	if (g_auth_mode == DRCOM_AUTH_MODE_OFF)
	{
		// Bypass all inbound packages.
		lck_rw_unlock_shared(g_auth_mode_lock);
		return 0;
	}
	lck_rw_unlock_shared(g_auth_mode_lock);
	
	// Make sure address family is correct
	assert(to->sa_family == AF_INET);
	assert(sizeof(struct sockaddr_in) <= to->sa_len);	
	struct sockaddr_in * addr = (struct sockaddr_in *)to;	
	
	// Check whether this package should be ignored according to its destination
	// IP address.
	if (!is_excluded(addr))
	{		
		// Set the active flag.
		g_active = true;
		
		dprintf("drcom_udp_data_out_func() is triggered in monitored socket (so=0x%x)", so);
	}
	
	return 0;
}

/* Dispatch vector for drcom UDP filter */
const static struct sflt_filter drcom_udp_filter = {
	DRCOM_UDP_FILTER_HANDLE,	/* sflt_handle */
	SFLT_GLOBAL,				/* sf_flags */
	MYBUNDLEID,					/* sf_name - cannot be nil else param err results */
	drcom_udp_unregistered_func,/* sf_unregistered_func */
	drcom_udp_attach_func,		/* sf_attach_func - cannot be nil else param err results */			
	drcom_udp_detach_func,		/* sf_detach_func - cannot be nil else param err results */
	NULL,						/* sf_notify_func */
	NULL,						/* sf_getpeername_func */
	NULL,						/* sf_getsockname_func */
	drcom_udp_data_in_func,		/* sf_data_in_func */
	drcom_udp_data_out_func,	/* sf_data_out_func */
	NULL,						/* sf_connect_in_func */
	NULL,						/* sf_connect_out_func */
	NULL,						/* sf_bind_func */
	NULL,						/* sf_setoption_func */
	NULL,						/* sf_getoption_func */
	NULL,						/* sf_listen_func */
	NULL						/* sf_ioctl_func */
};

static errno_t
install_drcom_udp_filter()
{
	errno_t retval;
	
	if (g_drcom_udp_filter_registered)
	{
		dprintf("Oops, drcom UDP filter has been installed.");
		return 0;		
	}

	if (g_drcom_udp_unreg_started && !g_drcom_udp_unreg_completed)
	{
		dprintf("Drcom UDP filter is being uninstalled; try again!");
		return EAGAIN;		
	}
	
	if (!g_drcom_udp_filter_registered)
	{
		// register the filter with PF_INET domain, SOCK_DGRAM type, UDP protocol
		retval = sflt_register(&drcom_udp_filter, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (retval == 0)
		{
			dprintf("Drcom UDP filter has been registered");
			g_drcom_udp_filter_registered = true;
			g_drcom_udp_unreg_started = false;
			g_drcom_udp_unreg_completed = false;
		}		
		else
		{
			dprintf("sflt_register(drcom_udp_filter) failed (errno=%d)", retval);
			return retval;
		}	
	}

	return 0;
}

static errno_t
uninstall_drcom_udp_filter()
{
	errno_t retval;
	
	if (!g_drcom_udp_filter_registered)
	{
		dprintf("Oops, drcom UDP filter hasn't been installed yet.");
		return 0;		
	}
	
	if (!g_drcom_udp_unreg_started)
	{
		// start the unregistration process
		retval = sflt_unregister(DRCOM_UDP_FILTER_HANDLE);
		if (retval)
		{
			dprintf( "sflt_unregister(DRCOM_UDP_FILTER_HANDLE) failed (errno=%d)", retval);
			return retval;
		}
		else
		{
			// Indicate that we've started the unreg process.
			g_drcom_udp_unreg_started = true;
		}		
	}

	if (!g_drcom_udp_unreg_completed)
	{
		dprintf("Drcom UDP filter is being unregistered.");
		return EINPROGRESS;
	}	
	
	return 0;		
}

/* =================================== */
#pragma mark User-space controlling interface for drcom.kext

static errno_t
install_drcom_filters(void)
{
	errno_t retval;
	
	retval = install_drcom_udp_filter();
	if (retval)
	{
		dprintf("install_drcom_udp_filter() failed (errno=%d)", retval);
		return retval;
	}
	
	retval = install_drcom_tcp_filter();
	if (retval)
	{
		dprintf("install_drcom_tcp_filter() failed (errno=%d)", retval);
		return retval;		
	}
	
	return 0;
}

static errno_t
uninstall_drcom_filters(void)
{
	errno_t retval;
	
	retval = uninstall_drcom_udp_filter();
	if (retval)
	{
		dprintf("uninstall_drcom_udp_filter() failed (errno=%d)", retval);
		return retval;
	}
	
	retval = uninstall_drcom_tcp_filter();
	if (retval)
	{
		dprintf("uninstall_drcom_tcp_filter() failed (errno=%d)", retval);
		return retval;		
	}
	
	return 0;
}

static errno_t
handle_cmd_set_params(const void * data, size_t data_len)
{
	dprintf("handle_cmd_set_params() has been triggered.");
	
	struct drcom_set_params_opt * set_params_opt_ptr = NULL;
	u_int8_t * tmp_exclude_list = NULL;
	
	// Verify the length of data
	if (NULL == data || data_len < sizeof(struct drcom_set_params_opt))
	{
		dprintf("Corrupted data for DRCOM_CTL_PARAMS.");
		return EINVAL;
	}
		
	set_params_opt_ptr = (struct drcom_set_params_opt *) data;
	dprintf("Extracting %d entries to exclude list.", set_params_opt_ptr->exclude_count);
	
	if (set_params_opt_ptr->exclude_count > 0)
	{
		// Verify the length of header plus exclude list
		size_t list_len = set_params_opt_ptr->exclude_count * sizeof(struct exclude_entry);				
		if (data_len < (sizeof(struct drcom_set_params_opt) + list_len))
		{
			dprintf("Corrupted exclude list.");
			return EINVAL;
		}
		
		// Allocate membory to store exclude list
		tmp_exclude_list = _MALLOC(list_len, M_TEMP, M_WAITOK | M_ZERO);
		if (tmp_exclude_list == NULL)
		{
			dprintf("_MALLOC() failed");
			return ENOMEM;
		}		
		
		// Fill exlucde list without header
		memcpy(tmp_exclude_list, data + sizeof(struct drcom_set_params_opt), list_len);
	}
	
	// Update the global exclude list
	lck_rw_lock_exclusive(g_params_lock);
	g_exclude_num = set_params_opt_ptr->exclude_count;
	if (g_exclude_list)
		_FREE(g_exclude_list, M_TEMP);
	g_exclude_list = (struct exclude_entry *) tmp_exclude_list;	
	lck_rw_unlock_exclusive(g_params_lock);
	
	dprintf("Exclude list has been updated.");
	
	return 0;
}

static errno_t
handle_cmd_set_auth(const void * data, size_t data_len)
{
	errno_t result = 0;
	errno_t retval;
	
	dprintf("handle_cmd_set_auth() has been triggered.");
	
	struct drcom_set_auth_opt * set_auth_opt_ptr;
	
	// Verify the length of optval
	if (NULL == data || data_len < sizeof(struct drcom_set_auth_opt))
	{
		dprintf("Corrupted data for DRCOM_CTL_AUTH.");
		return EINVAL;
	}
	
	set_auth_opt_ptr = (struct drcom_set_auth_opt *) data;

	lck_rw_lock_exclusive(g_auth_mode_lock);
	
	if (g_auth_mode == set_auth_opt_ptr->cmd)
	{
		goto unlock;
	}
	
	switch (set_auth_opt_ptr->cmd) {
		case DRCOM_AUTH_MODE_ON:
			dprintf("DRCOM_AUTH_MODE_ON is received.");
			
			// Try to install filter first.
			// Make sure user-space program handles error code, e.g. EAGAIN,
			// very carefully.			
			retval = install_drcom_filters();
			if (retval)
			{
				dprintf("install_drcom_filters() failed (errno=%d)", retval);
				result = retval;
				goto unlock;
			}
			if (set_auth_opt_ptr->autologout)
			{
				install_autologout_timer();
			}
			
			g_auth_mode = set_auth_opt_ptr->cmd;
			g_pid = set_auth_opt_ptr->pid;
			g_autologout = set_auth_opt_ptr->autologout;
			memcpy(g_auth_data, set_auth_opt_ptr->auth_data, DRCOM_AUTH_DATA_LEN);
			
			dprintf("Authentication mode is turned ON.");
			break;
		case DRCOM_AUTH_MODE_OFF:
			dprintf("DRCOM_AUTH_MODE_OFF is received.");
			
			// Try to uninstall filter first.
			// Make sure user-space program handles error code, e.g. EINPROGRESS,
			// very carefully.			
			retval = uninstall_drcom_filters();
			if (retval)
			{
				dprintf("uninstall_drcom_filters() failed (errno=%d)", retval);
				result = retval;
				goto unlock;
			}
			uninstall_autologout_timer();
			
			g_auth_mode = set_auth_opt_ptr->cmd;
			g_pid = 0;
			g_autologout = false;
			memset(g_auth_data, 0, DRCOM_AUTH_DATA_LEN);
			dprintf("Authentication mode is turned OFF.");
			break;
		default:
			dprintf("Cannot identify command.");
			result = EINVAL;
			break;
	}
	
unlock:	
	lck_rw_unlock_exclusive(g_auth_mode_lock);	
	
	return result;
}

static errno_t
drcom_ctl_connect_func(
    kern_ctl_ref kctlref, 
    struct sockaddr_ctl * sac, 
    void ** unitinfo)
{
	// Do nothing here.
	return 0;
}

static errno_t
drcom_ctl_setopt_func(
    kern_ctl_ref kctlref,
    u_int32_t unit,
    void * unitinfo, 
    int opt,
    void * data,
    size_t len)	
{
	// opt dispatcher
	switch (opt)
	{
		case DRCOM_CTL_PARAMS:
			return handle_cmd_set_params(data, len);
		
		case DRCOM_CTL_AUTH:
			return handle_cmd_set_auth(data, len);
			
		default:
			return EINVAL;
	}
	
	return EINVAL;	
}

// Data structure to register a system control
// This is not a const structure since the ctl_id field will be set
// when the ctl_register call succeeds
static struct kern_ctl_reg drcom_ctl_reg = {
	MYBUNDLEID,				/* use a reverse dns name which includes a name unique to your comany */
	0,						/* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
	0,						/* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
	CTL_FLAG_PRIVILEGED,	/* privileged access required to access this filter */
	0,						/* use default send size buffer */
	0,						/* use default receive size buffer */
	drcom_ctl_connect_func,	/* called when a connection request is accepted (requied field)*/
	NULL,					/* called when a connection becomes disconnected */
	NULL,					/* ctl_send_func - handles data sent from the client to kernel control */
	drcom_ctl_setopt_func,	/* called when the user process makes the setsockopt call */
	NULL					/* called when the user process makes the getsockopt call */
};

static errno_t
install_drcom_controller()
{
	errno_t retval;
	
	if (g_drcom_ctl_ref)
	{
		dprintf("Oops, drcom controller has been installed.");
		return 0;		
	}
	
	// register our control structure so that we can be found by a user level process.
	retval = ctl_register(&drcom_ctl_reg, &g_drcom_ctl_ref);
	if (retval == 0) {
		dprintf("Controller filter has been registered (id=0x%x, ref=0x%x)", drcom_ctl_reg.ctl_id, g_drcom_ctl_ref);
	}
	else
	{
		dprintf("ctl_register() failed (errno=%d)", retval);
	}	
	
	return retval;
}

static errno_t
uninstall_drcom_controller()
{
	errno_t retval = 0;
	
	if (g_drcom_ctl_ref)
	{
		retval = ctl_deregister(g_drcom_ctl_ref);
		if (retval)
		{
			dprintf("ctl_deregister() failed (errno=%d)", retval);
		}
		else
		{
			g_drcom_ctl_ref = NULL;
		}
	}
	else
	{
		dprintf("Oops, drcom controller hasn't been registered yet.");
	}
	return retval;
}

/* =================================== */
#pragma mark Kernel extension functions

kern_return_t drcom_start(kmod_info_t * ki, void * d)
{
	errno_t retval;
	
	retval = init_locks();	
	if (retval)
	{
		dprintf("init_locks() failed (errno=%d)", retval);
		return KERN_RESOURCE_SHORTAGE;
	}		
	
	retval = install_drcom_controller();
	if (retval)
	{
		dprintf("install_controller_filter() failed (errno=%d)", retval);
		goto fail;
	}
	
	
    return KERN_SUCCESS;
	
fail:
	uninstall_drcom_controller();	
	release_locks();
	
	return KERN_FAILURE;
}


kern_return_t
drcom_stop (kmod_info_t * ki, void * d)
{
	errno_t retval;

	lck_rw_lock_exclusive(g_auth_mode_lock);
	g_auth_mode == DRCOM_AUTH_MODE_OFF;
	lck_rw_unlock_exclusive(g_auth_mode_lock);
	
	uninstall_autologout_timer();

	retval = uninstall_drcom_filters();
	if (retval)
	{
		dprintf("uninstall_drcom_filter() failed (errno=%d)", retval);
		return KERN_FAILURE;		
	}		
	
	retval = uninstall_drcom_controller();
	if (retval)
	{
		dprintf("uninstall_drcom_controller() failed (errno=%d)", retval);
		return KERN_FAILURE;		
	}

	lck_rw_lock_exclusive(g_params_lock);
	if (g_exclude_list)
	{
		_FREE(g_exclude_list, M_TEMP);		
		g_exclude_list = NULL;
	}
	lck_rw_unlock_exclusive(g_params_lock);	
	
	release_locks();	
	
	return KERN_SUCCESS;
	
}
