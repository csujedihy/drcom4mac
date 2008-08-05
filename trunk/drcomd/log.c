#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>

#include "log.h"

static int daemon_mode = 0;

static void log_message(int priority, const char *format, va_list args)
{
	if(daemon_mode)
		vsyslog(priority, format, args);
	else
		vfprintf(stderr, format, args);
}

void logerr(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        log_message(LOG_ERR, format, args);
        va_end(args);
}

void loginfo(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        log_message(LOG_INFO, format, args);
        va_end(args);
}

void dbg(const char *format, ...)
{
#ifdef DEBUG
        va_list args;
        va_start(args, format);
        log_message(LOG_DEBUG, format, args);
        va_end(args);
#else
	(void)format;
#endif
}

void logging_init(const char *program_name, int daemon)
{
	if(daemon){
		openlog(program_name, LOG_PID | LOG_CONS, LOG_DAEMON);
		daemon_mode = daemon;
	}
}

void logging_close(void)
{
	if(daemon_mode)
		closelog();
}
