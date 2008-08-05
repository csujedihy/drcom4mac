#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>

extern void logerr(const char *format, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void loginfo(const char *format, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void dbg(const char *format, ...)
	__attribute__ ((format (printf, 1, 2)));

extern void logging_init(const char *, int);
extern void logging_close(void);

#endif
