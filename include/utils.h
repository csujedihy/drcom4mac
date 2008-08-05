#ifndef UTILS_H_
#define UTILS_H_

extern ssize_t safe_send(int, const void *, size_t);
extern ssize_t safe_recv(int, void *, size_t);
extern int get_interface_ipaddr(char *, u_int32_t *);

#endif

