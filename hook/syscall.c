#include <sys/types.h>
#include <sys/socket.h>
#include "syscall.h"

int _open(const char *pathname, int flags, int mode) {
	SC_TEMPLATE(NR_open);
}

int _write(int fd, const void *buf, unsigned int count) {
	SC_TEMPLATE(NR_write);
}

int _read(int fd, const void *buf, unsigned int count) {
	SC_TEMPLATE(NR_read);
}

void _exit(int status) {
	SC_TEMPLATE(NR_exit);
}

int _execve(const char *filename, char *const argv[], char *const envp[]) {
	SC_TEMPLATE(NR_execve);
}

void _close(int fd) {
	SC_TEMPLATE(NR_close);
}

int _socket(int domain, int type, int protocol) {
	SC_TEMPLATE(NR_socket);
}

int _connect(int fd, struct sockaddr *addr, socklen_t addrlen) {
	SC_TEMPLATE(NR_connect);
}

ssize_t _sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	SC_LONG_TEMPLATE(NR_sendto);
}
