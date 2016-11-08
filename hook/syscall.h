#ifndef _SCALL_H_
#define _SCALL_H_

#include <sys/types.h>
#include <sys/socket.h>

#define NR_read 0
#define NR_write 1
#define NR_open 2
#define NR_close 3
#define NR_execve 59
#define NR_exit 60
#define NR_socket 41
#define NR_connect 42
#define NR_sendto 44

#define STRx(x) #x
#define STR(x) STRx(x)

// hard wired for x86_64 for now
#define SC_TEMPLATE(x) asm("movl $" STR(x) ", %%eax\n\tsyscall" ::: "eax")
#define SC_LONG_TEMPLATE(x) asm("mov %%rcx, %%r10\nmovl $" STR(x) ", %%eax\n\tsyscall" ::: "eax")


int _open(const char *pathname, int flags, int mode);
int _write(int fd, const void *buf, unsigned int count);
int _read(int fd, const void *buf, unsigned int count);
void _exit(int status);
int _execve(const char *filename, char *const argv[], char *const envp[]);
void _close(int fd);
int _socket(int domain, int type, int protocol);
int _connect(int fd, struct sockaddr *addr, socklen_t addrlen);
ssize_t _sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

#endif
