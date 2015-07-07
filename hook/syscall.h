#ifndef _SCALL_H_
#define _SCALL_H_

// hard wired for x86_64 for now
#define SC_TEMPLATE(x) asm("movl $" #x ", %%eax\n\tsyscall" ::: "eax")

int _open(const char *pathname, int flags, int mode) {
	SC_TEMPLATE(2); // NR_open
}

int _write(int fd, const void *buf, unsigned int count) {
	SC_TEMPLATE(1); // NR_write
}

void _exit(int status) {
	SC_TEMPLATE(60); // NR_exit
}

void _close(int fd) {
	SC_TEMPLATE(3); // NR_close
}


#endif
