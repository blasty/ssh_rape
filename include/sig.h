#ifndef __SIG_H__
#define __SIG_H__

typedef struct {
	u64 placeholder;
	char *name;
	char *str;
	u64  addr;
} signature;

u64 find_sig(u8 *b, int maxlen, u8 *sig, int siglen);
u64 find_sig_mem(inject_ctx *ctx, u8 *sig, int siglen, int perm_mask);
u64 find_call(inject_ctx *ctx, u64 addr);

#endif
