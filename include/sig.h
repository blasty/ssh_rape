#ifndef __SIG_H__
#define __SIG_H__

#define LEA_RDI 0x3d
#define LEA_RAX 0x05

#define LOAD_LEA 0x8d
#define LOAD_MOV 0x8b

typedef struct {
	u64 placeholder;
	char *name;
	char *str;
	u64  addr;
} signature;

u64 find_sig(u8 *b, int maxlen, u8 *sig, int siglen);
u64 find_sig_mem(inject_ctx *ctx, u8 *sig, int siglen, int perm_mask);
u64 find_call(inject_ctx *ctx, u64 addr);

u64 lea_by_debugstr(inject_ctx *ctx, u8 lea_reg, char *str);
u64 find_prev_load(inject_ctx *ctx, u8 load_ins, u8 lea_reg, u64 start_addr, u64 lea_addr);
u64 find_next_opcode(inject_ctx *ctx, u64 start_addr, u8 *sig, u8 siglen);
u64 sub_by_debugstr(inject_ctx *ctx, char *str);
u64 jmp_by_debugstr(inject_ctx *ctx, char *str);
u64 resolve_call_insn(inject_ctx *ctx, u64 call_insn_addr);

#endif
