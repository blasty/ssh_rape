#ifndef __INJECT_H__
#define __INJECT_H__

#include <fcntl.h>
#include <types.h>

#define MAX_KEY_ALLOWED_CALLS 32

typedef struct {
	u64 start;
	u64 end;
	u64 size;
	int perm;
	u8 *data;
} mem_mapping;


typedef struct {
	pid_t pid;
	u64 sc_addr;
	u64 elf_base;
	mem_mapping **mappings;
	int num_maps;
	int debug;
	int uses_new_key_system;
	u64 config_addr;

	// DYNSYM
	u8 *dynsym;
	u8 *dynstr;
	u64 dynsym_base;
	u64 dynstr_base;
	int dynsym_sz;
	int dynstr_sz;

	// SYMTAB
	u8 *symtab;
	u8 *strtab;
	u64 symtab_base;
	u64 strtab_base;
	int symtab_sz;
	int strtab_sz;

	// GOT
	u8 *got;
	u64 got_base;
	int got_sz;

	// RELA
	u8 *rela;
	u64 rela_base;
	int rela_sz;
} inject_ctx;

void inject_ctx_init(inject_ctx *ctx, pid_t pid);
void inject_ctx_deinit(inject_ctx *ctx);
u64 inject_resolve_rexec(inject_ctx *ctx);
void inject_ctx_map_reload(inject_ctx *ctx);

#endif
