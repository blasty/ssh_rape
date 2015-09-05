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
} inject_ctx;

#endif
