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
} inject_ctx;

#endif
