#include <types.h>
#include <string.h>
#include <inject.h>
#include <common.h>
#include <util.h>
#include <callcache.h>
#include <ptrace.h>
#include <sig.h>

u64 find_sig(u8 *b, int maxlen, u8 *sig, int siglen) {
	int i;

	for(i = 0; i < maxlen; i++) {
		if (memcmp(b+i, sig, siglen) == 0)
			return i;
	}

	return 0;
}

u64 find_sig_mem(inject_ctx *ctx, u8 *sig, int siglen, int perm_mask) {
	unsigned long a;
	mem_mapping *mapping;
	int i;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];
		if ((mapping->perm & perm_mask) != perm_mask)
			continue;

		a = find_sig(mapping->data, mapping->size, sig, siglen);

		if (a != 0)
			return mapping->start + a;
	}

	return 0;
}

u64 find_call(inject_ctx *ctx, u64 addr) {
	int i,j;
	char call_pat[]="\xe8\x00\x00\x00\x00";
	int *rptr = (int*)&call_pat[1];
	mem_mapping *mapping;
	u64 call_addr = 0;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		// skip non exec mappingz
		if (!(mapping->perm & MEM_X))
			continue;

		for(j = 0; j < mapping->size-5; j++) {
			*rptr = addr - (mapping->start+j+5);
			if (memcmp(mapping->data+j, call_pat, 5) == 0) {
				if (call_addr != 0) info("OMFG DUPE HIT");
				call_addr = mapping->start+j;
			}
		}
	}

	if (call_addr == 0)
		error("could NOT find call insn for addr 0x%llx", addr);

	return call_addr;
}

u64 lea_by_debugstr(inject_ctx *ctx, u8 lea_reg, char *str) {
	u64 lea_addr, str_addr;
	char leabuf[]="\x48\x8d\x00\x00\x00\x00\x00";
	int *rptr = (int*)&leabuf[3];
	int i, j;
	mem_mapping *mapping;

	leabuf[2] = lea_reg;

	str_addr = find_sig_mem(ctx, (u8*)str, strlen(str), MEM_R);

	if (str_addr == 0)
		error("could not locate str '%s'", str);

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size-7; j++) {
			*rptr = str_addr - (mapping->start+j+7);
			if (memcmp(mapping->data+j, leabuf, 7) == 0) {
				lea_addr = mapping->start+j;
			}
		}
	}

	return lea_addr;
}

u64 find_prev_lea(inject_ctx *ctx, u8 lea_reg, u64 start_addr, u64 lea_addr) {
	int i, j;
	mem_mapping *mapping;
	char leabuf[]="\x48\x8d\x00\x00\x00\x00\x00";
	int *rptr = (int*)&leabuf[3];

	leabuf[2] = lea_reg;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if (!(start_addr >= mapping->start && start_addr <= mapping->end))
			continue;

		for(j = (start_addr - 7 - mapping->start); j > 0; j--) {
			*rptr = lea_addr - (mapping->start+j+7);

			if (memcmp(mapping->data+j, leabuf, 7) == 0) {
				return mapping->start+j;
			}
		}
	}

	return 0;
}

u64 find_next_opcode(inject_ctx *ctx, u64 start_addr, u8 *sig, u8 siglen) {
	int i, j;
	mem_mapping *mapping;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if (!(start_addr >= mapping->start && start_addr <= mapping->end))
			continue;

		for(j = start_addr - mapping->start; j < mapping->size - siglen; j++) {
			if (memcmp(mapping->data+j, sig, siglen) == 0) {
				return mapping->start+j;
			}
		}
	}

	return 0;
}

u64 sub_by_debugstr(inject_ctx *ctx, char *str) {
	u64 lea_addr = 0, rdiff=0, rtop=0;
	callcache_entry *callcache, *entry;
	u32 callcache_total;
	int i;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	lea_addr = lea_by_debugstr(ctx, LEA_RDI, str);

	if (lea_addr == 0) 
		error("could not find 'lea' insn for str '%s'", str);

	rdiff=0x313337;
	rtop=0;

	for(i=0; i<callcache_total; i++) {
		entry = &callcache[i];
		if (entry->dest < lea_addr) {
			if (lea_addr - entry->dest < rdiff) {
				rdiff = lea_addr - entry->dest;
				rtop = entry->dest;
			}
		}
	}

	return rtop;
}

u64 resolve_call_insn(inject_ctx *ctx, u64 call_insn_addr) {
	u8 opcode;
	u32 call;

	_peek(ctx->pid, call_insn_addr, &opcode, 1);

	if (opcode != 0xe8)
		return 0;

	_peek(ctx->pid, call_insn_addr+1, &call, 4);

	return call_insn_addr + 5 + call;
}
