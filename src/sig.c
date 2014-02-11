#include <types.h>
#include <string.h>
#include <inject.h>
#include <common.h>
#include <util.h>

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


