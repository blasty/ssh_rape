#include <string.h>
#include <stdlib.h>
#include <inject.h>
#include <types.h>
#include <common.h>

u64 *callcache;
u32 callcache_total=0;

void cache_calltable(inject_ctx *ctx) {
	mem_mapping *mapping;
	int32_t *v;
	int i, j, total=0;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size - 5; j++) {
			if (mapping->data[j] == 0xe8) {
				total++;
				j += 4;
			}
		}
	}

	callcache_total = total;
	callcache = malloc(total * 2 * sizeof(u64));

	memset(callcache, 0, total * 2 * sizeof(u64));

	total=0;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size - 5; j++) {
			if (mapping->data[j] == 0xe8) {
				v = (int32_t*)&mapping->data[j+1];
				callcache[(total*2)+0] = mapping->start+j;
				callcache[(total*2)+1] = mapping->start + j + 5 + *v;
				total++;
				j += 4;
			}
		}
	}
}

u64 *get_callcache() {
	return callcache;
}

u32 get_callcachetotal() {
	return callcache_total;
}
