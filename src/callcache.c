#include <string.h>
#include <stdlib.h>
#include <inject.h>
#include <types.h>
#include <common.h>
#include <callcache.h>

static callcache_entry *callcache;
static u32 callcache_total=0;

void cache_calltable(inject_ctx *ctx) {
	mem_mapping *mapping;
	callcache_entry *entry;
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
	callcache = malloc(total * sizeof(callcache_entry));

	memset(callcache, 0, total * sizeof(callcache_entry));

	total=0;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size - 5; j++) {
			if (mapping->data[j] == 0xe8) {
				v = (int32_t*)&mapping->data[j+1];
				entry = &callcache[total];
				entry->addr = mapping->start+j;
				entry->dest = mapping->start + j + 5 + *v;
				total++;
				j += 4;
			}
		}
	}
}

/*
 * 	Returns the number of calls to function_addr found.
 * 	Stores the locations of the call instructions in an array of u64 
 * 	and stores a pointer to it in the call_list param.
 */
int find_calls(u64 *call_list, u64 function_addr) {
	u64 *calls = NULL;
	callcache_entry *entry;
	int i, num_calls = 0;
	
	// Loop once to count the calls
	for (i = 0; i < callcache_total; i++) {
		entry = &callcache[i];
		if (entry->dest == function_addr)
			num_calls++;
	}
	
	if (num_calls > 0) {
		calls = calloc(num_calls, sizeof(u64));
	
		// Loop again to store the calls
		num_calls = 0;
		for (i = 0; i < callcache_total; i++) {
			entry = &callcache[i];
			if (entry->dest == function_addr)
				calls[num_calls] = entry->addr;
				num_calls++;
		}
	}
	
	call_list = calls;
	return num_calls;
}

callcache_entry *get_callcache() {
	return callcache;
}

u32 get_callcachetotal() {
	return callcache_total;
}

void free_callcache() {
	if (callcache != NULL)
		free(callcache);
}
