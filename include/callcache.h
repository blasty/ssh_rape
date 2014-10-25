#ifndef __CALLCACHE_H__
#define __CALLCACHE_H__

#include <inject.h>

typedef struct {
	u64 addr;
	u64 dest;
} callcache_entry;

void cache_calltable(inject_ctx *ctx);
void free_callcache();

int find_calls(u64 **call_list, u64 function_addr);
callcache_entry *get_callcache();
u32 get_callcachetotal();

#endif
