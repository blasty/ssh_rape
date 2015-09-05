#ifndef __CALLCACHE_H__
#define __CALLCACHE_H__

#include <inject.h>

#define CALLCACHE_TYPE_CALL 0
#define CALLCACHE_TYPE_JUMP 1

typedef struct {
	u64 addr;
	u64 dest;
	u64 type;
} callcache_entry;

void cache_calltable(inject_ctx *ctx);
void callcache_free();

int find_calls(u64 **call_list, u64 function_addr);
callcache_entry *get_callcache();
u32 get_callcachetotal();

#endif
