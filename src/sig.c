#include <types.h>
#include <string.h>
#include <inject.h>
#include <common.h>
#include <util.h>
#include <callcache.h>
#include <ptrace.h>
#include <sig.h>
#include <elflib.h>

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

u64 prevcall_by_debugstr(inject_ctx *ctx, char *str) {
	callcache_entry *entry, *callcache;
	int callcache_total;
	int i;

	u64 lea_addr = lea_by_debugstr(ctx, LEA_RDI, str);
	u64 prevcall = 0;
	u64 top = 0;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for (i = 0; i < callcache_total; i++) {
		entry = &callcache[i];

		if (entry->type == CALLCACHE_TYPE_CALL && entry->addr < lea_addr && entry->addr > top) {
			top = entry->addr;
			prevcall = entry->dest;
		}
	}

	return prevcall;
}

u64 find_plt_entry(inject_ctx *ctx, u64 got_addr) {
	unsigned char opcode[]="\xff\x25\x00\x00\x00\x00";
	int i, j;
	int *rptr = (int*)&opcode[2];
	mem_mapping *mapping;
	u64 plt_entry = 0;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size-6; j++) {
			*rptr = got_addr - (mapping->start + j + 6);

			if (memcmp(mapping->data+j, opcode, 6) == 0) {
				plt_entry = mapping->start + j;

				if (ctx->debug)
					info("plt_entry = 0x%lx", plt_entry);
			}
		}
	}

	return plt_entry;
}

u64 find_entrypoint(u64 addr) {
	return find_entrypoint_inner(addr, 1);
}

u64 find_entrypoint_inner(u64 addr, int cnt) {
	callcache_entry *entry, *entry_b, *callcache;
	u64 result=0;
	int callcache_total, i, j, acnt=0;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for (i = 0; i < callcache_total; i++) {
		entry = &callcache[i];
		if (entry->type == CALLCACHE_TYPE_CALL && entry->dest < addr && entry->dest > result) {
			acnt = 0;

			for(j=0; j<callcache_total; j++) {
				entry_b = &callcache[j];
				if (entry_b->dest == entry->dest)
					acnt++;
			}

			if (acnt >= cnt) {
				result = entry->dest;
			}
		}
	}

	return result;
}

int find_next_call_in_table(callcache_entry *callcache, int start_idx, int num_items) {
	int i;

	for(i=start_idx; i<num_items; i++) {
		if (callcache[i].type == CALLCACHE_TYPE_CALL)
			return i;
	}

	return -1;
}

u64 find_callpair(u64 addr_a, u64 addr_b) {
	callcache_entry *entry_a, *entry_b, *callcache;
	u64 result = 0;
	int callcache_total, i = 0;
	int idx_a, idx_b;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	while(i < callcache_total-1) {
		idx_a = find_next_call_in_table(callcache, i, callcache_total);
		idx_b = find_next_call_in_table(callcache, idx_a+1, callcache_total);

		if (idx_a == -1 || idx_b == -1)
			break;

		entry_a = &callcache[idx_a];
		entry_b = &callcache[idx_b];

		if (entry_a->dest == addr_a && entry_b->dest == addr_b) {
			result = entry_a->addr;
		}

		i = idx_b;
	}

	return result;
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
				if(ctx->debug)
					info("lea addr = 0x%llx", mapping->start+j);

				lea_addr = mapping->start+j;
			}
		}
	}

	return lea_addr;
}

u64 find_prev_load(inject_ctx *ctx, u8 load_ins, u8 lea_reg, 
				  u64 start_addr, u64 lea_addr) {
	int i, j;
	mem_mapping *mapping;
	char leabuf[]="\x48\x00\x00\x00\x00\x00\x00";
	int *rptr = (int*)&leabuf[3];

	leabuf[1] = load_ins;
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

u64 block_by_debugstr(inject_ctx *ctx, char *str, int type) {
	u64 lea_addr = 0;

	lea_addr = lea_by_debugstr(ctx, LEA_RDI, str);

	if (lea_addr == 0) 
		error("could not find 'lea' insn for str '%s'", str);

	info("lea = 0x%lx", lea_addr);

	return find_entrypoint_inner(lea_addr, 1);
}

u64 find_nearest_call(u64 start, u64 func) {
	u64 top=0;
	callcache_entry *callcache, *entry;
	u32 callcache_total;
	int i;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for(i=0; i<callcache_total; i++) {
		entry = &callcache[i];

		if (
			entry->type == CALLCACHE_TYPE_CALL && entry->dest == func &&
			entry->addr > start && (entry->addr < top || top == 0)
		) {
			top = entry->addr;
		}
	}

	return top;
}

u64 sub_by_debugstr(inject_ctx *ctx, char *str) {
	return block_by_debugstr(ctx, str, CALLCACHE_TYPE_CALL);
}

u64 jmp_by_debugstr(inject_ctx *ctx, char *str) {
	return block_by_debugstr(ctx, str, CALLCACHE_TYPE_JUMP);
}

u64 resolve_call_insn(inject_ctx *ctx, u64 call_insn_addr) {
	u8 opcode;
	int call;

	_peek(ctx->pid, call_insn_addr, &opcode, 1);

	if (opcode != 0xe8)
		return 0;

	_peek(ctx->pid, call_insn_addr+1, &call, 4);

	return call_insn_addr + 5 + call;
}

addr_t resolve_reloc_all(inject_ctx *ctx, char *sym) {
	u64 addr = 0;
 
	if (ctx->rela_plt_sz != 0) {
		addr	= resolve_reloc(
			ctx->rela_plt, ctx->rela_plt_sz, ctx->dynsym, ctx->dynsym_sz, (char*)ctx->dynstr, sym
		);
	}

	if (addr == 0) {
		addr	= resolve_reloc(
			ctx->rela_dyn, ctx->rela_dyn_sz, ctx->dynsym, ctx->dynsym_sz, (char*)ctx->dynstr, sym
		);
	}

	return addr;
}


u64 plt_by_name(inject_ctx *ctx, char *name) {
	return find_plt_entry(ctx, ctx->elf_base + resolve_reloc_all(ctx, name));
}
