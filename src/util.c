#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#include <inject.h>
#include <elflib.h>

void error( const char* format, ... ) {
	va_list args;

	printf("\x1b[31m[\x1b[1m!\x1b[0m\x1b[31m]\x1b[0m \x1b[31m\x1b[1mERROR: \x1b[0m\x1b[31m");

	va_start( args, format );
	vfprintf(stdout, format, args);
	va_end(args);

	printf("\x1b[0m\n");

	// every error is very critical
	exit(-1);
}

void info( const char* format, ... ) {
	va_list args;

	printf("\x1b[36m[\x1b[1m+\x1b[0m\x1b[36m]\x1b[0m ");
	printf("\x1b[37m\x1b[1m");

	va_start( args, format );
	vfprintf(stdout, format, args);
	va_end(args);

	printf("\x1b[0m\n");
}

void info2( const char* format, ... ) {
	va_list args;

	printf("\x1b[33m \x1b[1m|_\x1b[0m\x1b[33m\x1b[0m ");
	printf("\x1b[32m\x1b[1m");

	va_start( args, format );
	vfprintf(stdout, format, args);
	va_end(args);

	printf("\x1b[0m\n");
}

void hexdump(void *ptr, int buflen) {
	unsigned char *buf = (unsigned char*)ptr;
	int i, j;
	for (i=0; i<buflen; i+=16) {
		printf("%06x: ", i);
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				printf("%02x ", buf[i+j]);
			else
				printf("   ");
		printf(" ");
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
		printf("\n");
	}
}

u64 resolve_symbol_tab(inject_ctx *ctx, char *name) {
	u64 sym;

	if (ctx->dynsym != 0 && ctx->dynstr != 0) {
		sym = resolve_symbol(ctx->dynsym, ctx->dynsym_sz, (char*)ctx->dynstr, name);
	}

	if (sym == 0 && ctx->symtab != 0 && ctx->strtab != 0) {
		sym = resolve_symbol(ctx->symtab, ctx->symtab_sz, (char*)ctx->strtab, name);
	}

	if (sym != 0) {
		sym += ctx->elf_base;
	}

	return sym;
}

u64 find_hole(inject_ctx *ctx, u64 call, u32 size) {
	mem_mapping *m1, *m2;
	u64 hole_addr = 0;
	int i;
	
	for(i = 0; i < ctx->num_maps; i++) {
		m1 = ctx->mappings[i];
		m2 = ctx->mappings[i+1];

		if(
			call >= m1->start &&
			m2->start > (m1->end + size)
		) {
			hole_addr = m1->end;

			break;
		}
	}
	
	return hole_addr;
}
