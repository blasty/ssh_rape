#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

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

