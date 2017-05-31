#include "syscall.h"

int _strlen(const char *s) {
	int len=0;

	while(*s++)
		len++;

	return len;
}

void _strcpy(char *dst, char *src) {
	while(*src != '\0') {
		*dst++ = *src++;
	}

	*dst++ = '\0';
}

void _memset(void *dst, unsigned char val, int len) {
	unsigned char *dst8 = dst;

	while(len--) {
		*dst8++ = val;
	}
}

void _strcat(char *dst, char *src) {
	while(*dst) {
		dst++;
	}

	_strcpy(dst, src);
}


void _writestr(int fd, char *s) {
	_write(fd, s, _strlen(s));
}

int isprint(char c) {
	return (c >= 0x20 && c <= 0x7e) ? 1 : 0;
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

#ifdef HAVE_DEBUG
void hexdump(int fd, void *ptr, int buflen) {
	char line[256];

	unsigned char *buf = (unsigned char*)ptr;
	int i, j;
	for (i=0; i<buflen; i+=16) {
		_memset(line, 0, 256);
		mini_snprintf(line, 256, "%06x: ", i);
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				mini_snprintf(line + _strlen(line), 256, "%02x ", buf[i+j]);
			else
				mini_snprintf(line + _strlen(line), 256, "   ");
		mini_snprintf(line + _strlen(line), 256, " ");
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				mini_snprintf(line + _strlen(line), 256, "%c", isprint(buf[i+j]) ? buf[i+j] : '.');
		mini_snprintf(line + _strlen(line), 256, "\n");

		_write(fd, line, _strlen(line));
	}
}
#endif
