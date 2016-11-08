#ifndef __UTIL_H__
#define __UTIL_H__

int _strlen(const char *s);
void _strcpy(char *dst, char *src);
void _memset(unsigned char *dst, unsigned char val, int len);
void _strcat(char *dst, char *src);
void _writestr(int fd, char *s);
int isprint(char c);
int _strncmp(unsigned char *s1, unsigned char *s2, int len);

#ifdef HAVE_DEBUG
void hexdump(int fd, void *ptr, int buflen);
#endif

#endif
