#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdarg.h>

void error( const char* format, ... );
void info( const char* format, ... );
void info2( const char* format, ... );
void hexdump(void *ptr, int buflen);

#endif
