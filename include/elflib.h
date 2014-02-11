#ifndef __ELFLIB_H__
#define __ELFLIB_H__

#include <stdio.h>
#include <types.h>

void _peek_file(FILE *f, unsigned long addr, void *ptr, int len);
addr_t resolve_symbol(u8 *tab, int tab_size, char *str, char *sym);
int get_section(char *fn, char *sect, unsigned char **ret);

#endif
