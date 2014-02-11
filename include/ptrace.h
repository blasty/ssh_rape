#ifndef __MYPTRACE_H__
#define __MYPTRACE_H__

#include <stdio.h>
#include <inject.h>

void _attach(int pid);
void _detach(int pid);
void _peek(int pid, unsigned long addr, void *ptr, int len);
void _peek_file(FILE *f, unsigned long addr, void *ptr, int len);
void _poke(int pid, unsigned long addr, void *vptr,int len);
int _mmap(inject_ctx *ctx, void *addr, size_t len, int prot, int flags, int fd, off_t offset);

#endif
