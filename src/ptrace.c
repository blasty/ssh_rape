#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <types.h>
#include <inject.h>

void _attach(int pid) {
	if((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}

	waitpid(pid, NULL, WUNTRACED);
}

void _detach(int pid) {
	if(ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
		perror("ptrace_detach");
		exit(-1);
	}
}

void _peek(int pid, unsigned long addr, void *ptr, int len) {
	long word;
	int count=0;

	while(len > 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr+count, NULL);
		memcpy((u8*)(ptr + count), &word, (len < 8) ? len : 8);
		len -= 8;
		count += 8;
	}
}

void _poke(int pid, unsigned long addr, void *vptr,int len) {
       	int count;
       	long word;
	u8 *w8=(u8*)&word;

	count = 0;

	while (len > 0) {
		if (len >= 8) {
			memcpy(&word, vptr+count, 8);
		} else {
			_peek(pid, addr+(8-len), w8+(8-len), len);
			memcpy(w8, vptr+count, len);
		}

		word = ptrace(PTRACE_POKETEXT, pid, addr+count, word);
		len -= 8;
		count += 8;
	}
}

int _mmap(inject_ctx *ctx, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
	struct user_regs_struct regs_bak, *regs;
	unsigned long maddr;
	int i;

	regs = malloc(sizeof(struct user_regs_struct));

	if (ptrace(PTRACE_GETREGS, ctx->pid, NULL, &regs_bak) < 0) {
		perror("ptrace");
		exit(-1);
	}

	memcpy(regs, &regs_bak, sizeof(struct user_regs_struct));

	regs->rip = ctx->sc_addr;
	regs->rax = 0x09; // __nr_mmap 
	regs->rdi = (unsigned long)addr;
	regs->rsi = len;
	regs->rdx = prot;
	regs->r10 = flags;
	regs->r9  = fd;
	regs->r8  = offset;

	if (ptrace(PTRACE_SETREGS, ctx->pid, NULL, regs) < 0) {
		perror("ptrace");
		exit(-1);
	}

	maddr = ctx->sc_addr;

	if (ptrace(PTRACE_SINGLESTEP, ctx->pid, NULL, NULL) < 0)
		printf("ss phail!\n");

	if (waitpid(ctx->pid, &i, 0) < 0)
		perror("waitpid");

	// Get registers after the syscall
	if (ptrace(PTRACE_GETREGS, ctx->pid, NULL, regs) < 0) {
		perror("ptrace");
		exit(-1);
	}

	ptrace(PTRACE_SETREGS, ctx->pid, NULL, &regs_bak);

	// Return value of mmap()
	maddr = regs->rax;

	free(regs);

	return maddr;
}

