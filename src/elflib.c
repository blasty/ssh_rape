#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <types.h>
#include <inject.h>
#include <elflib.h>

int get_section(char *fn, char *sect, unsigned char **ret, u64 *sect_base) {
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
			*sect_base = shdr->sh_addr;
			_peek_file(f, shdr->sh_offset, *ret, shdr->sh_size);
			break;
		}
	}

	fclose(f);

	return shdr->sh_size; 
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

void _peek_file(FILE *f, unsigned long addr, void *ptr, int len) {
	fseek(f, addr, SEEK_SET);
	fread(ptr, len, 1, f);
}

