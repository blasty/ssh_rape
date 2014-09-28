#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map.h>
#include <types.h>
#include <common.h>
#include <inject.h>
#include <util.h>
#include <ptrace.h>

mem_mapping *mappings[MAX_MAPPING];

void map_init() {
	memset(mappings, 0, sizeof(mem_mapping*) * MAX_MAPPING);
}

void map_print(inject_ctx *ctx) {
	int i;
	u64 last_end = 0;
	mem_mapping *m;	

	for(i = 0; i < ctx->num_maps; i++) {
		m = ctx->mappings[i];

		if (last_end == 0)
			info2("[%016lX -> %016lx]", m->start, m->end);
		else
			info2("[%016lX -> %016lx] <hole size:%lu>", m->start, m->end, m->start-last_end);
	
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

mem_mapping **get_mappings() {
	return mappings;
}
