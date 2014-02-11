#ifndef __MAP_H__
#define __MAP_H__

#include <types.h>
#include <inject.h>

void map_init();
void map_print(inject_ctx *ctx);
void map_load(inject_ctx *ctx, mem_mapping *out, char *line);
int map_load_all(inject_ctx *ctx);
void swap_map(mem_mapping *m1, mem_mapping *m2);
void sort_maps(inject_ctx *ctx);
mem_mapping **get_mappings();

#endif
