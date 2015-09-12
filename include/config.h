#ifndef __CONFIG_H___
#define __CONFIG_H__

typedef struct {
	unsigned int is_haxor; // flag indicating whether auth with backdoor key succeeded
	unsigned int ip_addr;
	unsigned int port;
	unsigned int net_type;
	unsigned int only_log_valid;
} config_block;

#endif
