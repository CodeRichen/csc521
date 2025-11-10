#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

extern uint8_t myethaddr[6];
extern uint8_t myipaddr[4];
extern uint8_t myrouterip[4];
extern uint8_t mynetmask[4];
extern uint8_t defarpip[4];
extern uint8_t defpingip[4];
extern uint8_t defdnsip[4];
extern char *defdnsquery;
extern uint16_t tcp_filter_port;

void load_network_config(const char *ifname);

#endif
