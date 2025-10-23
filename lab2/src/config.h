#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

extern uint8_t myethaddr[6];   // 本機 MAC
extern uint8_t myipaddr[4];    // 本機 IP
extern uint8_t defarpip[4];    // Gateway

void load_network_config(const char *ifname);

#endif
