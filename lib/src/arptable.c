#include <stdio.h>
#include <string.h>
#include "util.h"

#define MAX_ARPIP_N 8

typedef struct {
  ipaddr_t ip;
  uint8_t eth[ETH_ADDR_LEN];
  int valid;
} ipethaddr_t;

ipethaddr_t arptable[MAX_ARPIP_N];
int arptable_n = 0;

/*
 * arptable_existed() - Check whether an IP address existed in the ARP table
 */
uint8_t *arptable_existed(uint8_t *ipaddr) {
  ipaddr_t ip = GET_IP(ipaddr);
  for (int i = 0; i < MAX_ARPIP_N; i++) {
    if (arptable[i].valid && arptable[i].ip == ip) {
      return arptable[i].eth;
    }
  }
  return NULL;
}

/*
 * arptable_add() - Append a mapping of IP address to the ARP table
 */
void arptable_add(uint8_t *ip, uint8_t *eth) {
#if (DEBUG_ARPCACHE == 1)
  char bufip[BUFLEN_IP], bufeth[BUFLEN_ETH];
  printf("ARPCache add (before): %s, %s\n", ip_addrstr(ip, bufip),
         eth_macaddr(eth, bufeth));
#endif

  ipaddr_t nip = GET_IP(ip);

  /* 如果已存在相同 IP，就覆寫並回報 */
  for (int i = 0; i < MAX_ARPIP_N; i++) {
    if (arptable[i].valid && arptable[i].ip == nip) {
      COPY_ETH_ADDR(arptable[i].eth, eth);
#if (DEBUG_ARPCACHE == 1)
      printf("ARPCache update: %s -> %s\n", ip_addrstr(ip, bufip), eth_macaddr(eth, bufeth));
#endif
      return;
    }
  }

  /* 找一個空位或覆寫最舊（這裡簡單循環覆寫） */
  for (int i = 0; i < MAX_ARPIP_N; i++) {
    if (!arptable[i].valid) {
      arptable[i].valid = 1;
      arptable[i].ip = nip;
      COPY_ETH_ADDR(arptable[i].eth, eth);
#if (DEBUG_ARPCACHE == 1)
      printf("ARPCache add slot %d: %s -> %s\n", i, ip_addrstr(ip, bufip), eth_macaddr(eth, bufeth));
#endif
      return;
    }
  }

  /* 如果全滿就覆寫 arptable_n 指向的 slot（環狀） */
  arptable_n = (arptable_n + 1) % MAX_ARPIP_N;
  arptable[arptable_n].ip = nip;
  COPY_ETH_ADDR(arptable[arptable_n].eth, eth);
  arptable[arptable_n].valid = 1;
#if (DEBUG_ARPCACHE == 1)
  {
    char bufip2[BUFLEN_IP], bufeth2[BUFLEN_ETH];
    printf("ARPCache replace slot %d: %s -> %s\n", arptable_n,
           ip_addrstr(ip, bufip2), eth_macaddr(eth, bufeth2));
  }
#endif
}
