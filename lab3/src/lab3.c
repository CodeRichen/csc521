#include <stdio.h>
#include <stdlib.h>
/* #include <windows.h> */

#include <pcap.h>
#include "config.h"
#include "arp.h"
#include "icmp.h"
#include "netdevice.h"
#include "util.h"
#include "icmp.h"

/**
 * main_proc() - the main thread
 **/
int main_proc(netdevice_t *p, const char *subnet) {
    uint8_t target_ip[4];

    int base0 = 140, base1 = 127, base2 = 208; // 預設
    if (subnet && strlen(subnet) > 0) {
        sscanf(subnet, "%hhu.%hhu.%hhu", &target_ip[0], &target_ip[1], &target_ip[2]);
        base0 = target_ip[0];
        base1 = target_ip[1];
        base2 = target_ip[2];
    }

    for (int i = 1; i <= 254; i++) {
        target_ip[0] = base0;
        target_ip[1] = base1;
        target_ip[2] = base2;
        target_ip[3] = i;
        icmp_ping(p, target_ip);
        usleep(5000);
    }

    printf("Waiting for ICMP Echo Reply ... (press Enter to stop)\n");

    while (1) {
        if (netdevice_rx(p) == -1)
            break;
        if (readready()) {
            if (fgetc(stdin) == '\n') break;
        }
    }
    return 0;
}


/****
 ****	MAIN ENTRY
 ****/
int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  netdevice_t *p;
  char subnet[32] = {0};  // 用來接子網字串

  if (argc >= 2) {
    strcpy(devname, argv[1]);
  } else {
    fprintf(stderr, "Usage: %s <interface> [subnet]\n", argv[0]);
    return -1;
  }

  if (argc >= 3) {
    strcpy(subnet, argv[2]);  // e.g. "192.168.0.0/24"
  }

  printf("Loading network configuration for interface: %s\n", devname);
  load_network_config(devname);

  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main);

  main_proc(p, subnet);  // 傳入 subnet 給 main_proc()

  netdevice_close(p);
  return 0;
}

