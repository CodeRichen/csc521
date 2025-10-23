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
int main_proc(netdevice_t *p) {
    char buf[MAX_LINEBUF];
    ipaddr_t ip;
    int key;

    uint8_t base_ip[4] = {140, 127, 208, 0};

    printf("Start ICMP scan on subnet: %d.%d.%d.0/24\n",
           base_ip[0], base_ip[1], base_ip[2]);

  uint8_t target_ip[4];
for (int i = 1; i <= 254; i++) {
    target_ip[0] = 140;
    target_ip[1] = 127;
    target_ip[2] = 208;
    target_ip[3] = i;
    icmp_ping(p, target_ip);
    usleep(50000);
}


    printf("Waiting for ICMP Echo Reply ... (press Enter to stop)\n");

    while (1) {
        if (netdevice_rx(p) == -1)
            break;

        if (readready()) {
            if ((key = fgetc(stdin)) == '\n') break;
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

  /*
   * Get the device name of capture interface
   */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
    return -1;
  }

  /*
   * Load system network configuration (MAC, IP, MASK, GATEWAY)
   */
  printf("Loading network configuration for interface: %s\n", devname);
  load_network_config(devname);  // ✅ 新增自動讀取網卡資訊

  /*
   * Open the specified interface
   */
  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  /*
   * Register the packet handler callback of specific protocol
   */
  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main);

  /*
   * Start main loop
   */
  main_proc(p);

  /*
   * Clean up the resources
   */
  netdevice_close(p);
  return 0;
}
