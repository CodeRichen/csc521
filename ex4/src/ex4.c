#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "common.h"
#include "dns.h"
#include "icmp.h"
#include "mypcap.h"
#include "tcp.h"

/**
 * main_proc() - the main thread
 **/
int main_proc(mypcap_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

#if (FG_ARP_SEND_REQUEST == 1)
  arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */

#if (FG_DNS_QUERY == 1)
  ip = resolve(p, defdnsquery);
  printf("%s\t%s\n", defdnsquery, ip_addrstr((uint8_t *)&ip, NULL));
#if (FG_ICMP_SEND_REQUEST == 1)
  icmp_ping(p, (uint8_t *)&ip);
#endif  // FG_ICMP_SEND_REQUEST
#endif  // FG_DNS_QUERY

  /* Read the packets */
  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (mypcap_proc(p) == -1) {
      break;
    }

    /*----------------------------------*
     * Other works can be inserted here *
     *----------------------------------*/

    /* key pressed? */
    if (!readready()) continue;
    if ((key = fgetc(stdin)) == '\n') break;
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
    trimright(buf);
    if ((ip = retrieve_ip_addr(buf)) != 0 || (ip = resolve(p, buf)) != 0) {
#if (FG_DNS_DO_PING == 1)
      icmp_ping(p, (uint8_t *)&ip);
#else
      printf("%s\t%s\n", buf, ip_addrstr(ip, NULL));
#endif /* FG_DNS_DO_PING */
    } else {
      printf("Invalid IP (Enter to exit)\n");
    }
  }

  return 0;
}

/****
 ****	MAIN ENTRY
 ****/

int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  mypcap_t *p;

  /*
   * Get the device name of capture interface
   */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (mypcap_getdevice(0, devname) == MYPCAP_ERR) {
    return -1;
  }

  /*
   * Open the specified interface
   */
  if ((p = mypcap_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  /*
   * Register the packet handler callback of specific protocol
   */
  mypcap_add_prot(p, ETH_ARP, (mypcap_handler)&arp_main);
  mypcap_add_prot(p, ETH_IP, (mypcap_handler)&ip_main);

  main_proc(p);

  /*
   * Clean up the resources
   */
  mypcap_close(p);
}