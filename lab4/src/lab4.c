#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "dns.h"
#include "icmp.h"
#include "netdevice.h"
#include "tcp.h"
#include "util.h"

extern char *defdnsquery;
extern uint16_t tcp_filter_port;

/**
 * 🔧 改進：完整的 TCP callback handler
 */
void rcvd_raw_tcp(myip_hdr_t *ip_hdr, mytcp_hdr_t *tcp_hdr, uint8_t *data,
                  int len) {
  if (swap16(tcp_hdr->dstport) != tcp_filter_port) return;

  uint16_t remote_port = swap16(tcp_hdr->srcport);
  char *remote_ip = ip_addrstr(ip_hdr->srcip, NULL);

  // SYN-ACK: 三向交握的第二步
  if ((tcp_hdr->flags & TCP_FG_SYN) && (tcp_hdr->flags & TCP_FG_ACK)) {
    printf("✓ Received SYN-ACK from %s:%d\n", remote_ip, remote_port);
    printf("  Server is LISTENING and ready to accept connection\n");
  }
  // RST: 連線被拒絕
  else if (tcp_hdr->flags & TCP_FG_RST) {
    printf("✗ Received RST from %s:%d\n", remote_ip, remote_port);
    printf("  Port is CLOSED or connection rejected\n");
  }
  // FIN: 對方關閉連線
  else if (tcp_hdr->flags & TCP_FG_FIN) {
    printf("→ Received FIN from %s:%d\n", remote_ip, remote_port);
    printf("  Remote side closing connection\n");
  }
  // 純 ACK
  else if ((tcp_hdr->flags & TCP_FG_ACK) && !(tcp_hdr->flags & TCP_FG_SYN)) {
    // 一般不印出純 ACK，因為會有很多
  }
  // PSH: 有資料推送
  else if (tcp_hdr->flags & TCP_FG_PSH) {
    printf("→ Received data from %s:%d (%d bytes)\n", 
           remote_ip, remote_port, len);
  }
}

/**
 * 🔧 改進：加入更好的錯誤處理與提示
 */
int main_proc(netdevice_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

  printf("\n=== Network Stack Initialization ===\n");

  /* ARP Request */
#if (FG_ARP_SEND_REQUEST == 1)
  printf("→ Sending ARP request...\n");
  arp_request(p, NULL);
#endif

  /* DNS Query & Tests */
#if (FG_DNS_QUERY == 1)
  printf("→ Resolving DNS: %s\n", defdnsquery);
  ip = resolve(p, defdnsquery);
  
  if (ip == 0) {
    printf("✗ DNS resolution FAILED for %s\n", defdnsquery);
    printf("  Possible reasons:\n");
    printf("  1. Domain does not exist\n");
    printf("  2. DNS server is unreachable\n");
    printf("  3. No A record for this domain (might have only AAAA/CNAME)\n");
    printf("  \n");
    printf("  Suggestion: Try a different domain (e.g., google.com, nuk.edu.tw)\n");
  } else {
    printf("✓ Resolved: %s = %s\n", defdnsquery,
           ip_addrstr((uint8_t *)&ip, NULL));

#if (FG_ICMP_SEND_REQUEST == 1)
    printf("→ Sending ICMP ping to %s\n", ip_addrstr((uint8_t *)&ip, NULL));
    icmp_ping(p, (uint8_t *)&ip);
#endif

#if (FG_TCP_SEND_SYN == 1)
    printf("→ Attempting TCP connection to %s:80\n",
           ip_addrstr((uint8_t *)&ip, NULL));
    
    mytcp_param_t tcp_param;
    COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&ip);
    tcp_param.srcport = tcp_filter_port;
    tcp_param.dstport = 80;

    tcp_syn(p, tcp_param, NULL, 0);
    printf("  Waiting for response...\n");
#endif
  }
#endif

  printf("\n=== Packet Capture Started ===\n");
  printf("Commands:\n");
  printf("  - Type IP or hostname to ping/connect\n");
  printf("  - Press Enter to exit\n");
  printf("\n");

  /* Main Loop */
  int packet_count = 0;
  while (1) {
    if (netdevice_rx(p) == -1) {
      fprintf(stderr, "✗ Error receiving packets\n");
      break;
    }
    packet_count++;

    /* Keyboard input */
    if (!readready()) continue;
    if ((key = fgetc(stdin)) == '\n') {
      printf("\n=== Exiting (processed %d packets) ===\n", packet_count);
      break;
    }
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
    trimright(buf);

    printf("\n→ Query: %s\n", buf);

    /* Resolve IP */
    if ((ip = retrieve_ip_addr(buf)) != 0) {
      printf("✓ Valid IP: %s\n", ip_addrstr((uint8_t *)&ip, NULL));
    } else if ((ip = resolve(p, buf)) != 0) {
      printf("✓ Resolved: %s = %s\n", buf, ip_addrstr((uint8_t *)&ip, NULL));
    } else {
      printf("✗ Failed to resolve: %s\n", buf);
      printf("  Check domain name or try direct IP address\n\n");
      continue;
    }

#if (FG_DNS_DO_PING == 1)
    printf("→ Pinging %s...\n", ip_addrstr((uint8_t *)&ip, NULL));
    icmp_ping(p, (uint8_t *)&ip);
#endif

#if (FG_TCP_SEND_SYN == 1)
    printf("→ TCP SYN to %s:80...\n", ip_addrstr((uint8_t *)&ip, NULL));
    mytcp_param_t tcp_param;
    COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&ip);
    tcp_param.srcport = tcp_filter_port;
    tcp_param.dstport = 80;
    tcp_syn(p, tcp_param, NULL, 0);
#endif
    printf("\n");
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  netdevice_t *p;

  /* Get device name */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
    fprintf(stderr, "✗ No network device found\n");
    return -1;
  }

  printf("Loading network configuration for %s...\n", devname);
  load_network_config(devname);

  /* Open device */
  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "✗ Failed to open %s\n  %s\n", devname, errbuf);
    return -1;
  }
  printf("✓ Capturing packets on interface %s\n", devname);

  /* Register protocol handlers */
  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main);
  tcp_set_raw_handler((tcp_raw_handler)&rcvd_raw_tcp);

  /* Main processing */
  int ret = main_proc(p);

  /* Cleanup */
  netdevice_close(p);
  printf("✓ Network device closed\n");

  return ret;
}