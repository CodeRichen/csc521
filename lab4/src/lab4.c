#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "arp.h"
#include "dns.h"
#include "icmp.h"
#include "netdevice.h"
#include "tcp.h"
#include "util.h"
#include <arpa/inet.h>

// ===== 全域變數 =====
#define PORT_SCAN_START 1
#define PORT_SCAN_END 100
#define SCAN_TIMEOUT_SEC 3

typedef struct {
  uint16_t port;
  uint16_t local_port;
  uint32_t seq;
  int status;  // 0=waiting, 1=open, 2=closed, 3=filtered
  time_t sent_time;
} port_scan_t;

static port_scan_t scan_ports[PORT_SCAN_END + 1];
static ipaddr_t target_ip = 0;
static int total_responses = 0;

extern char *defdnsquery;

// ===== 檢查 IP 是否為目標 IP =====
static int is_target_ip(uint8_t *ip) {
  return memcmp(ip, &target_ip, 4) == 0;
}

// ===== TCP 回應處理 =====
void rcvd_raw_tcp(myip_hdr_t *ip_hdr, mytcp_hdr_t *tcp_hdr, uint8_t *data, int len) {
  // 只處理來自目標 IP 的封包
  if (!is_target_ip(ip_hdr->srcip)) {
    return;
  }
  
  uint16_t remote_port = swap16(tcp_hdr->srcport);
  uint16_t local_port = swap16(tcp_hdr->dstport);
  uint32_t ack_num = swap32(tcp_hdr->ack);
  
  // 檢查是否為我們掃描的 port
  if (remote_port < PORT_SCAN_START || remote_port > PORT_SCAN_END) {
    return;
  }
  
  port_scan_t *scan = &scan_ports[remote_port];
  
  // 驗證 local port
  if (scan->local_port != local_port) {
    return;
  }
  
  // 已經有結果了，不重複處理
  if (scan->status != 0) {
    return;
  }
  
  // 驗證 ACK number (應該等於我們發送的 SEQ + 1)
  if (ack_num != scan->seq + 1) {
    return;
  }
  
  // 判斷回應類型
  if ((tcp_hdr->flags & TCP_FG_SYN) && (tcp_hdr->flags & TCP_FG_ACK)) {
    // SYN-ACK: Port is OPEN
    scan->status = 1;
    total_responses++;
    printf("✓ Port %d → OPEN (SYN/ACK received)\n", remote_port);
    printf("  TCP -A--S-: %d -> %d\n", remote_port, local_port);
  } 
  else if (tcp_hdr->flags & TCP_FG_RST) {
    // RST or RST-ACK: Port is CLOSED
    scan->status = 2;
    total_responses++;
    printf("✗ Port %d → CLOSED (RST received)\n", remote_port);
    printf("  TCP -A-R--: %d -> %d\n", remote_port, local_port);
  }
}

// ===== 初始化掃描表 =====
void init_scan_table(void) {
  memset(scan_ports, 0, sizeof(scan_ports));
  for (int i = PORT_SCAN_START; i <= PORT_SCAN_END; i++) {
    scan_ports[i].port = i;
    scan_ports[i].local_port = 20000 + i;
    scan_ports[i].seq = 0;
    scan_ports[i].status = 0;
    scan_ports[i].sent_time = 0;
  }
}

// ===== 產生隨機 SEQ =====
static uint32_t generate_seq(uint16_t port) {
  return ((uint32_t)rand() << 16) ^ ((uint32_t)time(NULL) * 997) ^ (port * 1009);
}

// ===== 發送 TCP SYN 到指定 port =====
void send_tcp_syn_to_port(netdevice_t *p, ipaddr_t target, uint16_t port) {
  mytcp_param_t tcp_param;
  
  port_scan_t *scan = &scan_ports[port];
  scan->local_port = 20000 + port;
  scan->seq = generate_seq(port);
  scan->sent_time = time(NULL);
  
  COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&target);
  tcp_param.ip.protocol = IP_PROTO_TCP;
  /* srcip will be set by tcp layer */
  COPY_IPV4_ADDR(tcp_param.ip.srcip, myipaddr);

  tcp_param.srcport = scan->local_port;
  tcp_param.dstport = port;

  /* Use tcp helper to send SYN with custom SEQ so checksum is computed
   * consistently by tcp layer. */
  tcp_send_syn_with_seq(p, tcp_param, NULL, 0, scan->seq);
  printf("tcp_send(): %d->%s:%d, ----S- Seq=%u\n", tcp_param.srcport,
         ip_addrstr((uint8_t *)&target, NULL), tcp_param.dstport,
         (unsigned int)scan->seq);
}

// ===== 檢查 timeout 的 ports =====
void check_timeouts(void) {
  time_t now = time(NULL);
  for (int i = PORT_SCAN_START; i <= PORT_SCAN_END; i++) {
    port_scan_t *scan = &scan_ports[i];
    if (scan->status == 0 && scan->sent_time > 0) {
      if ((now - scan->sent_time) >= SCAN_TIMEOUT_SEC) {
        scan->status = 3;
        total_responses++;
        printf("⊘ Port %d → FILTERED (no response)\n", i);
      }
    }
  }
}

// ===== 等待 DNS 回應 =====
void wait_for_dns_response(netdevice_t *p, int timeout_sec) {
  time_t start = time(NULL);
  while ((time(NULL) - start) < timeout_sec) {
    netdevice_rx(p);
    if (target_ip != 0) {
      break;
    }
    usleep(10000);  // 10ms
  }
}

// ===== 主掃描流程 =====
int main_proc(netdevice_t *p) {
  printf("\n=== TCP Port Scanner ===\n");
  printf("Target: %s\n", defdnsquery);
  printf("Port range: %d-%d\n\n", PORT_SCAN_START, PORT_SCAN_END);

  // Step 1: DNS 解析
  printf("→ Resolving DNS...\n");
  /* If user provided a dotted IPv4 string, use it directly and skip DNS. */
  struct in_addr in;
  if (inet_pton(AF_INET, defdnsquery, &in) == 1) {
    target_ip = in.s_addr; /* network byte order */
  } else {
    target_ip = resolve(p, defdnsquery);
  }
  
  // 等待 DNS 回應
  if (target_ip == 0) {
    printf("  Waiting for DNS response...\n");
    wait_for_dns_response(p, 5);
  }
  
  if (target_ip == 0) {
    printf("✗ DNS resolution FAILED for %s\n", defdnsquery);
    printf("  Please check:\n");
    printf("  1. Domain name is correct\n");
    printf("  2. DNS server (8.8.8.8) is reachable\n");
    printf("  3. Network connectivity\n");
    return -1;
  }
  
  char *ip_str = ip_addrstr((uint8_t *)&target_ip, NULL);
  printf("✓ Resolved: %s = %s\n\n", defdnsquery, ip_str);

  // Step 2: 初始化掃描表
  init_scan_table();
  srand(time(NULL) ^ getpid());
  total_responses = 0;

  // Step 3: 發送 TCP SYN 到所有 ports
  printf("=== Starting Port Scan to %s ===\n", ip_str);
  printf("Sending SYN packets to ports %d-%d...\n\n", 
         PORT_SCAN_START, PORT_SCAN_END);
  
  for (int port = PORT_SCAN_START; port <= PORT_SCAN_END; port++) {
    send_tcp_syn_to_port(p, target_ip, port);
    
    // 每發送 10 個封包就處理一下接收
    if (port % 10 == 0) {
      for (int j = 0; j < 20; j++) {
        netdevice_rx(p);
        usleep(500);  // 0.5ms
      }
    }
  }

  printf("\n=== All %d SYN packets sent, waiting for responses ===\n\n", 
         PORT_SCAN_END - PORT_SCAN_START + 1);

  // Step 4: 持續監聽回應
  time_t start_time = time(NULL);
  time_t last_check = start_time;
  time_t last_progress = start_time;
  int expected_total = PORT_SCAN_END - PORT_SCAN_START + 1;
  
  while (1) {
    netdevice_rx(p);
    
    time_t now = time(NULL);
    
    // 每秒顯示進度
    if (now - last_progress >= 1) {
      printf("  [Progress: %d/%d responses received, %d sec elapsed]\n", 
             total_responses, expected_total, (int)(now - start_time));
      last_progress = now;
    }
    
    // 每秒檢查一次 timeout
    if (now - last_check >= 1) {
      check_timeouts();
      last_check = now;
    }
    
    // 檢查是否所有 port 都已完成
    if (total_responses >= expected_total) {
      printf("\n=== All ports responded ===\n");
      break;
    }
    
    // 總超時時間 (15 秒)
    if ((now - start_time) > 15) {
      printf("\n=== Scan timeout, finishing... ===\n");
      check_timeouts();
      break;
    }
    
    usleep(5000);  // 5ms
  }

  // Step 5: 顯示掃描結果摘要
  printf("\n========================================\n");
  printf("=== Scan Results Summary ===\n");
  printf("========================================\n");
  
  int open_count = 0, closed_count = 0, filtered_count = 0;
  
  printf("\n--- OPEN ports ---\n");
  for (int i = PORT_SCAN_START; i <= PORT_SCAN_END; i++) {
    if (scan_ports[i].status == 1) {
      printf("  %d/tcp  open\n", i);
      open_count++;
    }
  }
  if (open_count == 0) {
    printf("  (none)\n");
  }
  
  printf("\n--- CLOSED ports ---\n");
  int show_closed = 0;
  for (int i = PORT_SCAN_START; i <= PORT_SCAN_END; i++) {
    if (scan_ports[i].status == 2) {
      if (show_closed < 10) {  // 只顯示前 10 個
        printf("  %d/tcp  closed\n", i);
        show_closed++;
      }
      closed_count++;
    }
  }
  if (closed_count == 0) {
    printf("  (none)\n");
  } else if (closed_count > 10) {
    printf("  ... and %d more closed ports\n", closed_count - 10);
  }
  
  printf("\n--- FILTERED ports ---\n");
  int show_filtered = 0;
  for (int i = PORT_SCAN_START; i <= PORT_SCAN_END; i++) {
    if (scan_ports[i].status == 3) {
      if (show_filtered < 10) {  // 只顯示前 10 個
        printf("  %d/tcp  filtered\n", i);
        show_filtered++;
      }
      filtered_count++;
    }
  }
  if (filtered_count == 0) {
    printf("  (none)\n");
  } else if (filtered_count > 10) {
    printf("  ... and %d more filtered ports\n", filtered_count - 10);
  }
  
  printf("\n========================================\n");
  printf("Target: %s (%s)\n", defdnsquery, ip_str);
  printf("Total ports scanned: %d\n", PORT_SCAN_END - PORT_SCAN_START + 1);
  printf("Open:     %d\n", open_count);
  printf("Closed:   %d\n", closed_count);
  printf("Filtered: %d\n", filtered_count);
  printf("========================================\n");

  return 0;
}

// ===== main 函數 =====
int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  netdevice_t *p;
  if (argc >= 2) {
    strcpy(devname, argv[1]);
    /* Optional second argument: target domain or IP (overrides default defdnsquery) */
    if (argc >= 3) {
      defdnsquery = argv[2];
    }
  } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
    fprintf(stderr, "✗ No network device found\n");
    return -1;
  }

  printf("Loading network configuration for %s...\n", devname);
  load_network_config(devname);

  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "✗ Failed to open %s\n  %s\n", devname, errbuf);
    return -1;
  }
  printf("✓ Capturing packets on interface %s\n", devname);

  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main);
  tcp_set_raw_handler((tcp_raw_handler)&rcvd_raw_tcp);

  int ret = main_proc(p);

  netdevice_close(p);
  printf("\n✓ Network device closed\n");

  return ret;
}