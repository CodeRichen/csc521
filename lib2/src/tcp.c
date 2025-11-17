#include "tcp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "util.h"

#if (DEBUG_TCP == 1)
static char *tcp_flagstr(uint8_t flags) {
  static char buf[7];
  buf[0] = ((flags & TCP_FG_URT) != 0) ? 'U' : '-';
  buf[1] = ((flags & TCP_FG_ACK) != 0) ? 'A' : '-';
  buf[2] = ((flags & TCP_FG_PSH) != 0) ? 'P' : '-';
  buf[3] = ((flags & TCP_FG_RST) != 0) ? 'R' : '-';
  buf[4] = ((flags & TCP_FG_SYN) != 0) ? 'S' : '-';
  buf[5] = ((flags & TCP_FG_FIN) != 0) ? 'F' : '-';
  buf[6] = '\0';
  return buf;
}
#endif

static tcp_raw_handler raw_handler = NULL;

// ===== 儲存每個連接的 sequence number =====
typedef struct {
  uint16_t local_port;
  uint16_t remote_port;
  uint32_t seq;
} tcp_conn_t;

#define MAX_CONNECTIONS 256
static tcp_conn_t connections[MAX_CONNECTIONS];
static int conn_count = 0;

// 儲存 sequence number
void tcp_store_seq(uint16_t local_port, uint16_t remote_port, uint32_t seq) {
  // 檢查是否已存在
  for (int i = 0; i < conn_count; i++) {
    if (connections[i].local_port == local_port && 
        connections[i].remote_port == remote_port) {
      connections[i].seq = seq;
      return;
    }
  }
  
  // 新增
  if (conn_count < MAX_CONNECTIONS) {
    connections[conn_count].local_port = local_port;
    connections[conn_count].remote_port = remote_port;
    connections[conn_count].seq = seq;
    conn_count++;
  }
}

// 取得 sequence number
uint32_t tcp_get_seq(uint16_t local_port, uint16_t remote_port) {
  for (int i = 0; i < conn_count; i++) {
    if (connections[i].local_port == local_port && 
        connections[i].remote_port == remote_port) {
      return connections[i].seq;
    }
  }
  return 0;
}

static uint16_t tcp_checksum(myip_param_t *ip_param, uint8_t *pkt, int tcplen) {
  mytcp_hdr_t *tcp_hdr = (mytcp_hdr_t *)pkt;
  uint16_t oldchksum, newchksum;
  uint16_t *srcip2, *dstip2;
  uint32_t sum;

  /* Pseudo header checksum */
  srcip2 = (uint16_t *)ip_param->srcip;
  dstip2 = (uint16_t *)ip_param->dstip;
  sum = swap16(*srcip2) + swap16(*(srcip2 + 1));
  sum += swap16(*dstip2) + swap16(*(dstip2 + 1));
  sum += ip_param->protocol + tcplen;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);

  /* TCP packet checksum */
  oldchksum = tcp_hdr->chksum;
  tcp_hdr->chksum = swap16((uint16_t)sum);
  newchksum = checksum(pkt, tcplen);
  tcp_hdr->chksum = oldchksum;

  return newchksum;
}

void tcp_set_raw_handler(tcp_raw_handler callback) { 
  raw_handler = callback; 
}

void tcp_main(netdevice_t *p, uint8_t *pkt, int len) {
  myip_hdr_t *ip_hdr;
  mytcp_hdr_t *tcp_hdr;
  int ip_hdr_len, tcp_hdr_len;

  ip_hdr = (myip_hdr_t *)pkt;
  ip_hdr_len = hlen(ip_hdr) * 4;
  
  uint8_t *tcp_segment = pkt + ip_hdr_len;
  int tcp_total_len = len - ip_hdr_len;
  
  pkt += ip_hdr_len;
  len -= ip_hdr_len;

  tcp_hdr = (mytcp_hdr_t *)pkt;
  tcp_hdr_len = ((tcp_hdr->hlen) >> 2) & 0x3C;
  
  if (tcp_hdr_len < 20 || tcp_hdr_len > 60 || tcp_hdr_len > len) {
    return;
  }
  
  pkt += tcp_hdr_len;
  len -= tcp_hdr_len;

#if (DEBUG_TCP == 1)
  myip_param_t ip_param;
  COPY_IPV4_ADDR(ip_param.srcip, ip_hdr->srcip);
  COPY_IPV4_ADDR(ip_param.dstip, ip_hdr->dstip);
  ip_param.protocol = ip_hdr->protocol;
  
  uint16_t calc_chk = tcp_checksum(&ip_param, tcp_segment, tcp_total_len);
  uint16_t recv_chk = tcp_hdr->chksum;

  uint16_t srcport = swap16(tcp_hdr->srcport);
  uint16_t dstport = swap16(tcp_hdr->dstport);

  printf("TCP %s: %d->%d, Len=%d, Seq=%u, Ack=%u, chksum=%04x/%04x",
         tcp_flagstr(tcp_hdr->flags), srcport, dstport, tcp_total_len,
         swap32(tcp_hdr->seq), swap32(tcp_hdr->ack),
         recv_chk, calc_chk);
  
  if (calc_chk != recv_chk) {
    printf(" ⚠MISMATCH");
  }
  printf("\n");
#endif

#if (DEBUG_TCP_DUMP == 1)
  print_data((uint8_t *)tcp_hdr, tcp_hdr_len);
#endif

  if (raw_handler) {
    (*raw_handler)(ip_hdr, tcp_hdr, pkt, len);
  }
}

static uint32_t generate_isn(void) {
  static int initialized = 0;
  if (!initialized) {
    srand(time(NULL));
    initialized = 1;
  }
  return (uint32_t)rand();
}

void tcp_syn(netdevice_t *p, mytcp_param_t tcp_param, uint8_t *payload,
             int payload_len) {
  int hdr_len = sizeof(mytcp_hdr_t);
  int pkt_len = payload_len + hdr_len;
  uint8_t pkt[pkt_len];
  mytcp_hdr_t *tcp_hdr = (mytcp_hdr_t *)pkt;
  myip_param_t *ip_param;

  ip_param = &tcp_param.ip;
  ip_param->protocol = IP_PROTO_TCP;
  COPY_IPV4_ADDR(ip_param->srcip, myipaddr);

  tcp_hdr->srcport = swap16(tcp_param.srcport);
  tcp_hdr->dstport = swap16(tcp_param.dstport);
  
  // 產生並儲存 sequence number
  uint32_t seq = generate_isn();
  tcp_hdr->seq = swap32(seq);
  
  // 儲存以便後續驗證
  tcp_store_seq(tcp_param.srcport, tcp_param.dstport, seq);
  
  tcp_hdr->ack = 0;
  tcp_hdr->hlen = TCP_MIN_HLEN;
  tcp_hdr->flags = TCP_FG_SYN;
  tcp_hdr->window = swap16(TCP_DEF_WINDOW);
  tcp_hdr->urgent = 0;
  tcp_hdr->chksum = tcp_checksum(ip_param, pkt, pkt_len);

  if (payload_len > 0) {
    memcpy(pkt + sizeof(mytcp_hdr_t), payload, payload_len);
  }

#if (DEBUG_TCP)
  printf("tcp_syn(): %d->%s:%d, %s Len=%d, Seq=%u, chksum=%04x\n",
         (int)tcp_param.srcport, ip_addrstr(ip_param->dstip, NULL),
         (int)tcp_param.dstport, tcp_flagstr(tcp_hdr->flags), pkt_len,
         seq, tcp_hdr->chksum);
#endif

#if (DEBUG_TCP_DUMP == 1)
  print_data((uint8_t *)pkt, pkt_len);
#endif

  ip_send(p, ip_param, pkt, pkt_len);
}

/*
 * tcp_send_syn_with_seq(): same as tcp_syn but allows caller to set initial
 * sequence number. Useful for SYN scanners that use unique SEQ per probe.
 */
void tcp_send_syn_with_seq(netdevice_t *p, mytcp_param_t tcp_param,
                           uint8_t *payload, int payload_len, uint32_t seq) {
  int hdr_len = sizeof(mytcp_hdr_t);
  int pkt_len = payload_len + hdr_len;
  uint8_t pkt[pkt_len];
  mytcp_hdr_t *tcp_hdr = (mytcp_hdr_t *)pkt;
  myip_param_t *ip_param;

  ip_param = &tcp_param.ip;
  ip_param->protocol = IP_PROTO_TCP;
  COPY_IPV4_ADDR(ip_param->srcip, myipaddr);

  tcp_hdr->srcport = swap16(tcp_param.srcport);
  tcp_hdr->dstport = swap16(tcp_param.dstport);
  tcp_hdr->seq = swap32(seq);

  /* store seq for validation */
  tcp_store_seq(tcp_param.srcport, tcp_param.dstport, seq);

  tcp_hdr->ack = 0;
  tcp_hdr->hlen = TCP_MIN_HLEN;
  tcp_hdr->flags = TCP_FG_SYN;
  tcp_hdr->window = swap16(TCP_DEF_WINDOW);
  tcp_hdr->urgent = 0;
  tcp_hdr->chksum = tcp_checksum(ip_param, pkt, pkt_len);

  if (payload_len > 0) {
    memcpy(pkt + sizeof(mytcp_hdr_t), payload, payload_len);
  }

#if (DEBUG_TCP)
  printf("tcp_send_with_seq(): %d->%s:%d, %s Len=%d, seq=%u, chksum=%04x\n",
         (int)tcp_param.srcport, ip_addrstr(ip_param->dstip, NULL),
         (int)tcp_param.dstport, tcp_flagstr(tcp_hdr->flags), pkt_len,
         (unsigned int)seq, tcp_hdr->chksum);
#endif

  ip_send(p, ip_param, pkt, pkt_len);
}