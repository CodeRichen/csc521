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

/*
 * 🔧 修正：Checksum 計算 - 不要對 checksum 本身做 swap16
 * 問題根源：checksum 欄位在網路中已經是 big-endian，
 * 但比對時錯誤地再次執行 swap16 導致字節順序相反
 */
static uint16_t tcp_checksum(myip_param_t *ip_param, uint8_t *pkt, int tcplen) {
  mytcp_hdr_t *tcp_hdr = (mytcp_hdr_t *)pkt;
  uint16_t oldchksum, newchksum;
  uint16_t *srcip2, *dstip2;
  uint32_t sum;

  /* checksum: pseudo header */
  srcip2 = (uint16_t *)ip_param->srcip;
  dstip2 = (uint16_t *)ip_param->dstip;
  sum = swap16(*srcip2) + swap16(*(srcip2 + 1));
  sum += swap16(*dstip2) + swap16(*(dstip2 + 1));
  sum += ip_param->protocol + tcplen;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);

  /* checksum: tcp packet */
  oldchksum = tcp_hdr->chksum;
  tcp_hdr->chksum = swap16((uint16_t)sum);
  newchksum = checksum(pkt, tcplen);
  tcp_hdr->chksum = oldchksum;

  return newchksum;
}

void tcp_set_raw_handler(tcp_raw_handler callback) { 
  raw_handler = callback; 
}

/*
 * 🔧 修正：TCP header length 驗證與 checksum 比對
 */
void tcp_main(netdevice_t *p, uint8_t *pkt, int len) {
  myip_hdr_t *ip_hdr;
  mytcp_hdr_t *tcp_hdr;
  int ip_hdr_len, tcp_hdr_len;

  ip_hdr = (myip_hdr_t *)pkt;
  ip_hdr_len = hlen(ip_hdr) * 4;
  
  // 保存完整的 TCP segment 用於 checksum 計算
  uint8_t *tcp_segment = pkt + ip_hdr_len;
  int tcp_total_len = len - ip_hdr_len;
  
  pkt += ip_hdr_len;
  len -= ip_hdr_len;

  tcp_hdr = (mytcp_hdr_t *)pkt;
  tcp_hdr_len = ((tcp_hdr->hlen) >> 2) & 0x3C;  // 🔧 修正：正確提取 header length
  
  // 🔧 修正：允許 header length 為 20-60 bytes（含 options）
  if (tcp_hdr_len < 20 || tcp_hdr_len > 60 || tcp_hdr_len > len) {
    printf("⚠ Invalid TCP header length: %d (total len=%d)\n", tcp_hdr_len, len);
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
  // 🔧 關鍵修正：不要對 checksum 做 swap，直接比較
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

/*
 * 產生隨機初始序號
 */
static uint32_t generate_isn(void) {
  static int initialized = 0;
  if (!initialized) {
    srand(time(NULL));
    initialized = 1;
  }
  return (uint32_t)rand();
}

/*
 * 🔧 修正：正確設定所有欄位
 */
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
  tcp_hdr->seq = swap32(generate_isn());
  tcp_hdr->ack = 0;
  tcp_hdr->hlen = TCP_MIN_HLEN;  // 🔧 使用原本的巨集定義
  tcp_hdr->flags = TCP_FG_SYN;
  tcp_hdr->window = swap16(TCP_DEF_WINDOW);
  tcp_hdr->urgent = 0;
  tcp_hdr->chksum = tcp_checksum(ip_param, pkt, pkt_len);

  if (payload_len > 0) {
    memcpy(pkt + sizeof(mytcp_hdr_t), payload, payload_len);
  }

#if (DEBUG_TCP)
  printf("tcp_syn(): %d->%s:%d, %s Len=%d, chksum=%04x\n",
         (int)tcp_param.srcport, ip_addrstr(ip_param->dstip, NULL),
         (int)tcp_param.dstport, tcp_flagstr(tcp_hdr->flags), pkt_len,
         tcp_hdr->chksum);
#endif

#if (DEBUG_TCP_DUMP == 1)
  print_data((uint8_t *)pkt, pkt_len);
#endif

  ip_send(p, ip_param, pkt, pkt_len);
}