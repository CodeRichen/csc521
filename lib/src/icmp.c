#include "icmp.h"

#include <stdio.h>
#include <string.h>

#include "ip.h"
#include "util.h"

static char *ICMP_TYPE[] = {"Echo Reply",
                            "1",
                            "2",
                            "Destination Unreachable",
                            "Source Quench",
                            "Redirect (Change a Route)",
                            "6",
                            "7",
                            "Echo Request",
                            "9",
                            "10",
                            "Time Exceeded for a Datagram",
                            "Parameter Problem on a Datagram",
                            "Timestamp Request",
                            "Timestamp Reply",
                            "Information Request",
                            "Information Reply",
                            "Address Mask Request",
                            "Address Mask Reply"};
#define N_ICMP_TYPE (sizeof(ICMP_TYPE) / sizeof(char *))

static char *ICMP_CODE[] = {
    "Network Unreachable",
    "Host Unreachable",
    "Protocol Unreachable",
    "Port Unreachable",
    "Fragmentation Needed and DF Set",
    "Source Route Failed",
    "Destination Network Unknown",
    "Destination Host Unknown",
    "Source Host Isolated",
    "Communication with Destination Network Administratively Prohibited",
    "Communication with Destination Host Administratively Prohibited",
    "Network Unreachable for Type of Service",
    "Host Unreachable for Type of Service"};
#define N_ICMP_CODE (sizeof(ICMP_CODE) / sizeof(char *))

/**
 * icmp_main() - The entry point to receive packets from the bottom layer.
 **/

void icmp_main(netdevice_t *p, uint8_t *pkt, int len) {
  myip_hdr_t *ip_hdr;
  myicmp_hdr_t *icmp_hdr;

  ip_hdr = (myip_hdr_t *)pkt;
  pkt += sizeof(myip_hdr_t);
  len -= sizeof(myip_hdr_t);

  icmp_hdr = (myicmp_hdr_t *)pkt;

#if (DEBUG_ICMP == 1)
  printf("%4d ICMP ", len);
#endif /* DEBUG_ICMP == 1 */

  print_ip(ip_hdr->srcip, "->");
  print_ip(ip_hdr->dstip, ": ");

  if (icmp_hdr->type >= N_ICMP_TYPE) {
    printf("[Bad Type %d] ", icmp_hdr->type);
  } else {
    printf("[%s] ", ICMP_TYPE[icmp_hdr->type]);
  }

  switch (icmp_hdr->type) {
    case ICMP_TYPE_ECHO_REP:
      /* 檢查 identifier 是否為我們設定的 0x5515（network byte order 處理） */
      if (ntohs(icmp_hdr->id) == 0x5515) {
        printf("Echo Reply (id=0x5515) - Host alive: ");
        print_ip(ip_hdr->srcip, "\n");
      } else {
        /* 不是我們的掃描回覆，也印出基本資訊 */
        printf("Echo Reply (id=0x%04x)\n", ntohs(icmp_hdr->id));
      }
#if (DEBUG_ICMP_DUMP == 1)
      print_data((uint8_t *)icmp_hdr, len);
#endif
      break;

    case ICMP_TYPE_ECHO_REQ:
      /* 若需要對別人的 echo request 做回覆，可在此處加入回應程式碼 */
      printf("\n");
#if (DEBUG_ICMP_DUMP == 1)
      print_data((uint8_t *)icmp_hdr, len);
#endif
      break;

    case ICMP_TYPE_DST_UN:
    case ICMP_TYPE_REDIR:
    case ICMP_TYPE_TIME_EXCD:
    default:
      if (icmp_hdr->code >= N_ICMP_CODE)
        printf("Bad Code(%02x)\n", (int)icmp_hdr->code);
      else
        printf("%s\n", ICMP_CODE[icmp_hdr->code]);
  }
}

/**
 * icmp_ping() - To send a ICMP echo request to the desired IP address.
 **/
void icmp_ping(netdevice_t *p, uint8_t *dstip) {
  uint8_t pktbuf[MAX_IP_PAYLOAD_LEN];
  myicmp_hdr_t *icmp_hdr = (myicmp_hdr_t *)pktbuf;
  myip_param_t ip_param;
  int len;

  if (dstip == NULL) dstip = defpingip;

#if (DEBUG_ICMP == 1)
  printf("icmp_ping(): Ping %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ICMP */

  SET_IP(ip_param.dstip, dstip);
  SET_IP(ip_param.srcip, myipaddr);
  ip_param.protocol = IP_PROTO_ICMP; /* 0x01 */

  /* 構造 ICMP Echo Request */
  memset(pktbuf, 0, sizeof(pktbuf));
  icmp_hdr->type = ICMP_TYPE_ECHO_REQ;
  icmp_hdr->code = 0;
  icmp_hdr->chksum = 0x0000;

  /* 設定 Identifier 為 0x5515（使用 network byte order）*/
  icmp_hdr->id = htons(0x5515);

  /* sequence 可從 0 開始，若要每次不同可做遞增（使用 htons） */
  icmp_hdr->seq = htons(0x0000);

  len = sizeof(myicmp_hdr_t);
  icmp_hdr->chksum = checksum((uint8_t *)icmp_hdr, len);
  ip_send(p, &ip_param, pktbuf, len);
}

