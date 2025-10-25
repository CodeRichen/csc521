#include "arp.h"

#include <stdio.h>
#include <stdlib.h>

#include "ip.h"
#include "util.h"

const uint8_t eth_broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t eth_null_addr[] = {0, 0, 0, 0, 0, 0};

static const char *arp_op_str(uint16_t op);
static void arp_dump(myarp_t *arp);

/*
 * Per-IP Linked List Queue for Pending Packets
 */

typedef struct pending_packet {
  uint8_t payload[MAX_CAP_LEN];
  int len;
  uint16_t eth_type;
  struct pending_packet *next;
} pending_packet_t;

typedef struct ip_queue_entry {
  ipaddr_t dst_ip;
  pending_packet_t *packets;  // Linked list of pending packets
  struct ip_queue_entry *next;
} ip_queue_entry_t;

static ip_queue_entry_t *tosend_queue_head = NULL;

/**
 * find_ip_queue() - Find queue entry for a specific IP
 **/
static ip_queue_entry_t *find_ip_queue(ipaddr_t dst_ip) {
  ip_queue_entry_t *entry = tosend_queue_head;
  while (entry != NULL) {
    if (entry->dst_ip == dst_ip) {
      return entry;
    }
    entry = entry->next;
  }
  return NULL;
}

/**
 * enqueue_packet() - Add a packet to the queue for a specific IP
 **/
static void enqueue_packet(ipaddr_t dst_ip, uint16_t eth_type, 
                          uint8_t *payload, int payload_len) {
  ip_queue_entry_t *ip_entry = find_ip_queue(dst_ip);
  
  // Create IP entry if it doesn't exist
  if (ip_entry == NULL) {
    ip_entry = (ip_queue_entry_t *)malloc(sizeof(ip_queue_entry_t));
    if (ip_entry == NULL) {
      fprintf(stderr, "Failed to allocate memory for IP queue entry\n");
      return;
    }
    ip_entry->dst_ip = dst_ip;
    ip_entry->packets = NULL;
    ip_entry->next = tosend_queue_head;
    tosend_queue_head = ip_entry;
  }
  
  // Create new packet node
  pending_packet_t *pkt = (pending_packet_t *)malloc(sizeof(pending_packet_t));
  if (pkt == NULL) {
    fprintf(stderr, "Failed to allocate memory for pending packet\n");
    return;
  }
  
  pkt->len = payload_len;
  pkt->eth_type = eth_type;
  memcpy(pkt->payload, payload, payload_len);
  pkt->next = NULL;
  
  // Append to the end of packet list
  if (ip_entry->packets == NULL) {
    ip_entry->packets = pkt;
  } else {
    pending_packet_t *p = ip_entry->packets;
    while (p->next != NULL) {
      p = p->next;
    }
    p->next = pkt;
  }
  
#if (DEBUG_ARP == 1)
  printf("enqueue_packet(): Queued packet for IP %s (eth_type=%04x, len=%d)\n",
         ip_addrstr((uint8_t *)&dst_ip, NULL), swap16(eth_type), payload_len);
#endif
}

/**
 * dequeue_and_send_all() - Send all queued packets for a specific IP
 **/
static void dequeue_and_send_all(netdevice_t *p, ipaddr_t dst_ip) {
  ip_queue_entry_t *prev = NULL;
  ip_queue_entry_t *ip_entry = tosend_queue_head;
  
  // Find the IP entry
  while (ip_entry != NULL && ip_entry->dst_ip != dst_ip) {
    prev = ip_entry;
    ip_entry = ip_entry->next;
  }
  
  if (ip_entry == NULL) {
    return;  // No queued packets for this IP
  }
  
#if (DEBUG_ARP == 1)
  printf("dequeue_and_send_all(): Sending all queued packets for %s\n",
         ip_addrstr((uint8_t *)&dst_ip, NULL));
#endif
  
  // Send all packets for this IP
  pending_packet_t *pkt = ip_entry->packets;
  int count = 0;
  while (pkt != NULL) {
    pending_packet_t *next = pkt->next;
    
    // Send the packet
    uint8_t *eth_dst = arptable_existed((uint8_t *)&dst_ip);
    if (eth_dst != NULL) {
      eth_hdr_t eth_hdr;
      COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
      COPY_ETH_ADDR(eth_hdr.eth_dst, eth_dst);
      eth_hdr.eth_type = pkt->eth_type;
      
      if (netdevice_xmit(p, eth_hdr, pkt->payload, pkt->len) != 0) {
        fprintf(stderr, "Failed to send queued packet.\n");
      }
      count++;
    }
    
    free(pkt);
    pkt = next;
  }
  
#if (DEBUG_ARP == 1)
  printf("dequeue_and_send_all(): Sent %d packet(s)\n", count);
#endif
  
  // Remove the IP entry from the queue
  if (prev == NULL) {
    tosend_queue_head = ip_entry->next;
  } else {
    prev->next = ip_entry->next;
  }
  free(ip_entry);
}

/**
 * has_pending_packets() - Check if there are pending packets for an IP
 **/
static int has_pending_packets(ipaddr_t dst_ip) {
  ip_queue_entry_t *entry = find_ip_queue(dst_ip);
  return (entry != NULL && entry->packets != NULL);
}

/**
 * arp_request() - Send a ARP request for <IP> address
 **/
void arp_request(netdevice_t *p, uint8_t *ip) {
  eth_hdr_t eth_hdr;
  myarp_t pkt;

  if (ip == NULL) ip = defarpip;
  COPY_ETH_ADDR(eth_hdr.eth_dst, eth_broadcast_addr);
  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = ETH_ARP;

  pkt.ethtype = ARP_ETH_TYPE;
  pkt.iptype = ETH_IP;
  pkt.ethlen = ETH_ADDR_LEN;
  pkt.iplen = IPV4_ADDR_LEN;
  pkt.op = ARP_OP_REQUEST;
  COPY_ETH_ADDR(pkt.srceth, myethaddr);
  COPY_IPV4_ADDR(pkt.srcip, myipaddr);
  COPY_ETH_ADDR(pkt.dsteth, eth_null_addr);
  COPY_IPV4_ADDR(pkt.dstip, ip);

#if (DEBUG_ARP_REQUEST == 1)
  printf("arp_request() to %s\n", ip_addrstr(ip, NULL));
  arp_dump(&pkt);
#endif /* DEBUG_ARP_REQUEST */

  if (netdevice_xmit(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP request.\n");
  }
}

/**
 * arp_reply() - Reply the configured hardware address
 **/
void arp_reply(netdevice_t *p, uint8_t *dsteth, uint8_t *dstip) {
  eth_hdr_t eth_hdr;
  myarp_t pkt;

  COPY_ETH_ADDR(eth_hdr.eth_dst, dsteth);
  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = ETH_ARP;

  pkt.ethtype = ARP_ETH_TYPE;
  pkt.iptype = ETH_IP;
  pkt.ethlen = ETH_ADDR_LEN;
  pkt.iplen = IPV4_ADDR_LEN;
  pkt.op = ARP_OP_REPLY;
  COPY_ETH_ADDR(pkt.srceth, myethaddr);
  COPY_IPV4_ADDR(pkt.srcip, myipaddr);
  COPY_ETH_ADDR(pkt.dsteth, dsteth);
  COPY_IPV4_ADDR(pkt.dstip, dstip);

#if (DEBUG_ARP_REPLY == 1)
  printf("arp_reply() to %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ARP_REPLY */

  if (netdevice_xmit(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP reply.\n");
  }
}

/**
 * arp_main() - The handler for incoming APR packets
 **/
void arp_main(netdevice_t *p, uint8_t *pkt, unsigned int len) {
  myarp_t *arp;

  arp = (myarp_t *)pkt;

#if (DEBUG_ARP == 1)
  arp_dump(arp);
#endif /* DEBUG_ARP */

  /* ARP request to My IP: reply it */
  switch (arp->op) {
    case ARP_OP_REQUEST: /* ARP Request */
      if (memcmp(arp->dstip, myipaddr, IPV4_ADDR_LEN) == 0)
        arp_reply(p, arp->srceth, arp->srcip);
      break;

    case ARP_OP_REPLY: /* ARP Reply */
    {
      char s_srcip[BUFLEN_IP], s_dstip[BUFLEN_IP];
      char s_srceth[BUFLEN_ETH];
      printf("DEBUG: ARP REPLY raw: src=%s mac=%s -> dst=%s\n",
             ip_addrstr(arp->srcip, s_srcip), eth_macaddr(arp->srceth, s_srceth),
             ip_addrstr(arp->dstip, s_dstip));

      /* show derived values used in logic */
      ipaddr_t src_ip_u32 = GET_IP(arp->srcip);
      ipaddr_t dst_ip_u32 = GET_IP(arp->dstip);
      printf("DEBUG: GET_IP(src) = 0x%08x, GET_IP(dst) = 0x%08x\n",
             (unsigned)src_ip_u32, (unsigned)dst_ip_u32);

      if (IS_MY_IP(arp->dstip)) {
        printf("DEBUG: ARP reply is for me -> call arptable_add()\n");
        arptable_add(arp->srcip, arp->srceth);
      } else {
        printf("DEBUG: ARP reply NOT for me (dst != myip)\n");
      }

      // Check if we have pending packets for this source IP
      ipaddr_t replied_ip = GET_IP(arp->srcip);
      if (has_pending_packets(replied_ip)) {
        printf("DEBUG: ARP reply matches queued IP -> sending all queued packets\n");
        dequeue_and_send_all(p, replied_ip);
      }
    }
    break;

#if (DEBUG_ARP == 1)
    default:
      printf("unknown ARP opcode\n");
#endif /* DEBUG_ARP */
  }
}

/**
 * arp_send() - Send out packets from upper layer to the specificed destination
 * IP address.
 **/
void arp_send(netdevice_t *p, uint8_t *dst_ip, uint16_t eth_type, uint8_t *payload,
              int payload_len) {
  uint8_t *eth_dst;
  eth_hdr_t eth_hdr;

  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = eth_type;

  if ((eth_dst = arptable_existed(dst_ip)) != NULL) {
    /* Send directly if MAC available */
    COPY_ETH_ADDR(eth_hdr.eth_dst, eth_dst);
    if (netdevice_xmit(p, eth_hdr, payload, payload_len) != 0) {
      fprintf(stderr, "Failed to send.\n");
    }
#if (DEBUG_ARP == 1)
    printf("arp_send(): Packet sent to %s (%s) eth_type=%04x\n",
           ip_addrstr(dst_ip, NULL), eth_macaddr(eth_dst, NULL),
           swap16(eth_type));
#if (DEBUG_ARP_DUMP == 1)
    print_data(payload, payload_len);
#endif  // DEBUG_ARP_DUMP == 1
#endif  // DEBUG_ARP == 1
  } else {
#if (DEBUG_ARP == 1)
    printf(
        "arp_send(): MAC address of %s is unavailable. "
        "The outgoing packet is queued.\n",
        ip_addrstr(dst_ip, NULL));
#endif
    /* Put to the queue and request ARP if MAC unavailable */
    ipaddr_t dst_ip_u32 = GET_IP(dst_ip);
    
    // Check if we already sent an ARP request for this IP
    int first_packet = !has_pending_packets(dst_ip_u32);
    
    enqueue_packet(dst_ip_u32, eth_type, payload, payload_len);
    
    // Only send ARP request if this is the first packet for this IP
    if (first_packet) {
      arp_request(p, dst_ip);
    }
  }
}

/**
 * arp_resend() - Re-send the queued packet (deprecated, use dequeue_and_send_all)
 **/
void arp_resend(netdevice_t *p) {
  // This function is kept for backward compatibility but is no longer used
  // The new implementation automatically sends all queued packets when
  // an ARP reply is received in arp_main()
#if (DEBUG_ARP == 1)
  printf("arp_resend(): Called (deprecated function)\n");
#endif
}

/**
 * arp_op_str() - Convert the operation code to human-readable string
 **/
static const char *arp_op_str(uint16_t op) {
  switch (op) {
    case ARP_OP_REPLY:
      return "Reply";
    case ARP_OP_REQUEST:
      return "Request";
    default:
      return "Unknown";
  }
}

/**
 * arp_dump() - Format output the content of ARP packet
 **/
static void arp_dump(myarp_t *arp) {
  char srceth[BUFLEN_ETH], srcip[BUFLEN_IP];
  char dsteth[BUFLEN_ETH], dstip[BUFLEN_IP];
  printf(
      "ARP Eth=%04x/%d, IP=%04x/%d, Op=%04x(%s)\n"
      "\tFrom %s (%s)\n"
      "\tTo   %s (%s)\n",
      swap16(arp->ethtype), arp->ethlen, swap16(arp->iptype), arp->iplen,
      swap16(arp->op), arp_op_str(arp->op), eth_macaddr(arp->srceth, srceth),
      ip_addrstr(arp->srcip, srcip), eth_macaddr(arp->dsteth, dsteth),
      ip_addrstr(arp->dstip, dstip));
}