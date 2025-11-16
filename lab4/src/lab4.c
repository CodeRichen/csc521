#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "dns.h"
#include "icmp.h"
#include "netdevice.h"
#include "tcp.h"
#include "util.h"

extern char *defdnsquery;          // 預設 DNS 查詢的主機名稱（例如 csie.nuk.edu.tw）
extern uint16_t tcp_filter_port;   // 預設要監聽或過濾的 TCP port

/**
 * 當有 TCP 封包被捕獲時的 callback handler
 * 會在 tcp_main() → tcp_set_raw_handler() 被呼叫時註冊
 */
void rcvd_raw_tcp(myip_hdr_t *ip_hdr, mytcp_hdr_t *tcp_hdr, uint8_t *data,
                  int len) {
  // 若目標 port 不是指定的 tcp_filter_port，則忽略該封包
  if (swap16(tcp_hdr->dstport) != tcp_filter_port) return;

  // 如果封包是 TCP 的 SYN + ACK
  if (tcp_hdr->flags & TCP_FG_SYN && tcp_hdr->flags & TCP_FG_ACK) {
    printf("Received SYN-ACK from %s:%d\n", ip_addrstr(ip_hdr->srcip, NULL),
           swap16(tcp_hdr->srcport));
  }

  // 如果封包是 TCP 的 RST（重置）
  if (tcp_hdr->flags & TCP_FG_RST) {
    printf("Received RST from %s:%d\n", ip_addrstr(ip_hdr->srcip, NULL),
           swap16(tcp_hdr->srcport));
  }
}

/**
 * main_proc() - 主執行緒
 * 負責：
 *   1. 傳送 ARP/DNS/ICMP/TCP 請求
 *   2. 從網卡讀取封包
 *   3. 根據鍵盤輸入發送 ping 或 DNS 查詢
 */
int main_proc(netdevice_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

  /* =============================
   * 1️⃣ 送出 ARP Request
   * ============================= */
#if (FG_ARP_SEND_REQUEST == 1)
  arp_request(p, NULL);  // 若開啟該 flag，會對預設 IP 傳送 ARP request
#endif /* FG_ARP_REQUEST */

  /* =============================
   * 2️⃣ 執行 DNS 查詢與 TCP/ICMP 測試
   * ============================= */
#if (FG_DNS_QUERY == 1)
  // 向 DNS 伺服器查詢 defdnsquery (如 csie.nuk.edu.tw)
  ip = resolve(p, defdnsquery);
  printf("main_proc(): %s = %s\n", defdnsquery,
         ip_addrstr((uint8_t *)&ip, NULL));

#if (FG_ICMP_SEND_REQUEST == 1)
  // 執行 ICMP ping
  icmp_ping(p, (uint8_t *)&ip);
#endif  // FG_ICMP_SEND_REQUEST

#if (FG_TCP_SEND_SYN == 1)
  // 嘗試建立 TCP 連線（只送 SYN）
  mytcp_param_t tcp_param;
  COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&ip);  // 設定目標 IP
  tcp_param.srcport = tcp_filter_port;  // 本機來源 port
  tcp_param.dstport = 80;               // HTTP 預設 port

  tcp_syn(p, tcp_param, NULL, 0);       // 傳送 SYN 封包
#endif  // FG_TCP_SEND_SYN
#endif  // FG_DNS_QUERY

  /* =============================
   * 3️⃣ 持續讀取封包（主迴圈）
   * ============================= */
  while (1) {
    /*
     * 處理封包緩衝區中收到的封包
     */
    if (netdevice_rx(p) == -1) {
      break;  // 若接收錯誤則離開
    }

    /*----------------------------------*
     * 可以在此區插入其他自訂任務
     *----------------------------------*/

    /* 使用者是否按下鍵盤輸入 */
    if (!readready()) continue;
    if ((key = fgetc(stdin)) == '\n') break;  // 按下 Enter 離開
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
    trimright(buf);  // 移除換行字元

    // 嘗試將輸入的文字解析為 IP 或主機名稱
    if ((ip = retrieve_ip_addr(buf)) != 0 || (ip = resolve(p, buf)) != 0) {
      printf("main_proc(): %s = %s\n", buf, ip_addrstr((uint8_t *)&ip, NULL));

#if (FG_DNS_DO_PING == 1)
      icmp_ping(p, (uint8_t *)&ip);
#endif  // FG_DNS_DO_PING

#if (FG_TCP_SEND_SYN == 1)
      // 若定義開啟 TCP 功能則發送 SYN
      mytcp_param_t tcp_param;
      COPY_IPV4_ADDR(tcp_param.ip.dstip, (uint8_t *)&ip);
      tcp_param.srcport = tcp_filter_port;
      tcp_param.dstport = 80;
      tcp_syn(p, tcp_param, NULL, 0);
#endif  // FG_TCP_SEND_SYN
    } else {
      printf("Invalid IP (Enter to exit)\n");
    }
  }

  return 0;
}

/****
 **** MAIN ENTRY（程式進入點）
 ****/
int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  netdevice_t *p;

  /*
   * 取得網卡名稱 (ex: enp0s3)
   */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
    return -1;
  }
  load_network_config(devname);
  /*
   * 開啟指定網卡介面
   */
  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  /*
   * 註冊各種協定封包處理 callback
   */
  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);  // 處理 ARP 封包
  netdevice_add_proto(p, ETH_IP, (ptype_handler)&ip_main);    // 處理 IP 封包
  tcp_set_raw_handler((tcp_raw_handler)&rcvd_raw_tcp);        // 設定 TCP raw handler

  // 進入主要封包處理流程
  main_proc(p);

  /*
   * 收尾動作，關閉裝置
   */
  netdevice_close(p);
}
