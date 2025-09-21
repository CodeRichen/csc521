#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arp.h"
#include "netdevice.h"
#include "util.h"

// 外部函數聲明
void arptable_print(void);

// 全域變數用於追蹤掃描進度
static int current_ip_suffix = 1;
static int scan_complete = 0;
static time_t last_scan_time = 0;
static const int SCAN_INTERVAL = 1; // 每秒掃描一個IP

/**
 * scan_next_ip() - 掃描下一個IP位址
 */
void scan_next_ip(netdevice_t *p) {
    time_t current_time = time(NULL);
    
    // 控制掃描頻率
    if (current_time - last_scan_time < SCAN_INTERVAL) {
        return;
    }
    
    if (current_ip_suffix > 254) {
        if (!scan_complete) {
            printf("Network scan completed!\n");
            arptable_print();
            scan_complete = 1;
        }
        return;
    }
    
    // 構建目標IP位址 (192.168.55.x) - 與Sender protocol address同網段
    uint8_t target_ip[4] = {172, 19, 213, current_ip_suffix}; //todo
     
    printf("Scanning IP: %d.%d.%d.%d\n", 
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    
    // 發送ARP請求
    arp_request(p, target_ip);
    
    current_ip_suffix++;
    last_scan_time = current_time;
}

/**
 * main_proc() - The main body of this lab
 **/
int main_proc(netdevice_t *p) {
    int key;
    char buf[MAX_LINEBUF];
    ipaddr_t ip;
    
    printf("Starting ARP network discovery...\n");
    printf("Press Enter to stop and show results\n");
    printf("Or type an IP address to send specific ARP request\n\n");

#if (FG_ARP_SEND_REQUEST == 1)
    /*
     * Send ARP request to given default IP address
     */
    arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */

    while (1) {
        /*
         * Process packets in the capture buffer
         */
        if (netdevice_rx(p) == -1) {
            break;
        }
        
        /*----------------------------------*
         * ARP網路掃描 - 插入在這裡持續執行 *
         *----------------------------------*/
        scan_next_ip(p);
        
        /*
         * If key is not pressed, continue to next loop
         */
        if (!readready()) {
            continue;
        }
        
        /*
         * If user pressed enter, exit the program
         */
        if ((key = fgetc(stdin)) == '\n') {
            break;
        }
        
        ungetc(key, stdin);
        if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
            break;
        }
        
        if ((ip = retrieve_ip_addr(buf)) == 0) {
            printf("Invalid IP (Enter to exit)\n");
        } else {
            printf("Sending ARP request to specific IP: %s\n", buf);
            arp_request(p, (unsigned char *)&ip);
        }
    }
    
    // 程式結束前顯示最終結果
    printf("\nFinal scan results:\n");
    arptable_print();
    
    return 0;
}

int main(int argc, char *argv[]) {
    char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
    netdevice_t *p;
    
    printf("ARP Network Discovery Tool\n");
    printf("==========================\n");
    
    /*
     * Get the device name of capture interface
     */
    if (argc == 2) {
        strcpy(devname, argv[1]);
    } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
        return -1;
    }
    
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
    
    main_proc(p);
    
    /*
     * Clean up the resources
     */
    netdevice_close(p);
    return 0;
}