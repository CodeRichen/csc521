#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arp.h"
#include "netdevice.h"
#include "util.h"
#include "config.h"

// 外部函數聲明
void arptable_print(void);



/**
 * scan_next_ip() - 掃描下一個IP位址
 */

uint8_t base_ip[4] = {192, 168, 0, 1}; 
int subnet_size = 4094; // 2^12 - 2 (排掉 network 和 broadcast)

void scan_next_ip(netdevice_t *p) {
    static int offset = 1;
    if (offset > subnet_size) {
        printf("Network scan completed!\n");
        arptable_print();
        return;
    }

    uint8_t target_ip[4];
    target_ip[0] = 192;
    target_ip[1] = 168;
    target_ip[2] = 0 + ((offset >> 8) & 0xF); 
    target_ip[3] = (offset & 0xFF);
    
    printf("Scanning IP: %d.%d.%d.%d\n",
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

    arp_request(p, target_ip);
    offset++;
    
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100000000; // 0.1 秒 = 1e8 奈秒
    nanosleep(&ts, NULL);
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
    const char *iface = "eth0";  // 預設介面

    if (argc >= 2) {
        iface = argv[1];          // 使用者指定介面
    }

    load_network_config(iface);    // 自動讀取 MAC、IP、GW

    printf("Using interface: %s\n", iface);
    
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