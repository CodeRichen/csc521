#include "config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdint.h>

uint8_t myethaddr[6] = {0};
uint8_t myipaddr[4]  = {0};
uint8_t defarpip[4]  = {0};

void load_network_config(const char *ifname) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    // 取得 MAC
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(myethaddr, ifr.ifr_hwaddr.sa_data, 6);
    } else {
        perror("ioctl(SIOCGIFHWADDR)");
    }

    // 取得 IP
    // if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
    //     struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    //     memcpy(myipaddr, &ipaddr->sin_addr, 4);
    // } else {
    //     perror("ioctl(SIOCGIFADDR)");
    // }
        myipaddr[0] = 192;
        myipaddr[1] = 168;
        myipaddr[2] = 55;
        myipaddr[3] = 15;

    close(fd);

    // 取得 Gateway (從 /proc/net/route)
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) {
        perror("fopen(/proc/net/route)");
        return;
    }

    char iface[IFNAMSIZ];
    unsigned long dest, gate;
    char buf[256];

    // 跳過標題
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp)) {
        if (sscanf(buf, "%s %lx %lx", iface, &dest, &gate) == 3) {
            if (strcmp(iface, ifname) == 0 && dest == 0) {
                // gateway 是小端序，要轉成正確順序
                defarpip[0] = gate & 0xFF;
                defarpip[1] = (gate >> 8) & 0xFF;
                defarpip[2] = (gate >> 16) & 0xFF;
                defarpip[3] = (gate >> 24) & 0xFF;
                break;
            }
        }
    }
    fclose(fp);

    // Debug 輸出
    printf("[CONFIG] MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
           myethaddr[0], myethaddr[1], myethaddr[2],
           myethaddr[3], myethaddr[4], myethaddr[5]);
    printf("[CONFIG] IP  = %d.%d.%d.%d\n",
           myipaddr[0], myipaddr[1], myipaddr[2], myipaddr[3]);
    printf("[CONFIG] GW  = %d.%d.%d.%d\n",
           defarpip[0], defarpip[1], defarpip[2], defarpip[3]);
}
