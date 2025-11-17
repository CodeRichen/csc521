    #include "config.h"
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <stdlib.h>

    /* ================================
    * 全域變數
    * ================================ */
    uint8_t myethaddr[6]  = {0};
    uint8_t myipaddr[4]   = {0};
    uint8_t myrouterip[4] = {0};
    uint8_t mynetmask[4]  = {0};
    uint8_t defarpip[4]   = {0};
    uint8_t defpingip[4]  = {140, 127, 208, 18};  // 系網預設目標

    uint8_t defdnsip[4]   = {8, 8, 8, 8};         // 預設 DNS
    char *defdnsquery     = "csie.nuk.edu.tw";  // 🔧 改為資工系網域
    uint16_t tcp_filter_port = 0x5515;  // 🔧 修正為學號末四碼

    /* ================================
    * 載入網卡設定
    * ================================ */
    void load_network_config(const char *ifname) {
        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            perror("socket");
            return;
        }

        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        // 取得 MAC
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(myethaddr, ifr.ifr_hwaddr.sa_data, 6);
        } else {
            perror("ioctl(SIOCGIFHWADDR)");
        }

        // 取得 IP
        if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
            struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
            memcpy(myipaddr, &ipaddr->sin_addr, 4);
        } else {
            perror("ioctl(SIOCGIFADDR)");
        }

        // 取得 Netmask
        if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
            struct sockaddr_in *netmask = (struct sockaddr_in *)&ifr.ifr_netmask;
            memcpy(mynetmask, &netmask->sin_addr, 4);
        } else {
            perror("ioctl(SIOCGIFNETMASK)");
        }

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

        fgets(buf, sizeof(buf), fp); // 跳過標題列

        while (fgets(buf, sizeof(buf), fp)) {
            if (sscanf(buf, "%s %lx %lx", iface, &dest, &gate) == 3) {
                if (strcmp(iface, ifname) == 0 && dest == 0) {
                    myrouterip[0] = gate & 0xFF;
                    myrouterip[1] = (gate >> 8) & 0xFF;
                    myrouterip[2] = (gate >> 16) & 0xFF;
                    myrouterip[3] = (gate >> 24) & 0xFF;
                    break;
                }
            }
        }
        fclose(fp);

        // 設定 defarpip = router
        memcpy(defarpip, myrouterip, 4);

        // Debug 輸出
        printf("[CONFIG] MAC  = %02x:%02x:%02x:%02x:%02x:%02x\n",
            myethaddr[0], myethaddr[1], myethaddr[2],
            myethaddr[3], myethaddr[4], myethaddr[5]);
        printf("[CONFIG] IP   = %d.%d.%d.%d\n",
            myipaddr[0], myipaddr[1], myipaddr[2], myipaddr[3]);
        printf("[CONFIG] MASK = %d.%d.%d.%d\n",
            mynetmask[0], mynetmask[1], mynetmask[2], mynetmask[3]);
        printf("[CONFIG] GW   = %d.%d.%d.%d\n",
            myrouterip[0], myrouterip[1], myrouterip[2], myrouterip[3]);
        printf("[CONFIG] defarpip  = %d.%d.%d.%d\n",
            defarpip[0], defarpip[1], defarpip[2], defarpip[3]);
        printf("[CONFIG] defpingip = %d.%d.%d.%d\n",
            defpingip[0], defpingip[1], defpingip[2], defpingip[3]);
        printf("[CONFIG] defdnsip  = %d.%d.%d.%d\n",
            defdnsip[0], defdnsip[1], defdnsip[2], defdnsip[3]);
        printf("[CONFIG] defdnsquery = %s\n", defdnsquery);
    }
