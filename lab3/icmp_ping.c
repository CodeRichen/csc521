// icmp_ping.c
// compile: gcc -o icmp_ping icmp_ping.c -Wall
// run: sudo ./icmp_ping 140.127.208.18

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// 計算 checksum（標準 RFC 1071）
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        // 如果長度為奇數，最後一個 byte 要處理
        unsigned short tmp = 0;
        *((unsigned char *)&tmp) = *((unsigned char *)buf);
        sum += tmp;
    }
    // fold 32-bit sum to 16 bits: add carrier
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IPv4 address>\n", argv[0]);
        return 1;
    }

    const char *dest_ip = argv[1];

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        fprintf(stderr, "需要 root 或 CAP_NET_RAW 權限\n");
        exit(1);
    }

    // 設定 recv 超時（1 秒）
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        // not fatal, 繼續
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", dest_ip);
        close(sock);
        return 1;
    }

    // 準備 ICMP Echo Request
    char sendbuf[64];
    memset(sendbuf, 0, sizeof(sendbuf));
    struct icmphdr *icmp = (struct icmphdr *)sendbuf;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(1);

    // payload 放入發送時間（用來計算 RTT）
    struct timeval t1;
    gettimeofday(&t1, NULL);
    memcpy(sendbuf + sizeof(struct icmphdr), &t1, sizeof(t1));
    int packet_len = sizeof(struct icmphdr) + sizeof(t1);

    icmp->checksum = 0;
    icmp->checksum = checksum(sendbuf, packet_len);

    ssize_t sent = sendto(sock, sendbuf, packet_len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    // 接收回覆
    char recvbuf[1500];
    memset(recvbuf, 0, sizeof(recvbuf));
    ssize_t recvd = recv(sock, recvbuf, sizeof(recvbuf), 0);
    if (recvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("timeout, no reply received within 1 second\n");
        } else {
            perror("recv");
        }
        close(sock);
        return 1;
    }

    // 解析收到的 IP header + ICMP
    struct ip *ip_hdr = (struct ip *)recvbuf;
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    if (recvd < ip_hdr_len + (int)sizeof(struct icmphdr)) {
        fprintf(stderr, "packet too short (%zd bytes)\n", recvd);
        close(sock);
        return 1;
    }

    struct icmphdr *icmp_r = (struct icmphdr *)(recvbuf + ip_hdr_len);

    // 檢查是否為 Echo Reply 且 id 匹配
    if (icmp_r->type == ICMP_ECHOREPLY &&
        icmp_r->un.echo.id == htons(getpid() & 0xFFFF)) {

        // 取得 payload 中的時間戳（請注意 bounds）
        if (ip_hdr_len + sizeof(struct icmphdr) + (int)sizeof(struct timeval) <= recvd) {
            struct timeval t_sent;
            memcpy(&t_sent, recvbuf + ip_hdr_len + sizeof(struct icmphdr), sizeof(t_sent));
            struct timeval t_now;
            gettimeofday(&t_now, NULL);

            long sec = t_now.tv_sec - t_sent.tv_sec;
            long usec = t_now.tv_usec - t_sent.tv_usec;
            if (usec < 0) {
                sec -= 1;
                usec += 1000000;
            }
            double rtt_ms = sec * 1000.0 + usec / 1000.0;
            char src[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src, sizeof(src));
            printf("Reply from %s: seq=%d, RTT = %.3f ms\n",
                   src, ntohs(icmp_r->un.echo.sequence), rtt_ms);
        } else {
            printf("Received echo reply, but no timestamp payload to compute RTT\n");
        }
    } else {
        printf("Received ICMP type=%d code=%d (not echo-reply for us)\n",
               icmp_r->type, icmp_r->code);
    }

    close(sock);
    return 0;
}
