
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ARP_ENTRIES 256

typedef struct {
    uint8_t ip[4];
    uint8_t eth[6];
    int valid;
} arp_entry_t;

static arp_entry_t arp_table[MAX_ARP_ENTRIES];
static int arp_count = 0;

/*
 * arptable_existed() - Check whether an IP address existed in the ARP table
 * \return The corresponding ethernet address. Return NULL if not found.
 */
uint8_t *arptable_existed(uint8_t *ipaddr) {
    for (int i = 0; i < arp_count; i++) {
        if (arp_table[i].valid && 
            memcmp(arp_table[i].ip, ipaddr, 4) == 0) {
            return arp_table[i].eth;
        }
    }
    return NULL;
}

/*
 * arptable_add() - Append a mapping of IP address to the ARP table
 */
void arptable_add(uint8_t *ip, uint8_t *eth) {
    // DEBUG: 確認函式被呼叫
    printf("[DEBUG] arptable_add() called for IP: %d.%d.%d.%d\n", 
           ip[0], ip[1], ip[2], ip[3]);
    
    // 檢查是否已存在
    if (arptable_existed(ip) != NULL) {
        printf("[DEBUG] IP already exists in table\n");
        return;
    }
    
    // 添加新條目
    if (arp_count < MAX_ARP_ENTRIES) {
        memcpy(arp_table[arp_count].ip, ip, 4);
        memcpy(arp_table[arp_count].eth, eth, 6);
        arp_table[arp_count].valid = 1;
        arp_count++;
        
        // 打印發現的機器
        printf("*** Found active machine: %d.%d.%d.%d -> %02x:%02x:%02x:%02x:%02x:%02x ***\n",
               ip[0], ip[1], ip[2], ip[3],
               eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);
    } else {
        printf("[DEBUG] ARP table full!\n");
    }
}

/*
 * arptable_print() - Print all entries in the ARP table
 */
void arptable_print(void) {
    printf("\n=== ARP Table ===\n");
    printf("Total active machines found: %d\n", arp_count);
    for (int i = 0; i < arp_count; i++) {
        if (arp_table[i].valid) {
            printf("%d.%d.%d.%d -> %02x:%02x:%02x:%02x:%02x:%02x\n",
                   arp_table[i].ip[0], arp_table[i].ip[1], 
                   arp_table[i].ip[2], arp_table[i].ip[3],
                   arp_table[i].eth[0], arp_table[i].eth[1], 
                   arp_table[i].eth[2], arp_table[i].eth[3], 
                   arp_table[i].eth[4], arp_table[i].eth[5]);
        }
    }
    printf("================\n\n");
}