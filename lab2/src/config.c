#include <stdint.h>
   /*
    * The MAC address of your interface
    */
   uint8_t myethaddr[] = {0x00, 0x15, 0x5d, 0x61, 0x51, 0x8a};
   /*
    * The IP address of your interface (Sender protocol address)
    */
   uint8_t myipaddr[] = {192, 168, 55, 15}; // 學號末四碼5515
   /*
    * The default IP address to send ARP requests to
    */
   uint8_t defarpip[] = {192, 168, 55, 1};