from scapy.all import *

FAKE_IP = "192.168.0.39"
FAKE_MAC = "39:39:39:39:39:39"

print(f"[*] 模擬 {FAKE_IP} 回覆裝置啟動中 (MAC={FAKE_MAC})")

def handle_arp(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # who-has
        if pkt[ARP].pdst == FAKE_IP:
            target_ip = pkt[ARP].psrc
            target_mac = pkt[ARP].hwsrc
            print(f"[+] 已回覆 ARP 給 {target_ip}")

            ether = Ether(dst=target_mac, src=FAKE_MAC, type=0x806)
            arp_reply = ARP(
                op=2,  # is-at
                psrc=FAKE_IP,
                hwsrc=FAKE_MAC,
                pdst=target_ip,
                hwdst=target_mac
            )
            sendp(ether / arp_reply, verbose=False)

def handle_icmp(pkt):
    if pkt.haslayer(ICMP) and pkt[IP].dst == FAKE_IP and pkt[ICMP].type == 8:
        print(f"[+] 收到 ICMP echo 請求，回覆中...")
        ether = Ether(src=FAKE_MAC, dst=pkt[Ether].src)
        ip = IP(src=FAKE_IP, dst=pkt[IP].src)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load if pkt.haslayer(Raw) else b''
        sendp(ether / ip / icmp / data, verbose=False)

sniff(filter="arp or icmp", prn=lambda p: (handle_arp(p), handle_icmp(p)))
