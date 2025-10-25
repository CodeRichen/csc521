from scapy.all import *

FAKE_IP = "192.168.0.39"
IFACE = "enp0s3"    # 改成你在 Get-NetAdapter 查到的介面名稱

print(f"[*] 模擬 {FAKE_IP} 裝置啟動中")

def handle_arp(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].pdst == FAKE_IP:
        print(f"[+] ARP from {pkt[ARP].psrc} asking {FAKE_IP}")
        target_mac = pkt[ARP].hwsrc
        target_ip = pkt[ARP].psrc
        fake_mac = get_if_hwaddr(IFACE)

        # 正確地建立乙太層 + ARP 封包
        ether = Ether(dst=target_mac, src=fake_mac, type=0x806)
        arp_reply = ARP(
            op=2,               # is-at
            hwsrc=fake_mac,
            psrc=FAKE_IP,
            hwdst=target_mac,
            pdst=target_ip
        )

        sendp(ether / arp_reply, iface=IFACE, verbose=False)
        print(f"  ↳ 已送出 ARP 回覆給 {target_ip} ({target_mac})")

def handle_icmp(pkt):
    if pkt.haslayer(ICMP) and pkt[IP].dst == FAKE_IP and pkt[ICMP].type == 8:
        print(f"[+] 收到 ICMP Echo Request 來自 {pkt[IP].src}")
        fake_mac = get_if_hwaddr(IFACE)
        ether = Ether(src=fake_mac, dst=pkt[Ether].src)
        ip = IP(src=FAKE_IP, dst=pkt[IP].src)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load if pkt.haslayer(Raw) else b''
        sendp(ether / ip / icmp / data, iface=IFACE, verbose=False)
        print(f"  ↳ 已回覆 ICMP Echo Reply")

# sniff(filter=f"arp or icmp and (dst host {FAKE_IP})", iface=IFACE, prn=lambda p: (handle_arp(p), handle_icmp(p)))
sniff(iface="eth0", filter="arp or icmp", prn=lambda p: (handle_arp(p), handle_icmp(p)))

