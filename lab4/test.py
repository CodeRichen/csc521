from scapy.all import *
import socket

target_ip = "140.127.74.226"


open_ports = []
filtered_ports = []

for dport in range(1, 101):

    # 2. 建立 TCP SYN（每個 port 有自己的 seq + sport）
    src_port = RandShort()
    seq_num = random.randint(0, 2**32 - 1)

    syn_pkt = IP(dst=target_ip) / TCP(
        sport=src_port,
        dport=dport,
        flags="S",
        seq=seq_num
    )

    # 3. 傳送 SYN 並等待回應
    resp = sr1(syn_pkt, timeout=0.5, verbose=0)

    if resp is None:
        # no reply → possibly filtered
        filtered_ports.append(dport)
        continue

    if resp.haslayer(TCP):
        tcp_layer = resp.getlayer(TCP)

        # SYN/ACK → open
        if tcp_layer.flags == 0x12:   # SYN + ACK
            open_ports.append(dport)

            # 依標準流程送 RST 結束握手
            rst_pkt = IP(dst=target_ip) / TCP(
                sport=src_port,
                dport=dport,
                flags="R",
                seq=seq_num + 1
            )
            send(rst_pkt, verbose=0)

        # RST → closed
        elif tcp_layer.flags == 0x14: # RST + ACK
            pass  # closed (不列入結果)

# 結果輸出
print("Open ports:", open_ports)
print("Filtered ports:", filtered_ports)
