from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {proto}")

        if TCP in packet or UDP in packet:
            print(f"    Payload: {bytes(packet[TCP].payload)[:20] if TCP in packet else bytes(packet[UDP].payload)[:20]}")
        print("-" * 60)

print("🔍 Starting packet sniffer... Press CTRL+C to stop.")
sniff(prn=packet_callback, store=False)
