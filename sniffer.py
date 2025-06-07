from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"[IP] {ip_src} → {ip_dst} | Protocol: {proto}", end="")

        if TCP in packet:
            print(f" | [TCP] {packet[TCP].sport} → {packet[TCP].dport}")
        elif UDP in packet:
            print(f" | [UDP] {packet[UDP].sport} → {packet[UDP].dport}")
        else:
            print()

# Capture indefinitely (Ctrl+C to stop), or set count=X
sniff(filter="ip", prn=process_packet)
