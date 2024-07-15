from scapy.all import sniff, IP, TCP, UDP, ARP
import datetime

def packet_callback(packet):
    # Get the timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check for IP packets
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Check for TCP packets
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"[{timestamp}] [TCP] {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        
        # Check for UDP packets
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"[{timestamp}] [UDP] {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
        
        # Generic IP packets
        else:
            print(f"[{timestamp}] [IP] {ip_src} -> {ip_dst} (protocol: {protocol})")
    
    # Check for ARP packets
    elif ARP in packet:
        arp_src = packet[ARP].psrc
        arp_dst = packet[ARP].pdst
        print(f"[{timestamp}] [ARP] {arp_src} -> {arp_dst}")

# Sniff packets indefinitely
sniff(prn=packet_callback, store=0)
