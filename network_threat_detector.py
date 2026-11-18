from scapy.all import *
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
from collections import Counter

# rdpcap() load & read your PCAP file & returns like a Python list
packets = rdpcap("samples/arp.pcapng")
total_packets = len(packets)

#-------------------------------------------------------------------------------------------------
# Basic Packets Calculation
ip_packets,tcp_packets,udp_packets,icmp_packets, arp_packets = [],[],[],[],[]

for pkt in packets:
    if IP in pkt:
        ip_packets.append(pkt)

for pkt in packets:
    if TCP in pkt:
        tcp_packets.append(pkt)

for pkt in packets:
    if UDP in pkt:
        udp_packets.append(pkt)

for pkt in packets:
    if ICMP in pkt:
        icmp_packets.append(pkt)

for pkt in packets:
    if ARP in pkt:
        arp_packets.append(pkt)

print(f"Total packets: {total_packets}")
print(f"IP packets: {len(ip_packets)}")
print(f"TCP packets: {len(tcp_packets)}")
print(f"UDP packets: {len(udp_packets)}")
print(f"ICMP packets: {len(icmp_packets)}")
print(f"ARP packets: {len(arp_packets)}")
print("------------------------------------")
print(f"IP %: {(len(ip_packets)/total_packets)*100:.2f}%")
print(f"TCP %: {(len(tcp_packets)/total_packets)*100:.2f}%")
print(f"UDP %: {(len(udp_packets)/total_packets)*100:.2f}%")
print(f"ICMP %: {(len(icmp_packets)/total_packets)*100:.2f}%")
print(f"ARP %: {(len(arp_packets)/total_packets)*100:.2f}%")
print("------------------------------------")
#-------------------------------------------------------------------------------------------------
# Top source IPs

src_ips=[]
for pkt in ip_packets:
    src_ips.append(pkt[IP].src)

# counter() - a special dictionary counting how many times items appear
top_src = Counter(src_ips).most_common(5)
print("Top 5 Source IPs:")
# key-vlaue = ip,count
for ip, count in top_src:
    print(f"{ip}: {count} packets")
print("------------------------------------")

# Top destination IPs
dst_ips=[]
for pkt in ip_packets:
    dst_ips.append(pkt[IP].dst)

top_dst = Counter(dst_ips).most_common(5)
print("Top 5 Destination IPs:")
for ip, count in top_dst:
    print(f"{ip}: {count} packets")

print("------------------------------------")

#-------------------------------------------------------------------------------------------------

# Port & Service Analysis
src_ports,dst_ports = [],[]

for pkt in tcp_packets:
    src_ports.append(pkt[TCP].sport)
    dst_ports.append(pkt[TCP].dport)

for pkt in udp_packets:
    src_ports.append(pkt[UDP].sport)
    dst_ports.append(pkt[UDP].dport)

print("Top 5 Source Ports:")
for port, count in Counter(src_ports).most_common(5):
    print(f"Port {port}: {count} packets")
print("------------------------------------")

print("Top 5 Destination Ports:")
for port, count in Counter(dst_ports).most_common(5):
    print(f"Port {port}: {count} packets")
print("------------------------------------")

#-------------------------------------------------------------------------------------------------
# Security-focused checks
syn_packets = []
for pkt in tcp_packets:
    # pkt[TCP] → extracts the TCP layer from that packet
    # .flags → accesses the flags field of the TCP header
    if pkt[TCP].flags == 'S':
        syn_packets.append(pkt)

print(f"Potential SYN scans (TCP SYN packets): {len(syn_packets)}")
print("------------------------------------")
#-------------------------------------------------------------------------------------------------
# Port Scanning- If one source IP sends SYN packets to many different 
# destination ports on same destination IP → possible port scan.

scan_tracker = {}

for pkt in tcp_packets:
    #only SYN packets;it ignores ACK, FIN, etc
    if pkt[TCP].flags == 'S':
        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport

        key = (src, dst)
        
        if key not in scan_tracker:
            #Set collection of unique items Automatically removes duplicates
            #Create an empty container to store unique ports for this (source, destination) pair.
            scan_tracker[key] = set()
        #add this destination port to the list of ports this attacker has scanned
        scan_tracker[key].add(dport)

print("Possible Port Scanners:")
#dictionary method loop through both keys and values of a dictionary at the same time
for (src, dst), ports in scan_tracker.items():
    #Only trigger an alert if the source has tried more than 20 different ports on the same destination.
    if len(ports) > 20:   # threshold can be changed
        print(f"{src} scanned {dst} on {len(ports)} ports")
print("------------------------------------")
#-------------------------------------------------------------------------------------------------

# ARP spoofing happens when:
# A single IP address is associated with multiple MAC addresses
# Or MAC ↔ IP mappings keep changing frequently in a short time

arp_table = {}

print("ARP Analysis:")

for pkt in packets:
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in arp_table and arp_table[ip] != mac:
            print(f"[ALERT] ARP Spoofing detected: {ip}")

        arp_table[ip] = mac

print("-----E N D-----")
