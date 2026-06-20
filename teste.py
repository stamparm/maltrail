import socket
import time
from scapy.all import IP, ICMP, Raw

# Change this to your Maltrail sensor's IP if it's on a different machine or bridge interface
target_ip = "19.168.0.1"  
payload = b"hidden_exfil_data_chunk"

# 1. Pre-craft all packets before the loop begins
print("Pre-compiling packets into raw bytes...")
raw_packets = []

# Simulating 200 different internal hosts
for host_id in range(10, 210):  
    spoofed_ip = f"192.168.0.{host_id}"
    
    # Craft the packet using Scapy
    packet = IP(src=spoofed_ip, dst=target_ip)/ICMP(type=8)/Raw(load=payload)
    
    # Cast the Scapy object to raw bytes for maximum transmission speed
    raw_packets.append(bytes(packet))

# 2. Open a native OS raw socket
try:
    # 255 is the standard IANA protocol number for Raw IP
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 255)
except PermissionError:
    print("Error: Raw sockets require root privileges. Please run with sudo.")
    exit(1)

print(f"Blasting packets to {target_ip}... Press Ctrl+C to stop.")

packet_count = 0
start_time = time.time()

# 3. Blast the network
try:
    while True:
        for pkt_bytes in raw_packets:
            # Send the pre-compiled raw bytes directly to the network interface
            s.sendto(pkt_bytes, (target_ip, 0))
            packet_count += 1
            
        # Print a performance metric every second
        current_time = time.time()
        if current_time - start_time >= 1.0:
            print(f"Speed: {packet_count} packets/second")
            packet_count = 0
            start_time = current_time
            
except KeyboardInterrupt:
    print("\nStress test stopped.")
finally:
    s.close()