from scapy.all import IP, UDP, send
import time

# Target host IP
dst_ip = "10.0.0.2"
src_ip = "10.0.0.1"

message = "hi how are you"
words = message.split()

for i, word in enumerate(words):
    pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=12345, dport=54321)/f"{i}:{word}"
    send(pkt)
    print(f"Sent: {word} with seq {i}")
    time.sleep(0.5)
