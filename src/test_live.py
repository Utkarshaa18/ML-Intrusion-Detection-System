from scapy.all import sniff

print("Starting live packet capture...")
print("Capturing for 10 seconds...\n")

packets = sniff(timeout=10)

print("Capture completed!")
print("Packets captured:", len(packets))

for packet in packets[:10]:
    print(packet.summary())