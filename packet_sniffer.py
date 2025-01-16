import scapy.all as scapy

# Define the callback function to handle each captured packet
def packet_callback(packet):
    print(f"Packet captured: {packet.summary()}")

# Function to start sniffing packets on the given network interface
def start_sniffing(interface):
    print(f"Starting packet sniffing on interface {interface}...")
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"Error sniffing on interface {interface}: {e}")

# Start sniffing on the "Wi-Fi" interface
start_sniffing("Wi-Fi")
