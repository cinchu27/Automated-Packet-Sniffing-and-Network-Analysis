from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter

# Global variables to hold packet info and protocol counts
packets_captured = []
protocol_counts = Counter()

def packet_handler(packet):
    """
    This function is called for each packet captured by Scapy.
    It analyzes the packet and updates our counters.
    """
    packets_captured.append(packet)
    
    # Determine the protocol
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            protocol_counts['TCP'] += 1
        elif packet.haslayer(UDP):
            protocol_counts['UDP'] += 1
        elif packet.haslayer(ICMP):
            protocol_counts['ICMP'] += 1
        else:
            protocol_counts['Other IP'] += 1
    else:
        protocol_counts['Non-IP'] += 1
    
    print(f"Captured packet #{len(packets_captured)}: {packet.summary()}")

def analyze_and_chart():
    """Analyzes the captured packets and generates a bar chart."""
    if not packets_captured:
        print("No packets were captured.")
        return

    print("\n--- Packet Analysis Complete ---")
    print(f"Total packets captured: {len(packets_captured)}")
    print("Protocol Distribution:")
    for proto, count in protocol_counts.items():
        print(f"  - {proto}: {count}")

    # Generate the bar chart
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.figure(figsize=(10, 6))
    plt.bar(protocols, counts, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd'])
    plt.xlabel('Protocol')
    plt.ylabel('Number of Packets')
    plt.title('Distribution of Captured Network Protocols')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the chart to a file
    plt.savefig('protocol_distribution.png')
    print("\nChart saved as protocol_distribution.png")
    plt.show()

def main():
    """
    Main function to start the packet sniffing process.
    """
    print("Starting packet capture... (Press Ctrl+C to stop early)")
    
    try:
        sniff(prn=packet_handler, count=100, store=0)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")

    analyze_and_chart()

if __name__ == "__main__":
    main()
