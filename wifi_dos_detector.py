import scapy.all as scapy
import time
import logging

logging.basicConfig(filename='wifi_dos.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def detect_wifi_dos(target_ip="192.168.1.1", packet_count=100, threshold=0.9):
    print("[+] Starting packet capture...")
    logging.info("Starting packet capture...")

    packets = scapy.sniff(count=packet_count)
    total_packets = len(packets)

    print(f"[+] {total_packets} packets captured.")
    logging.info(f"{total_packets} packets captured.")

    if total_packets > packet_count * threshold:
        print("[!] Excessive traffic detected. Possible DoS attack.")
        logging.warning("Excessive traffic detected. Possible DoS attack.")

        # Extract and display the source IP addresses of the packets if they contain IP layer information
        source_ips = []
        for packet in packets:
            if scapy.IP in packet:
                source_ips.append(packet[scapy.IP].src)

        if source_ips:
            print("[+] Source IPs maybe triggering the DoS attack:")
            print("\n".join(set(source_ips)))  # Display unique source IPs
        else:
            print("[+] No source IPs found.")
    else:
        print("[+] No signs of DoS attack.")
        logging.info("No signs of DoS attack.")

if __name__ == "__main__":
    detect_wifi_dos()
