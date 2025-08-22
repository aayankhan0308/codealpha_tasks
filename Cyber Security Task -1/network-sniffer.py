"""
Basic Network Sniffer for Windows
Captures and analyzes network traffic packets
"""

from scapy.all import *
import argparse
from datetime import datetime
import os
import sys

def process_packet(packet):
    """Process each captured packet and extract information"""
    # Get current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize variables
    protocol = "Unknown"
    src_ip = "Unknown"
    dst_ip = "Unknown"
    src_port = "Unknown"
    dst_port = "Unknown"
    payload = "None"
    
    # Check if packet has IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Check protocol type
        if packet.haslayer(TCP):
            protocol = "TCP"
            transport_layer = packet.getlayer(TCP)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            transport_layer = packet.getlayer(UDP)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            transport_layer = packet.getlayer(ICMP)
        else:
            protocol = "Other"
            transport_layer = None
        
        # Extract port information if available
        if transport_layer and hasattr(transport_layer, 'sport'):
            src_port = transport_layer.sport
            dst_port = transport_layer.dport
        
        # Extract payload if available
        if packet.haslayer(Raw):
            payload = packet.getlayer(Raw).load[:100]  # First 100 bytes
            try:
                # Try to decode as UTF-8
                payload = payload.decode('utf-8', errors='ignore')
            except:
                payload = "[Binary data]"
    
    # Print packet information
    print(f"[{timestamp}] {protocol}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    if payload != "None":
        print(f"    Payload: {payload}")
    print("-" * 80)

def start_sniffing(interface=None, count=0):
    """Start packet sniffing on the specified interface"""
    print(f"Starting packet sniffer on interface {interface or 'default'}")
    print("Press Ctrl+C to stop\n")
    
    # Sniff parameters
    sniff_params = {
        'prn': process_packet,
        'store': 0  # Don't store packets in memory
    }
    
    if interface:
        sniff_params['iface'] = interface
    
    if count > 0:
        sniff_params['count'] = count
    
    try:
        # Start sniffing
        sniff(**sniff_params)
    except PermissionError:
        print("Error: Permission denied. Try running with administrator privileges.")
    except Exception as e:
        print(f"Error: {e}")

def main():
    """Main function to handle command line arguments"""
    parser = argparse.ArgumentParser(description="Basic Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, 
                       help="Number of packets to capture (0 for infinite)")
    
    args = parser.parse_args()
    
    # Check if running with appropriate privileges (Windows)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("Warning: For best results, run as Administrator")
    except:
        print("Warning: Could not check admin privileges")
    
    start_sniffing(args.interface, args.count)

if __name__ == "__main__":
    main()