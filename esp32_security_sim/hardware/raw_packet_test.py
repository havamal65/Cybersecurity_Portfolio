#!/usr/bin/env python3
"""
Raw Packet Generator for Wireshark Testing

This script generates raw Ethernet frames that should be more reliably 
captured by Wireshark. It requires administrator privileges to run.
"""

import socket
import struct
import random
import time
import sys
import os

# Check if running as administrator (needed for raw sockets on Windows)
if os.name == 'nt':  # Windows
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("WARNING: This script requires administrator privileges!")
            print("Please run this script as administrator (right-click, 'Run as administrator')")
            print("Continuing anyway, but packet capture may not work...")
    except:
        print("Could not check administrator status. Continuing anyway...")

# Configuration
INTERFACE = ''  # empty string = let OS choose
ETH_P_ALL = 3  # from linux/if_ether.h
ETH_P_IP = 0x0800  # IP protocol

def create_eth_header(src_mac, dst_mac, eth_type=ETH_P_IP):
    """Create Ethernet header"""
    # Convert MAC addresses to binary format
    src = bytes.fromhex(src_mac.replace(':', ''))
    dst = bytes.fromhex(dst_mac.replace(':', ''))
    
    # Create header (destination MAC, source MAC, ethertype)
    header = struct.pack('!6s6sH', dst, src, eth_type)
    return header

def create_ip_header(src_ip, dst_ip, proto=17):  # 17 = UDP
    """Create IP header"""
    # IP header fields
    version = 4
    ihl = 5  # Internet Header Length
    tos = 0  # Type of Service
    tot_len = 20 + 8 + 32  # 20 bytes IP + 8 bytes UDP + 32 bytes data (minimum)
    id = random.randint(0, 65535)
    frag_off = 0
    ttl = 64
    protocol = proto  # UDP
    check = 0  # Will be calculated later
    saddr = socket.inet_aton(src_ip)  # Source address
    daddr = socket.inet_aton(dst_ip)  # Destination address
    
    # Combine version and ihl
    ver_ihl = (version << 4) + ihl
    
    # Create header without checksum
    header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    
    # Calculate checksum
    check = checksum(header)
    
    # Create header with checksum
    header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    return header

def create_udp_header(src_port, dst_port, length):
    """Create UDP header"""
    # UDP header fields
    src_port = src_port  # Source port
    dst_port = dst_port  # Destination port
    length = length      # Length of UDP header + data
    checksum = 0         # Will be calculated later
    
    # Create header
    header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
    return header

def checksum(msg):
    """Calculate IP header checksum"""
    s = 0
    
    # Loop through the message 2 bytes at a time
    for i in range(0, len(msg), 2):
        if i + 1 < len(msg):
            w = (msg[i] << 8) + msg[i + 1]
        else:
            w = (msg[i] << 8)
        s = s + w
    
    # Add the carry
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    
    # Take the one's complement
    s = ~s & 0xffff
    
    return s

def send_test_packets(count=10):
    """Send test packets that should be easily captured by Wireshark"""
    try:
        # Create a raw socket
        if os.name == 'nt':  # Windows
            # On Windows, SOCK_RAW might require administrator privileges
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.bind(('127.0.0.1', 0))
        else:  # Linux/macOS
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((INTERFACE, ETH_P_ALL))

        print(f"Sending {count} test packets...")
        
        for i in range(count):
            # For simplicity, we'll use fixed addresses
            if os.name == 'nt':  # Windows - no Ethernet header
                # Create IP header
                ip_header = create_ip_header('127.0.0.1', '127.0.0.1')
                
                # Create UDP header (8 bytes + data length)
                data_length = random.randint(32, 64)
                udp_length = 8 + data_length
                udp_header = create_udp_header(12345, 8888, udp_length)
                
                # Create random payload
                payload = bytes([random.randint(0, 255) for _ in range(data_length)])
                
                # Combine packet
                packet = ip_header + udp_header + payload
                
                # Send packet
                s.sendto(packet, ('127.0.0.1', 0))
            else:  # Linux/macOS
                # Create Ethernet header
                eth_header = create_eth_header('00:11:22:33:44:55', 'ff:ff:ff:ff:ff:ff')
                
                # Create IP header
                ip_header = create_ip_header('192.168.1.1', '192.168.1.2')
                
                # Create UDP header (8 bytes + data length)
                data_length = random.randint(32, 64)
                udp_length = 8 + data_length
                udp_header = create_udp_header(12345, 8888, udp_length)
                
                # Create random payload
                payload = bytes([random.randint(0, 255) for _ in range(data_length)])
                
                # Combine packet
                packet = eth_header + ip_header + udp_header + payload
                
                # Send packet
                s.send(packet)
            
            print(f"Sent packet #{i+1} with {data_length} bytes payload")
            time.sleep(0.5)  # Wait half a second between packets
        
        print("All packets sent!")
        
    except socket.error as e:
        if e.errno == 10013 and os.name == 'nt':  # Permission denied on Windows
            print("ERROR: Permission denied. Please run this script as administrator.")
        else:
            print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 's' in locals():
            s.close()
            
def main():
    print("==== Raw Packet Test for Wireshark ====")
    print("This script sends raw packets that should be visible in Wireshark")
    print("Configure Wireshark to capture on your loopback interface")
    print("Use display filter: udp.port == 8888")
    print()
    
    # Check if running as admin
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin() != 0:
            print("WARNING: For this script to work on Windows, you need to:")
            print("1. Run this script as administrator")
            print("2. Run Wireshark as administrator")
            input("Press Enter to continue anyway...")
    
    try:
        # Send test packets
        send_test_packets(10)
        
        print("\nTest completed. Check if Wireshark captured the packets.")
        print("Press Ctrl+C to exit")
        
        # Keep the program running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

if __name__ == "__main__":
    main() 