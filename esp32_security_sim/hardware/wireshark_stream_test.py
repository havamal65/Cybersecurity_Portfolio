#!/usr/bin/env python3
"""
Wireshark UDP Stream Test for ESP32 Security Device

This script simulates the UDP streaming functionality of our ESP32 PCAP implementation.
It sends WiFi packets in PCAP format to a UDP port that Wireshark can listen on.

To use:
1. Open Wireshark
2. Go to Capture > Options
3. Click "Manage Interfaces" > "New"
4. Select "UDP Socket"
5. Enter port 5555 (or whatever port you specify when running this script)
6. Click "OK" and start capture
7. Run this script
"""

import struct
import socket
import time
import random
import argparse
from datetime import datetime

# PCAP constants
PCAP_MAGIC_NUMBER = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_NETWORK_WIFI = 105  # LINKTYPE_IEEE802_11

# Default streaming settings
DEFAULT_PORT = 5555
DEFAULT_IP = "127.0.0.1"  # localhost

class WiresharkStreamer:
    def __init__(self, ip=DEFAULT_IP, port=DEFAULT_PORT, network_type=PCAP_NETWORK_WIFI):
        self.ip = ip
        self.port = port
        self.network_type = network_type
        self.sock = None
        self.packets_sent = 0
        
    def open(self):
        """Initialize UDP socket."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self
        
    def send_global_header(self):
        """Send PCAP global header."""
        if not self.sock:
            raise ValueError("Socket not initialized")
            
        # Create PCAP global header
        header = struct.pack(
            '=IHHiIII',           # Format string
            PCAP_MAGIC_NUMBER,    # Magic number
            PCAP_VERSION_MAJOR,   # Major version
            PCAP_VERSION_MINOR,   # Minor version
            0,                    # GMT to local correction (0 = GMT)
            0,                    # Accuracy of timestamps (0 = default)
            PCAP_SNAPLEN,         # Snapshot length
            self.network_type     # Data link type
        )
        
        # Send header
        self.sock.sendto(header, (self.ip, self.port))
        print(f"Sent PCAP global header to {self.ip}:{self.port}")
        
    def send_packet(self, packet_data, timestamp=None):
        """Send a packet in PCAP format."""
        if not self.sock:
            raise ValueError("Socket not initialized")
            
        if timestamp is None:
            timestamp = time.time()
            
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        
        # Create packet header
        packet_header = struct.pack(
            '=IIII',              # Format string
            ts_sec,               # Timestamp seconds
            ts_usec,              # Timestamp microseconds
            len(packet_data),     # Captured length
            len(packet_data)      # Original length
        )
        
        # Send packet (header + data)
        self.sock.sendto(packet_header + packet_data, (self.ip, self.port))
        self.packets_sent += 1
        
    def close(self):
        """Close the socket."""
        if self.sock:
            self.sock.close()
            self.sock = None


def generate_wifi_packet(length=64):
    """Generate a simple simulated WiFi packet with random data."""
    # Simplified WiFi frame header
    frame_control = random.randint(0, 0xFFFF)  # Random frame control field
    duration = random.randint(0, 0xFFFF)       # Random duration
    
    # Mac addresses (random)
    addr1 = bytes([random.randint(0, 255) for _ in range(6)])
    addr2 = bytes([random.randint(0, 255) for _ in range(6)])
    addr3 = bytes([random.randint(0, 255) for _ in range(6)])
    
    seq_ctrl = random.randint(0, 0xFFFF)       # Random sequence control
    
    # Create header
    header = struct.pack('=HH6s6s6sH', frame_control, duration, addr1, addr2, addr3, seq_ctrl)
    
    # Add random payload to reach desired length
    payload_len = max(0, length - len(header))
    payload = bytes([random.randint(0, 255) for _ in range(payload_len)])
    
    return header + payload


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Stream simulated WiFi packets to Wireshark")
    parser.add_argument("--ip", default=DEFAULT_IP, help=f"IP address to stream to (default: {DEFAULT_IP})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"UDP port to stream to (default: {DEFAULT_PORT})")
    parser.add_argument("--count", type=int, default=1000, help="Number of packets to send (default: 1000)")
    parser.add_argument("--interval", type=float, default=0.1, help="Interval between packets in seconds (default: 0.1)")
    args = parser.parse_args()
    
    print(f"Wireshark UDP Streaming Test")
    print(f"============================")
    print(f"Target: {args.ip}:{args.port}")
    print(f"Sending {args.count} packets with {args.interval}s interval")
    print()
    print("Make sure Wireshark is capturing on UDP port", args.port)
    print("Press Ctrl+C to stop streaming")
    print()
    
    try:
        # Initialize streamer
        streamer = WiresharkStreamer(args.ip, args.port).open()
        
        # Optionally send global header (not needed for streaming)
        # streamer.send_global_header()
        
        # Send packets
        print(f"Sending packets...")
        for i in range(args.count):
            # Generate packet of random length between 64 and 1500 bytes
            packet_length = random.randint(64, 1500)
            packet = generate_wifi_packet(packet_length)
            
            # Send to Wireshark
            streamer.send_packet(packet)
            
            # Show progress
            if (i+1) % 10 == 0:
                print(f"  Sent {i+1} packets...")
            
            # Wait between packets
            time.sleep(args.interval)
            
    except KeyboardInterrupt:
        print("\nStreaming stopped by user")
    finally:
        if 'streamer' in locals():
            streamer.close()
            print(f"\nStream ended. {streamer.packets_sent} packets sent.")


if __name__ == "__main__":
    main() 