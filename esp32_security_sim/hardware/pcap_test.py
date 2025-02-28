#!/usr/bin/env python3
"""
PCAP Test Script for ESP32 Security Device

This script simulates the behavior of our ESP32 PCAP implementation.
It creates a PCAP file with sample WiFi packets to verify the file format
is correct and can be opened by Wireshark.
"""

import struct
import os
import time
import random
from datetime import datetime

# PCAP file format constants
PCAP_MAGIC_NUMBER = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_NETWORK_WIFI = 105  # LINKTYPE_IEEE802_11

class PcapWriter:
    def __init__(self, filename, network_type=PCAP_NETWORK_WIFI):
        self.filename = filename
        self.network_type = network_type
        self.file = None
        self.packets_written = 0
        
    def open(self):
        """Open the PCAP file and write the global header."""
        self.file = open(self.filename, 'wb')
        
        # Write PCAP global header
        header = struct.pack(
            '=IHHiIII',           # Format string: = (native), I (uint32), H (uint16), i (int32)
            PCAP_MAGIC_NUMBER,    # Magic number
            PCAP_VERSION_MAJOR,   # Major version
            PCAP_VERSION_MINOR,   # Minor version
            0,                    # GMT to local correction (0 = GMT)
            0,                    # Accuracy of timestamps (0 = default)
            PCAP_SNAPLEN,         # Snapshot length
            self.network_type     # Data link type
        )
        self.file.write(header)
        return self
        
    def write_packet(self, packet_data, timestamp=None):
        """Write a packet with its header to the PCAP file."""
        if not self.file:
            raise ValueError("PCAP file not open")
            
        if timestamp is None:
            timestamp = time.time()
            
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        
        # Write packet header
        packet_header = struct.pack(
            '=IIII',              # Format string
            ts_sec,               # Timestamp seconds
            ts_usec,              # Timestamp microseconds
            len(packet_data),     # Captured length
            len(packet_data)      # Original length
        )
        
        self.file.write(packet_header)
        self.file.write(packet_data)
        self.packets_written += 1
        
    def close(self):
        """Close the PCAP file."""
        if self.file:
            self.file.close()
            self.file = None


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
    # Create output directory
    os.makedirs('pcap_test_output', exist_ok=True)
    
    # Generate a timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pcap_test_output/esp_capture_{timestamp}.pcap"
    
    print(f"Creating PCAP file: {filename}")
    
    # Open PCAP file
    pcap = PcapWriter(filename).open()
    
    # Generate and write random WiFi packets
    num_packets = 100
    print(f"Generating {num_packets} random WiFi packets...")
    
    for i in range(num_packets):
        # Generate packet of random length between 64 and 1500 bytes
        packet_length = random.randint(64, 1500)
        packet = generate_wifi_packet(packet_length)
        
        # Add small time increment
        timestamp = time.time() + (i * 0.001)  # 1ms between packets
        
        # Write to PCAP file
        pcap.write_packet(packet, timestamp)
        
        # Show progress
        if (i+1) % 10 == 0:
            print(f"  Wrote {i+1} packets...")
    
    # Close the PCAP file
    pcap.close()
    
    print(f"\nPCAP file created successfully.")
    print(f"Wrote {pcap.packets_written} packets to {filename}")
    print("\nYou can now open this file with Wireshark to verify it works correctly.")
    print("If using Windows: wireshark.exe -r", os.path.abspath(filename))
    print("If using Linux/macOS: wireshark -r", os.path.abspath(filename))


if __name__ == "__main__":
    main() 