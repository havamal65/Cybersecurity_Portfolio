#!/usr/bin/env python3
"""
Simple Loopback UDP Test

This script creates both a UDP sender and receiver on localhost to test if
Wireshark can capture the traffic. This provides a more complete test since
we're both sending and receiving packets.
"""

import socket
import threading
import time
import random
import sys

SERVER_PORT = 8888  # Using a different port

def receiver():
    """UDP receiver function that runs in a separate thread"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', SERVER_PORT))  # Bind to all interfaces
    print(f"[RECEIVER] Listening on port {SERVER_PORT}")
    
    try:
        count = 0
        while True:
            data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            count += 1
            print(f"[RECEIVER] Received packet #{count}: {len(data)} bytes from {addr}")
    except KeyboardInterrupt:
        print("[RECEIVER] Stopping receiver")
    finally:
        sock.close()

def sender(num_packets=20):
    """Send a specified number of UDP packets to localhost"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[SENDER] Will send {num_packets} packets to localhost:{SERVER_PORT}")
    time.sleep(1)  # Give receiver time to start
    
    try:
        for i in range(num_packets):
            # Create random payload
            payload_size = random.randint(50, 200)
            message = bytes([random.randint(0, 255) for _ in range(payload_size)])
            
            # Send the message
            sock.sendto(message, ('127.0.0.1', SERVER_PORT))
            print(f"[SENDER] Sent packet #{i+1}: {len(message)} bytes")
            time.sleep(0.5)  # Wait half a second between packets
            
        print("[SENDER] All packets sent")
    except Exception as e:
        print(f"[SENDER] Error: {e}")
    finally:
        sock.close()

def main():
    print("=== UDP Loopback Test ===")
    print("This will send and receive UDP packets on localhost")
    print("Configure Wireshark to capture with filter: udp port 8888")
    print()
    
    # Start receiver in a separate thread
    receiver_thread = threading.Thread(target=receiver)
    receiver_thread.daemon = True  # Thread will exit when main program exits
    receiver_thread.start()
    
    try:
        # Start sender after a short delay
        time.sleep(0.5)
        sender(20)  # Send 20 packets
        
        # Keep main thread alive to allow receiving all packets
        time.sleep(1)
        print("\nTest completed. Check if Wireshark captured the packets.")
        print("Press Ctrl+C to exit")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

if __name__ == "__main__":
    main() 