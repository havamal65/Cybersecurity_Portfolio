# Testing the ESP32 Wireshark Integration

This document provides instructions for testing the Wireshark integration components of our ESP32 security device implementation. Since we don't have a physical ESP32 with the actual ESP-IDF environment for building the firmware, these test scripts allow us to verify that our PCAP format and streaming implementations are working correctly.

## Prerequisites

- Python 3.6+
- Wireshark installed on your computer

## PCAP File Format Testing

The `pcap_test.py` script creates a PCAP file containing simulated WiFi packets that can be opened with Wireshark.

### How to Use

1. Run the script:
   ```
   python pcap_test.py
   ```

2. The script will create a file in the `pcap_test_output` directory with a name like `esp_capture_YYYYMMDD_HHMMSS.pcap`

3. Open the generated file in Wireshark:
   - Windows: `wireshark.exe -r <filename>`
   - Linux/macOS: `wireshark -r <filename>`

4. Verify that Wireshark can properly read and display the packets

## UDP Streaming Testing

The `wireshark_stream_test.py` script simulates streaming packets to Wireshark in real-time, just like our ESP32 implementation would do.

### How to Use

1. Open Wireshark on your computer

2. Set up a UDP listening interface:
   - Select the "Npcap Loopback Adapter" interface (for localhost testing)
   - Apply a display filter: `udp.port == 5555`
   - Click the blue shark fin button to start capturing

3. Run the test script:
   ```
   python wireshark_stream_test.py
   ```
   
   Or with custom parameters:
   ```
   python wireshark_stream_test.py --ip 127.0.0.1 --port 5555 --count 100 --interval 0.2
   ```

4. You should see packets appearing in Wireshark in real-time

5. Press Ctrl+C to stop the script when you're done testing

## Loopback Testing

The `loopback_test.py` script provides a simpler testing method by creating both a sender and receiver on your local machine.

### How to Use

1. Open Wireshark and select the "Npcap Loopback Adapter" interface
2. Apply the display filter: `udp.port == 8888`
3. Start capturing
4. Run the script:
   ```
   python loopback_test.py
   ```
5. You should see packets sent and received in both the console output and in Wireshark

## Raw Packet Testing

For more advanced testing, the `raw_packet_test.py` script attempts to send raw packets (requires administrator privileges).

### How to Use

1. Open a Command Prompt or PowerShell as Administrator
2. Navigate to the project directory
3. Run:
   ```
   python raw_packet_test.py
   ```
4. Monitor Wireshark to see if the packets appear

## What to Look for in Wireshark

When verifying the PCAP data:

1. **Proper Packet Display**: Wireshark should recognize the packets as the appropriate type (IEEE 802.11 for PCAP files, UDP for streaming)
2. **Timestamps**: Check that the packet timestamps are sequential and make sense
3. **Packet Details**: While our simulated packets contain random data, Wireshark should still display the basic frame structure
4. **No Errors**: Wireshark should not report any errors when reading the PCAP data

## Troubleshooting

If you don't see packets in Wireshark:

1. **Check Interface**: Ensure you're capturing on the correct interface
2. **Check Filter**: Make sure your display filter is correct (e.g., `udp.port == 5555`)
3. **Administrator Mode**: Try running both Wireshark and the test scripts as Administrator
4. **Firewall**: Check if Windows Firewall is blocking the UDP traffic
5. **Different Port**: Try a different port number if 5555 is being used by another application

## Notes for ESP32 Implementation

The code in the `esp_pcap` component uses the same PCAP file format and streaming approach as these test scripts. If these tests work with Wireshark, it confirms that our implementation approach is correct.

Once you have the ESP-IDF environment set up and can build the firmware for a physical ESP32:

1. Configure the project using `idf.py menuconfig`
2. Enable PCAP capture and/or Wireshark streaming
3. Flash the firmware to your ESP32
4. If using file capture, examine the generated PCAP files
5. If using streaming, configure Wireshark as described above to receive packets 