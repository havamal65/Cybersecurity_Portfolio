# Wireshark Integration for ESP32 Security Device

This document details the integration between our ESP32 security device and Wireshark, providing both PCAP file generation and real-time packet streaming capabilities.

## Integration Overview

We've implemented two primary methods for integrating with Wireshark:

1. **PCAP File Generation**: The ESP32 can write captured packets to PCAP files on an SD card, which can later be opened and analyzed in Wireshark.

2. **Real-time UDP Streaming**: The ESP32 can stream captured packets in real-time to a Wireshark instance running on a connected computer.

## PCAP Format Implementation

Our implementation adheres to the standard PCAP file format:

- Global Header (24 bytes):
  - Magic Number: 0xa1b2c3d4
  - Version: 2.4
  - Time Zone: GMT (0)
  - Accuracy: 0
  - Snapshot Length: 65535
  - Network Type: 105 (IEEE 802.11 wireless)

- Per-Packet Header (16 bytes):
  - Timestamp seconds
  - Timestamp microseconds
  - Captured length
  - Original packet length

## Components

### 1. esp_pcap Component

We've created a dedicated component `esp_pcap` that handles:
- PCAP file format implementation
- File writing operations
- UDP streaming functionality
- Packet buffering and processing

### 2. Integration with Security Core

The `esp_security_core` component now integrates with `esp_pcap` to:
- Forward captured packets to the PCAP module
- Configure capture options
- Manage PCAP operations

## Testing

We've verified our implementation using two test scripts:

### PCAP File Generation Test

- Script: `pcap_test.py`
- Function: Generates a sample PCAP file with simulated WiFi packets
- Results: Successfully creates PCAP files that open correctly in Wireshark

### Wireshark Streaming Test

- Script: `wireshark_stream_test.py`
- Function: Streams simulated WiFi packets to Wireshark in real-time
- Results: Successfully streams packets that appear in Wireshark when capturing on the specified UDP port

## Usage Instructions

### Opening PCAP Files

1. Generate PCAP files using the ESP32 or the test script
2. Open in Wireshark: `wireshark -r filename.pcap`

### Real-time Streaming

1. Configure Wireshark to capture on the loopback interface (for testing) or your network interface (for ESP32)
2. Apply a display filter: `udp.port == 5555` (or your configured port)
3. Start capturing in Wireshark
4. Run the ESP32 with streaming enabled

## Configuration Options

In the ESP32 implementation, you can configure:

- `PCAP_CAPTURE_ENABLED`: Enable/disable PCAP capture
- `PCAP_FILE_PREFIX`: Prefix for PCAP filenames
- `PCAP_STREAMING_ENABLED`: Enable/disable UDP streaming
- `PCAP_STREAMING_IP`: Target IP address for streaming
- `PCAP_STREAMING_PORT`: Target UDP port for streaming

## Notes for Real Hardware Implementation

When deploying to actual ESP32 hardware:

1. SD card must be connected and mounted for file capture
2. For streaming, the ESP32 and receiving computer must be on the same network
3. Adjust the `config.h` parameters to match your network configuration
4. Consider CPU and memory usage when enabling both capture and streaming

## Limitations

- File capture is limited by SD card speed and capacity
- Streaming may drop packets under heavy load
- Processing overhead may impact other security functions

## Future Enhancements

- Compression options for PCAP files
- Selective packet capture based on rules
- Integration with the web dashboard for direct download of PCAP files
- Custom dissectors for specific IoT protocols 