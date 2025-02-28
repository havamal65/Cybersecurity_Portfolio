# ESP32 Security Device Implementation

This folder contains the implementation of the ESP32 Security Device, which transforms our simulation into a real security monitoring and protection system running on ESP32 hardware.

## Prerequisites

- ESP-IDF v4.4 or later
- ESP32, ESP32-S2, or ESP32-S3 development board
- A microSD card adapter (optional, for logging)
- A USB-to-UART adapter for programming and monitoring
- Wireshark (optional, for packet analysis)

## Project Structure

- `main/` - Main application code
- `components/esp_security_core/` - Core security functionality
  - `include/` - Header files
  - `packet_capture.c` - Packet capture implementation
- `components/esp_pcap/` - PCAP capture and Wireshark integration
  - `include/` - Header files
  - `esp_pcap.c` - PCAP file and streaming functionality

## Setup Instructions

### 1. Install ESP-IDF

Follow the [official ESP-IDF installation guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) to set up the development environment.

### 2. Install Wireshark (Optional)

For packet analysis, download and install [Wireshark](https://www.wireshark.org/) on your computer.

### 3. Configure the Project

```bash
cd hardware
idf.py menuconfig
```

Under "ESP32 Security Device Configuration", set:
- WiFi SSID and password (if connecting to a network)
- Security preferences
- Logging options
- Wireshark integration options

### 4. Build and Flash

```bash
idf.py build
idf.py -p (PORT) flash
```

Replace `(PORT)` with your device's serial port (e.g., COM3 on Windows or /dev/ttyUSB0 on Linux).

### 5. Monitor Output

```bash
idf.py -p (PORT) monitor
```

## Hardware Setup

### Basic Setup

1. Connect the ESP32 development board to your computer via USB
2. Optionally connect a microSD card adapter to the ESP32 for logging
3. Power the device through USB or an external power supply

### SD Card Connection (for PCAP capture)

Connect an SD card to the ESP32 using SPI:
- MISO: GPIO2 (default, configurable)
- MOSI: GPIO15 (default, configurable)
- SCK: GPIO14 (default, configurable)
- CS: GPIO13 (default, configurable)

### Network Monitoring Setup

For passive monitoring:
1. Connect the ESP32 to your network via WiFi
2. Set WiFi to promiscuous mode (done automatically in the code)

For inline protection:
1. Configure the ESP32 as a WiFi access point
2. Connect devices through this access point
3. Set up appropriate firewall rules

## Wireshark Integration

The ESP32 Security Device provides two methods to integrate with Wireshark for professional packet analysis:

### 1. PCAP File Capture

By default, the device captures packets in PCAP format and stores them on the SD card. These files can be transferred to a computer and opened with Wireshark.

The device will:
- Create timestamped capture files in the configured directory
- Automatically rotate files when they reach the configured size
- Maintain a configurable number of capture files

To use the captured files:
1. Remove the SD card from the ESP32
2. Insert the SD card into your computer
3. Navigate to the `/pcap` directory
4. Open any `.pcap` file with Wireshark

### 2. Real-time Streaming

For real-time analysis, the device can stream packets directly to Wireshark (enable this feature in menuconfig):

1. Ensure your computer and ESP32 are on the same network
2. Configure Wireshark on your computer:
   - Open Wireshark
   - Go to Capture → Options
   - Click "Manage Interfaces" → "New"
   - Select "Remote Interface"
   - Under "Port", enter the configured UDP port (default: 5555)
   - Click "OK" and start capture

## Implementation Details

This implementation uses the ESP32's WiFi capabilities in promiscuous mode to capture network packets. These packets are then analyzed through our security pipeline:

1. Packet Capture - Using ESP32's WiFi in promiscuous mode
2. Firewall Rules - Applying configured rules to determine if packets should be allowed
3. IDS Detection - Monitoring for suspicious patterns
4. Alerting - Logging and notifying about security events
5. PCAP Generation - Saving packets in Wireshark-compatible format

## Limitations

- Processing power: The ESP32 can process a limited number of packets per second
- Memory constraints: Complex pattern matching is limited by available RAM
- WiFi only: This implementation focuses on WiFi traffic, not wired connections
- PCAP streaming overhead: Enabling real-time streaming may reduce packet processing capacity

## Future Enhancements

- External storage support for more extensive logging
- Integration with cloud services for threat intelligence updates
- Support for external sensors and indicators
- Web dashboard with secure authentication
- Protocol-specific dissectors for improved packet analysis
- PCAP file compression to save storage space 