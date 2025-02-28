/**
 * ESP32 Security Implementation - Packet Capture Module Header
 * 
 * This header defines the interface for the packet capture functionality.
 */

#ifndef ESP_SECURITY_PACKET_CAPTURE_H
#define ESP_SECURITY_PACKET_CAPTURE_H

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize packet capture functionality
 * 
 * This function initializes the WiFi in promiscuous mode and sets up the 
 * necessary tasks and queues for packet processing.
 * 
 * @return ESP_OK if successful, otherwise an error code
 */
esp_err_t init_packet_capture(void);

/**
 * Stop packet capture
 * 
 * This function stops the packet capture functionality and cleans up resources.
 * 
 * @return ESP_OK if successful, otherwise an error code
 */
esp_err_t stop_packet_capture(void);

/**
 * Get packet capture statistics
 * 
 * @param captured Pointer to store number of captured packets
 * @param analyzed Pointer to store number of analyzed packets
 * @param blocked  Pointer to store number of blocked packets
 * @param allowed  Pointer to store number of allowed packets
 */
void get_capture_stats(uint32_t *captured, uint32_t *analyzed, uint32_t *blocked, uint32_t *allowed);

#ifdef __cplusplus
}
#endif

#endif /* ESP_SECURITY_PACKET_CAPTURE_H */ 