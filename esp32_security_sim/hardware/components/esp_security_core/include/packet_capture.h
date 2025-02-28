#ifndef ESP_SECURITY_PACKET_CAPTURE_H
#define ESP_SECURITY_PACKET_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize packet capture system
 * 
 * Initializes WiFi in promiscuous mode for packet capturing
 * 
 * @param wifi_channel The WiFi channel to monitor
 * @return esp_err_t ESP_OK on success or an error code
 */
esp_err_t packet_capture_init(uint8_t wifi_channel);

/**
 * @brief Start packet capture
 * 
 * @return esp_err_t ESP_OK on success or an error code
 */
esp_err_t packet_capture_start(void);

/**
 * @brief Stop packet capture
 * 
 * @return esp_err_t ESP_OK on success or an error code
 */
esp_err_t packet_capture_stop(void);

/**
 * @brief Register a packet handler callback
 * 
 * @param callback Function to call when a packet is received
 * @param user_data User data to pass to the callback
 * @return esp_err_t ESP_OK on success or an error code
 */
typedef void (*packet_handler_t)(void *user_data, const uint8_t *data, size_t len, uint64_t timestamp_us);

esp_err_t packet_capture_register_handler(packet_handler_t callback, void *user_data);

/**
 * @brief Get packet capture statistics
 * 
 * @param packets_received Number of packets received
 * @param packets_dropped Number of packets dropped due to queue full
 * @return esp_err_t ESP_OK on success or an error code
 */
esp_err_t packet_capture_get_stats(uint32_t *packets_received, uint32_t *packets_dropped);

#ifdef __cplusplus
}
#endif

#endif /* ESP_SECURITY_PACKET_CAPTURE_H */ 