#ifndef ESP_PCAP_H
#define ESP_PCAP_H

#include <stdint.h>
#include <stdbool.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief PCAP file format global header
 * 
 * This is the header that appears at the beginning of a PCAP file.
 */
typedef struct {
    uint32_t magic_number;   /* Magic number */
    uint16_t version_major;  /* Major version number */
    uint16_t version_minor;  /* Minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* Accuracy of timestamps */
    uint32_t snaplen;        /* Max length of captured packets */
    uint32_t network;        /* Data link type */
} pcap_file_header_t;

/**
 * @brief PCAP packet header
 * 
 * This header precedes each packet in a PCAP file.
 */
typedef struct {
    uint32_t ts_sec;         /* Timestamp seconds */
    uint32_t ts_usec;        /* Timestamp microseconds */
    uint32_t incl_len;       /* Number of bytes included */
    uint32_t orig_len;       /* Actual length of packet */
} pcap_packet_header_t;

/* PCAP magic number in little-endian format */
#define PCAP_MAGIC_NUMBER       0xa1b2c3d4
/* PCAP version 2.4 */
#define PCAP_VERSION_MAJOR      2
#define PCAP_VERSION_MINOR      4
/* Maximum snapshot length (65535) */
#define PCAP_SNAPLEN            65535
/* LINKTYPE_ETHERNET: Ethernet link layer */
#define PCAP_NETWORK_ETHERNET   1
/* LINKTYPE_IEEE802_11: IEEE 802.11 wireless */
#define PCAP_NETWORK_WIFI       105

/* PCAP capture modes */
typedef enum {
    ESP_PCAP_CAPTURE_MODE_CONTINUOUS,  /* Capture continuously */
    ESP_PCAP_CAPTURE_MODE_TRIGGERED    /* Capture only when triggered */
} esp_pcap_capture_mode_t;

/* PCAP initialization configuration */
typedef struct {
    const char *base_path;             /* Base path for PCAP files (e.g., "/sdcard/pcap") */
    const char *filename_prefix;       /* Prefix for generated filenames */
    uint32_t max_file_size_bytes;      /* Maximum file size before rotation */
    uint8_t max_files;                 /* Maximum number of files to keep */
    uint16_t network_type;             /* PCAP network type (link layer type) */
    esp_pcap_capture_mode_t mode;      /* Capture mode */
    bool enable_streaming;             /* Enable UDP streaming to Wireshark */
    uint16_t streaming_port;           /* UDP port for streaming */
    const char *streaming_ip;          /* IP address for streaming */
} esp_pcap_config_t;

/**
 * @brief Initialize the PCAP capture system
 * 
 * @param config Configuration parameters
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_init(const esp_pcap_config_t *config);

/**
 * @brief Start packet capture
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_start_capture(void);

/**
 * @brief Stop packet capture
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_stop_capture(void);

/**
 * @brief Write a packet to the PCAP file and/or stream
 * 
 * @param packet_data Pointer to packet data
 * @param packet_len Length of the packet
 * @param timestamp_us Microsecond timestamp (if 0, current time will be used)
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_write_packet(const uint8_t *packet_data, uint32_t packet_len, uint64_t timestamp_us);

/**
 * @brief Check if PCAP capture is initialized
 * 
 * @return true if initialized, false otherwise
 */
bool esp_pcap_is_initialized(void);

/**
 * @brief Check if PCAP capture is currently active
 * 
 * @return true if active, false otherwise
 */
bool esp_pcap_is_capturing(void);

/**
 * @brief Get list of PCAP files
 * 
 * @param files Array to store file information
 * @param max_files Maximum number of files to return
 * @param num_files Actual number of files found
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_get_file_list(char **files, size_t max_files, size_t *num_files);

/**
 * @brief Trigger a new capture file (rotate to a new file)
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_rotate_file(void);

/**
 * @brief Delete a specific PCAP file
 * 
 * @param filename Name of the file to delete
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t esp_pcap_delete_file(const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PCAP_H */ 