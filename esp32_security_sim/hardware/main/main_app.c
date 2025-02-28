#include <stdio.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"
#include "driver/sdspi_host.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Include components */
#include "packet_capture.h"

static const char *TAG = "MAIN_APP";

/* Mount point for the SD Card */
static const char *MOUNT_POINT = CONFIG_SECURITY_SDCARD_MOUNT_POINT;

/* SD Card initialization function */
static esp_err_t init_sdcard(void) {
    ESP_LOGI(TAG, "Initializing SD card");

    /* Initialize SPI bus for SD card */
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    sdspi_slot_config_t slot_config = SDSPI_SLOT_CONFIG_DEFAULT();
    
    /* Set SPI mode pins */
    slot_config.gpio_miso = 2;   /* Replace with your actual pin numbers */
    slot_config.gpio_mosi = 15;
    slot_config.gpio_sck = 14;
    slot_config.gpio_cs = 13;

    /* Mount configuration for the FAT filesystem */
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = true,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024
    };

    sdmmc_card_t *card;
    esp_err_t ret = esp_vfs_fat_sdmmc_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &card);
    
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount filesystem on SD card");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        }
        return ret;
    }

    /* Create PCAP directory if it doesn't exist */
    char pcap_dir[64];
    snprintf(pcap_dir, sizeof(pcap_dir), "%s/pcap", MOUNT_POINT);
    mkdir(pcap_dir, 0755);

    /* Print card info */
    sdmmc_card_print_info(stdout, card);
    ESP_LOGI(TAG, "SD card initialized successfully");
    
    return ESP_OK;
}

/* Packet handler callback */
static void packet_handler(void *user_data, const uint8_t *data, size_t len, uint64_t timestamp_us) {
    /* Simple packet counter */
    static uint32_t packet_count = 0;
    packet_count++;
    
    /* Log every 100th packet */
    if (packet_count % 100 == 0) {
        ESP_LOGI(TAG, "Processed %u packets, last packet: %u bytes", packet_count, len);
    }
}

/* Statistics reporting task */
static void stats_task(void *pvParameters) {
    uint32_t packets_received = 0;
    uint32_t packets_dropped = 0;
    uint32_t prev_packets_received = 0;
    uint32_t interval_packets = 0;
    
    while (1) {
        /* Delay for the configured statistics interval */
        vTaskDelay(pdMS_TO_TICKS(CONFIG_SECURITY_STATS_INTERVAL_SEC * 1000));
        
        /* Get current statistics */
        packet_capture_get_stats(&packets_received, &packets_dropped);
        
        /* Calculate packets per second in the last interval */
        interval_packets = packets_received - prev_packets_received;
        float packets_per_second = (float)interval_packets / CONFIG_SECURITY_STATS_INTERVAL_SEC;
        
        /* Print statistics */
        ESP_LOGI(TAG, "Statistics: Received=%u, Dropped=%u, Rate=%.2f packets/sec", 
            packets_received, packets_dropped, packets_per_second);
        
        /* Save for next interval */
        prev_packets_received = packets_received;
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "ESP32 Security Device starting...");
    
    /* Initialize SD card if logging is enabled */
#ifdef CONFIG_SECURITY_LOG_TO_SDCARD
    if (init_sdcard() != ESP_OK) {
        ESP_LOGW(TAG, "SD card initialization failed, continuing without SD card");
    }
#endif

    /* Initialize packet capture on the configured channel */
    esp_err_t ret = packet_capture_init(CONFIG_SECURITY_PROMISCUOUS_CHANNEL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize packet capture: %s", esp_err_to_name(ret));
        return;
    }
    
    /* Register packet handler */
    ret = packet_capture_register_handler(packet_handler, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register packet handler: %s", esp_err_to_name(ret));
        return;
    }
    
    /* Start packet capture */
    ret = packet_capture_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start packet capture: %s", esp_err_to_name(ret));
        return;
    }
    
    /* Create statistics reporting task */
    xTaskCreate(stats_task, "stats_task", 4096, NULL, 5, NULL);
    
    ESP_LOGI(TAG, "ESP32 Security Device is now monitoring on channel %d", CONFIG_SECURITY_PROMISCUOUS_CHANNEL);
    ESP_LOGI(TAG, "Captured packets are being saved to PCAP files on the SD card");

#ifdef CONFIG_SECURITY_ENABLE_WIRESHARK_STREAMING
    ESP_LOGI(TAG, "Wireshark streaming is enabled on port %d", CONFIG_SECURITY_WIRESHARK_STREAMING_PORT);
    ESP_LOGI(TAG, "To connect Wireshark, select 'Capture > Options', add a UDP interface on port %d", 
             CONFIG_SECURITY_WIRESHARK_STREAMING_PORT);
#endif
} 