/**
 * ESP32 Security Implementation - Main Application
 * 
 * This is the main entry point for the ESP32 security device application.
 * It initializes the hardware and starts the security components.
 */

#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "packet_capture.h"

static const char *TAG = "ESP_SECURITY_MAIN";

// Task for periodic status reporting
static void status_report_task(void *pvParameters) {
    uint32_t captured, analyzed, blocked, allowed;
    uint64_t start_time = esp_timer_get_time();
    
    while (1) {
        // Get current stats
        get_capture_stats(&captured, &analyzed, &blocked, &allowed);
        
        // Calculate runtime in seconds
        uint64_t now = esp_timer_get_time();
        float runtime_seconds = (float)(now - start_time) / 1000000.0f;
        
        // Print status report
        ESP_LOGI(TAG, "=== ESP32 Security Status Report ===");
        ESP_LOGI(TAG, "Runtime: %.1f seconds", runtime_seconds);
        ESP_LOGI(TAG, "Packets captured: %lu", captured);
        ESP_LOGI(TAG, "Packets analyzed: %lu", analyzed);
        ESP_LOGI(TAG, "Packets blocked: %lu (%.1f%%)", 
                 blocked, (blocked > 0) ? (100.0f * blocked / analyzed) : 0.0f);
        ESP_LOGI(TAG, "Packets allowed: %lu (%.1f%%)", 
                 allowed, (allowed > 0) ? (100.0f * allowed / analyzed) : 0.0f);
        ESP_LOGI(TAG, "Capture rate: %.2f packets/sec", 
                 (runtime_seconds > 0) ? (captured / runtime_seconds) : 0);
        ESP_LOGI(TAG, "====================================");
        
        // Wait 10 seconds before next report
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

void app_main(void) {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    ESP_LOGI(TAG, "ESP32 Security Device Starting...");
    
    // Initialize packet capture
    ESP_ERROR_CHECK(init_packet_capture());
    
    // Create status reporting task
    xTaskCreate(status_report_task, "status_report", 4096, NULL, tskIDLE_PRIORITY, NULL);
    
    ESP_LOGI(TAG, "ESP32 Security Device Running");
    ESP_LOGI(TAG, "=== Configuration ===");
    ESP_LOGI(TAG, "Monitoring mode: WiFi Promiscuous");
    ESP_LOGI(TAG, "Firewall: Active");
    ESP_LOGI(TAG, "IDS: Active");
    ESP_LOGI(TAG, "====================");
    
    // The main task has nothing more to do, as packet processing happens in other tasks
} 