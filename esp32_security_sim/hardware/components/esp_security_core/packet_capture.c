#include <string.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_system.h"

#include "packet_capture.h"

/* Include PCAP component if enabled */
#ifdef CONFIG_SECURITY_ENABLE_PCAP
#include "esp_pcap.h"
#endif

static const char *TAG = "PACKET_CAPTURE";

/* Packet capture context */
typedef struct {
    bool initialized;
    bool running;
    uint8_t channel;
    packet_handler_t packet_handler;
    void *user_data;
    uint32_t packets_received;
    uint32_t packets_dropped;
    SemaphoreHandle_t mutex;
} packet_capture_ctx_t;

static packet_capture_ctx_t s_capture_ctx = {
    .initialized = false,
    .running = false,
    .channel = 1,
    .packet_handler = NULL,
    .user_data = NULL,
    .packets_received = 0,
    .packets_dropped = 0,
    .mutex = NULL
};

/* WiFi promiscuous mode receive callback */
static void wifi_sniffer_packet_handler(void *recv_buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) {
        ESP_LOGD(TAG, "Received packet of unknown type: %d", type);
        return;
    }

    /* Get reference to the received packet */
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)recv_buf;
    uint8_t *payload = pkt->payload;
    size_t len = pkt->rx_ctrl.sig_len;

    /* Get current timestamp */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t timestamp_us = (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;

    /* Update statistics */
    xSemaphoreTake(s_capture_ctx.mutex, portMAX_DELAY);
    s_capture_ctx.packets_received++;
    xSemaphoreGive(s_capture_ctx.mutex);

    /* Call packet handler if registered */
    if (s_capture_ctx.packet_handler != NULL) {
        s_capture_ctx.packet_handler(s_capture_ctx.user_data, payload, len, timestamp_us);
    }

#ifdef CONFIG_SECURITY_ENABLE_PCAP
    /* Write packet to PCAP file/stream if enabled */
    if (esp_pcap_is_initialized() && esp_pcap_is_capturing()) {
        esp_pcap_write_packet(payload, len, timestamp_us);
    }
#endif
}

esp_err_t packet_capture_init(uint8_t wifi_channel) {
    esp_err_t ret = ESP_OK;

    /* Check if already initialized */
    if (s_capture_ctx.initialized) {
        ESP_LOGW(TAG, "Packet capture already initialized");
        return ESP_OK;
    }

    /* Create mutex for thread safety */
    s_capture_ctx.mutex = xSemaphoreCreateMutex();
    if (s_capture_ctx.mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return ESP_ERR_NO_MEM;
    }

    /* Initialize NVS */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS flash");
        nvs_flash_erase();
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize NVS: %s", esp_err_to_name(ret));
        vSemaphoreDelete(s_capture_ctx.mutex);
        return ret;
    }

    /* Initialize WiFi with default config */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init WiFi: %s", esp_err_to_name(ret));
        vSemaphoreDelete(s_capture_ctx.mutex);
        return ret;
    }

    /* Set WiFi to station mode */
    ret = esp_wifi_set_mode(WIFI_MODE_STA);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set WiFi mode: %s", esp_err_to_name(ret));
        esp_wifi_deinit();
        vSemaphoreDelete(s_capture_ctx.mutex);
        return ret;
    }

    /* Start WiFi */
    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start WiFi: %s", esp_err_to_name(ret));
        esp_wifi_deinit();
        vSemaphoreDelete(s_capture_ctx.mutex);
        return ret;
    }

    /* Store channel for later use */
    s_capture_ctx.channel = wifi_channel;

#ifdef CONFIG_SECURITY_ENABLE_PCAP
    /* Initialize PCAP capture if enabled */
    esp_pcap_config_t pcap_config = {
        .base_path = CONFIG_SECURITY_SDCARD_MOUNT_POINT "/pcap",
        .filename_prefix = CONFIG_SECURITY_PCAP_FILENAME_PREFIX,
        .max_file_size_bytes = CONFIG_SECURITY_PCAP_MAX_FILE_SIZE_MB * 1024 * 1024,
        .max_files = CONFIG_SECURITY_PCAP_MAX_FILES,
        .network_type = PCAP_NETWORK_WIFI,  /* IEEE 802.11 wireless */
        .mode = ESP_PCAP_CAPTURE_MODE_CONTINUOUS,
#ifdef CONFIG_SECURITY_ENABLE_WIRESHARK_STREAMING
        .enable_streaming = true,
        .streaming_port = CONFIG_SECURITY_WIRESHARK_STREAMING_PORT,
        .streaming_ip = (strlen(CONFIG_SECURITY_WIRESHARK_STREAMING_IP) > 0) ? CONFIG_SECURITY_WIRESHARK_STREAMING_IP : NULL,
#else
        .enable_streaming = false,
#endif
    };

    ret = esp_pcap_init(&pcap_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize PCAP capture: %s", esp_err_to_name(ret));
        /* Continue anyway, as PCAP is optional */
    } else {
        /* Start PCAP capture */
        ret = esp_pcap_start_capture();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start PCAP capture: %s", esp_err_to_name(ret));
            /* Continue anyway, as PCAP is optional */
        }
    }
#endif

    s_capture_ctx.initialized = true;
    ESP_LOGI(TAG, "Packet capture initialized on channel %d", wifi_channel);

    return ESP_OK;
}

esp_err_t packet_capture_start(void) {
    esp_err_t ret = ESP_OK;

    if (!s_capture_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Take mutex */
    if (xSemaphoreTake(s_capture_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    if (!s_capture_ctx.running) {
        /* Set WiFi channel */
        ret = esp_wifi_set_channel(s_capture_ctx.channel, WIFI_SECOND_CHAN_NONE);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set WiFi channel: %s", esp_err_to_name(ret));
            xSemaphoreGive(s_capture_ctx.mutex);
            return ret;
        }

        /* Set filter to receive all packets */
        ret = esp_wifi_set_promiscuous_filter(NULL);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set promiscuous filter: %s", esp_err_to_name(ret));
            xSemaphoreGive(s_capture_ctx.mutex);
            return ret;
        }

        /* Set the packet handler */
        ret = esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set promiscuous callback: %s", esp_err_to_name(ret));
            xSemaphoreGive(s_capture_ctx.mutex);
            return ret;
        }

        /* Enable promiscuous mode */
        ret = esp_wifi_set_promiscuous(true);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to enable promiscuous mode: %s", esp_err_to_name(ret));
            xSemaphoreGive(s_capture_ctx.mutex);
            return ret;
        }

        s_capture_ctx.running = true;
        ESP_LOGI(TAG, "Packet capture started on channel %d", s_capture_ctx.channel);
    } else {
        ESP_LOGW(TAG, "Packet capture already running");
    }

    /* Release mutex */
    xSemaphoreGive(s_capture_ctx.mutex);

    return ESP_OK;
}

esp_err_t packet_capture_stop(void) {
    esp_err_t ret = ESP_OK;

    if (!s_capture_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Take mutex */
    if (xSemaphoreTake(s_capture_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    if (s_capture_ctx.running) {
        /* Disable promiscuous mode */
        ret = esp_wifi_set_promiscuous(false);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to disable promiscuous mode: %s", esp_err_to_name(ret));
            xSemaphoreGive(s_capture_ctx.mutex);
            return ret;
        }

        s_capture_ctx.running = false;
        ESP_LOGI(TAG, "Packet capture stopped");
    } else {
        ESP_LOGW(TAG, "Packet capture not running");
    }

    /* Release mutex */
    xSemaphoreGive(s_capture_ctx.mutex);

    return ESP_OK;
}

esp_err_t packet_capture_register_handler(packet_handler_t callback, void *user_data) {
    if (!s_capture_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Take mutex */
    if (xSemaphoreTake(s_capture_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    s_capture_ctx.packet_handler = callback;
    s_capture_ctx.user_data = user_data;

    /* Release mutex */
    xSemaphoreGive(s_capture_ctx.mutex);

    ESP_LOGI(TAG, "Packet handler registered");
    return ESP_OK;
}

esp_err_t packet_capture_get_stats(uint32_t *packets_received, uint32_t *packets_dropped) {
    if (!s_capture_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (packets_received == NULL || packets_dropped == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Take mutex */
    if (xSemaphoreTake(s_capture_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    *packets_received = s_capture_ctx.packets_received;
    *packets_dropped = s_capture_ctx.packets_dropped;

    /* Release mutex */
    xSemaphoreGive(s_capture_ctx.mutex);

    return ESP_OK;
} 