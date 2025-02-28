#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "esp_pcap.h"

static const char *TAG = "ESP_PCAP";

typedef struct {
    bool initialized;
    bool capturing;
    esp_pcap_config_t config;
    FILE *current_file;
    char current_filename[128];
    size_t current_file_size;
    int stream_socket;
    struct sockaddr_in stream_addr;
    SemaphoreHandle_t mutex;
} esp_pcap_ctx_t;

static esp_pcap_ctx_t s_pcap_ctx = {
    .initialized = false,
    .capturing = false,
    .current_file = NULL,
    .current_file_size = 0,
    .stream_socket = -1,
    .mutex = NULL
};

/* Helper function to get timestamp in microseconds */
static uint64_t get_timestamp_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/* Helper function to generate filename with timestamp */
static void generate_filename(char *filename, size_t max_len) {
    time_t now;
    struct tm timeinfo;
    
    time(&now);
    localtime_r(&now, &timeinfo);
    
    snprintf(filename, max_len, "%s/%s%04d%02d%02d_%02d%02d%02d.pcap",
             s_pcap_ctx.config.base_path,
             s_pcap_ctx.config.filename_prefix,
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

/* Create a new PCAP file with header */
static esp_err_t create_pcap_file(void) {
    pcap_file_header_t header;
    
    /* Close current file if open */
    if (s_pcap_ctx.current_file != NULL) {
        fclose(s_pcap_ctx.current_file);
        s_pcap_ctx.current_file = NULL;
    }
    
    /* Generate new filename */
    generate_filename(s_pcap_ctx.current_filename, sizeof(s_pcap_ctx.current_filename));
    
    /* Open new file */
    s_pcap_ctx.current_file = fopen(s_pcap_ctx.current_filename, "wb");
    if (s_pcap_ctx.current_file == NULL) {
        ESP_LOGE(TAG, "Failed to create PCAP file: %s", s_pcap_ctx.current_filename);
        return ESP_FAIL;
    }
    
    /* Initialize file header */
    header.magic_number = PCAP_MAGIC_NUMBER;
    header.version_major = PCAP_VERSION_MAJOR;
    header.version_minor = PCAP_VERSION_MINOR;
    header.thiszone = 0;  /* GMT */
    header.sigfigs = 0;   /* Accuracy of timestamps */
    header.snaplen = PCAP_SNAPLEN;
    header.network = s_pcap_ctx.config.network_type;
    
    /* Write header to file */
    if (fwrite(&header, sizeof(header), 1, s_pcap_ctx.current_file) != 1) {
        ESP_LOGE(TAG, "Failed to write PCAP header");
        fclose(s_pcap_ctx.current_file);
        s_pcap_ctx.current_file = NULL;
        return ESP_FAIL;
    }
    
    /* Reset file size counter (header size) */
    s_pcap_ctx.current_file_size = sizeof(header);
    
    ESP_LOGI(TAG, "Created new PCAP file: %s", s_pcap_ctx.current_filename);
    return ESP_OK;
}

/* Clean up old files if we have more than the maximum allowed */
static void cleanup_old_files(void) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char path[256];
    
    /* List of files to sort by age */
    typedef struct {
        char filename[128];
        time_t mtime;
    } file_info_t;
    
    file_info_t *files = NULL;
    size_t num_files = 0;
    size_t files_capacity = 16;
    
    /* Open directory */
    dir = opendir(s_pcap_ctx.config.base_path);
    if (dir == NULL) {
        ESP_LOGE(TAG, "Failed to open directory: %s", s_pcap_ctx.config.base_path);
        return;
    }
    
    /* Allocate initial array for files */
    files = calloc(files_capacity, sizeof(file_info_t));
    if (files == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for file list");
        closedir(dir);
        return;
    }
    
    /* Find all PCAP files in the directory */
    size_t prefix_len = strlen(s_pcap_ctx.config.filename_prefix);
    while ((entry = readdir(dir)) != NULL) {
        /* Check if it's a regular file with our prefix and .pcap extension */
        if (entry->d_type == DT_REG && 
            strncmp(entry->d_name, s_pcap_ctx.config.filename_prefix, prefix_len) == 0 &&
            strstr(entry->d_name, ".pcap") != NULL) {
            
            /* Get file stat for modification time */
            snprintf(path, sizeof(path), "%s/%s", s_pcap_ctx.config.base_path, entry->d_name);
            if (stat(path, &st) == 0) {
                /* Resize array if needed */
                if (num_files >= files_capacity) {
                    files_capacity *= 2;
                    file_info_t *new_files = realloc(files, files_capacity * sizeof(file_info_t));
                    if (new_files == NULL) {
                        ESP_LOGE(TAG, "Failed to resize file list");
                        break;
                    }
                    files = new_files;
                }
                
                /* Add file to list */
                strncpy(files[num_files].filename, entry->d_name, sizeof(files[num_files].filename) - 1);
                files[num_files].mtime = st.st_mtime;
                num_files++;
            }
        }
    }
    
    closedir(dir);
    
    /* If we have more files than allowed, sort by age and delete oldest */
    if (num_files > s_pcap_ctx.config.max_files) {
        /* Simple bubble sort by modification time (oldest first) */
        for (size_t i = 0; i < num_files - 1; i++) {
            for (size_t j = 0; j < num_files - i - 1; j++) {
                if (files[j].mtime > files[j + 1].mtime) {
                    file_info_t temp = files[j];
                    files[j] = files[j + 1];
                    files[j + 1] = temp;
                }
            }
        }
        
        /* Delete oldest files */
        size_t delete_count = num_files - s_pcap_ctx.config.max_files;
        for (size_t i = 0; i < delete_count; i++) {
            snprintf(path, sizeof(path), "%s/%s", s_pcap_ctx.config.base_path, files[i].filename);
            if (remove(path) == 0) {
                ESP_LOGI(TAG, "Deleted old PCAP file: %s", files[i].filename);
            } else {
                ESP_LOGE(TAG, "Failed to delete file %s: %s", files[i].filename, strerror(errno));
            }
        }
    }
    
    free(files);
}

/* Initialize the streaming socket */
static esp_err_t init_streaming_socket(void) {
    if (!s_pcap_ctx.config.enable_streaming) {
        return ESP_OK;
    }
    
    /* Create UDP socket */
    s_pcap_ctx.stream_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_pcap_ctx.stream_socket < 0) {
        ESP_LOGE(TAG, "Failed to create streaming socket");
        return ESP_FAIL;
    }
    
    /* Set up destination address */
    memset(&s_pcap_ctx.stream_addr, 0, sizeof(s_pcap_ctx.stream_addr));
    s_pcap_ctx.stream_addr.sin_family = AF_INET;
    s_pcap_ctx.stream_addr.sin_port = htons(s_pcap_ctx.config.streaming_port);
    
    if (s_pcap_ctx.config.streaming_ip != NULL) {
        inet_aton(s_pcap_ctx.config.streaming_ip, &s_pcap_ctx.stream_addr.sin_addr);
    } else {
        /* Default to broadcast */
        s_pcap_ctx.stream_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    }
    
    ESP_LOGI(TAG, "Wireshark streaming initialized to %s:%d", 
             s_pcap_ctx.config.streaming_ip ? s_pcap_ctx.config.streaming_ip : "255.255.255.255",
             s_pcap_ctx.config.streaming_port);
    
    return ESP_OK;
}

/* Stream a packet to Wireshark */
static void stream_packet(const uint8_t *packet_data, uint32_t packet_len, 
                         uint32_t ts_sec, uint32_t ts_usec) {
    if (s_pcap_ctx.stream_socket < 0 || !s_pcap_ctx.config.enable_streaming) {
        return;
    }
    
    /* Allocate buffer for packet header + data */
    uint8_t *buffer = malloc(sizeof(pcap_packet_header_t) + packet_len);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate buffer for streaming");
        return;
    }
    
    /* Fill in packet header */
    pcap_packet_header_t *phdr = (pcap_packet_header_t *)buffer;
    phdr->ts_sec = ts_sec;
    phdr->ts_usec = ts_usec;
    phdr->incl_len = packet_len;
    phdr->orig_len = packet_len;
    
    /* Copy packet data after header */
    memcpy(buffer + sizeof(pcap_packet_header_t), packet_data, packet_len);
    
    /* Send packet to Wireshark */
    ssize_t sent = sendto(s_pcap_ctx.stream_socket, buffer, sizeof(pcap_packet_header_t) + packet_len,
                  0, (struct sockaddr *)&s_pcap_ctx.stream_addr, sizeof(s_pcap_ctx.stream_addr));
    
    if (sent < 0) {
        ESP_LOGD(TAG, "Failed to send packet to Wireshark: %s", strerror(errno));
    }
    
    free(buffer);
}

/* Public API functions */

esp_err_t esp_pcap_init(const esp_pcap_config_t *config) {
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Check if already initialized */
    if (s_pcap_ctx.initialized) {
        ESP_LOGW(TAG, "PCAP capture already initialized");
        return ESP_OK;
    }
    
    /* Create mutex for thread safety */
    s_pcap_ctx.mutex = xSemaphoreCreateMutex();
    if (s_pcap_ctx.mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return ESP_ERR_NO_MEM;
    }
    
    /* Copy configuration */
    memcpy(&s_pcap_ctx.config, config, sizeof(esp_pcap_config_t));
    
    /* Make base directory if it doesn't exist */
    mkdir(s_pcap_ctx.config.base_path, 0755);
    
    /* Init streaming socket if needed */
    if (config->enable_streaming) {
        if (init_streaming_socket() != ESP_OK) {
            vSemaphoreDelete(s_pcap_ctx.mutex);
            return ESP_FAIL;
        }
    }
    
    /* Try cleaning up old files */
    cleanup_old_files();
    
    s_pcap_ctx.initialized = true;
    ESP_LOGI(TAG, "PCAP capture initialized with base path: %s", config->base_path);
    
    return ESP_OK;
}

esp_err_t esp_pcap_start_capture(void) {
    esp_err_t ret = ESP_OK;
    
    if (!s_pcap_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    /* Take mutex */
    if (xSemaphoreTake(s_pcap_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }
    
    if (!s_pcap_ctx.capturing) {
        /* Create initial PCAP file */
        ret = create_pcap_file();
        if (ret == ESP_OK) {
            s_pcap_ctx.capturing = true;
            ESP_LOGI(TAG, "PCAP capture started");
        }
    } else {
        ESP_LOGW(TAG, "PCAP capture already active");
    }
    
    /* Release mutex */
    xSemaphoreGive(s_pcap_ctx.mutex);
    
    return ret;
}

esp_err_t esp_pcap_stop_capture(void) {
    if (!s_pcap_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    /* Take mutex */
    if (xSemaphoreTake(s_pcap_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }
    
    if (s_pcap_ctx.capturing) {
        /* Close current file if open */
        if (s_pcap_ctx.current_file != NULL) {
            fclose(s_pcap_ctx.current_file);
            s_pcap_ctx.current_file = NULL;
        }
        s_pcap_ctx.capturing = false;
        ESP_LOGI(TAG, "PCAP capture stopped");
    } else {
        ESP_LOGW(TAG, "PCAP capture not active");
    }
    
    /* Release mutex */
    xSemaphoreGive(s_pcap_ctx.mutex);
    
    return ESP_OK;
}

esp_err_t esp_pcap_write_packet(const uint8_t *packet_data, uint32_t packet_len, uint64_t timestamp_us) {
    esp_err_t ret = ESP_OK;
    
    if (!s_pcap_ctx.initialized || !s_pcap_ctx.capturing) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (packet_data == NULL || packet_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Get timestamp if not provided */
    if (timestamp_us == 0) {
        timestamp_us = get_timestamp_us();
    }
    
    uint32_t ts_sec = timestamp_us / 1000000;
    uint32_t ts_usec = timestamp_us % 1000000;
    
    /* First, stream packet if enabled (do this outside the mutex to avoid delays) */
    stream_packet(packet_data, packet_len, ts_sec, ts_usec);
    
    /* Take mutex */
    if (xSemaphoreTake(s_pcap_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }
    
    /* Create file if not open */
    if (s_pcap_ctx.current_file == NULL) {
        if (create_pcap_file() != ESP_OK) {
            xSemaphoreGive(s_pcap_ctx.mutex);
            return ESP_FAIL;
        }
    }
    
    /* Create packet header */
    pcap_packet_header_t phdr;
    phdr.ts_sec = ts_sec;
    phdr.ts_usec = ts_usec;
    phdr.incl_len = packet_len;
    phdr.orig_len = packet_len;
    
    /* Write packet header */
    if (fwrite(&phdr, sizeof(phdr), 1, s_pcap_ctx.current_file) != 1) {
        ESP_LOGE(TAG, "Failed to write packet header");
        ret = ESP_FAIL;
        goto exit;
    }
    
    /* Write packet data */
    if (fwrite(packet_data, 1, packet_len, s_pcap_ctx.current_file) != packet_len) {
        ESP_LOGE(TAG, "Failed to write packet data");
        ret = ESP_FAIL;
        goto exit;
    }
    
    /* Update file size */
    s_pcap_ctx.current_file_size += sizeof(phdr) + packet_len;
    
    /* Flush data to disk */
    fflush(s_pcap_ctx.current_file);
    
    /* Check if we need to rotate file */
    if (s_pcap_ctx.current_file_size >= s_pcap_ctx.config.max_file_size_bytes) {
        /* Close current file */
        fclose(s_pcap_ctx.current_file);
        s_pcap_ctx.current_file = NULL;
        
        /* Clean up old files */
        cleanup_old_files();
        
        /* Create new file */
        if (create_pcap_file() != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create new file after rotation");
            ret = ESP_FAIL;
        }
    }
    
exit:
    /* Release mutex */
    xSemaphoreGive(s_pcap_ctx.mutex);
    
    return ret;
}

bool esp_pcap_is_initialized(void) {
    return s_pcap_ctx.initialized;
}

bool esp_pcap_is_capturing(void) {
    return s_pcap_ctx.capturing;
}

esp_err_t esp_pcap_get_file_list(char **files, size_t max_files, size_t *num_files) {
    if (!s_pcap_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (files == NULL || max_files == 0 || num_files == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    *num_files = 0;
    
    DIR *dir;
    struct dirent *entry;
    
    /* Open directory */
    dir = opendir(s_pcap_ctx.config.base_path);
    if (dir == NULL) {
        ESP_LOGE(TAG, "Failed to open directory: %s", s_pcap_ctx.config.base_path);
        return ESP_FAIL;
    }
    
    /* Find all PCAP files in the directory */
    size_t prefix_len = strlen(s_pcap_ctx.config.filename_prefix);
    while ((entry = readdir(dir)) != NULL && *num_files < max_files) {
        /* Check if it's a regular file with our prefix and .pcap extension */
        if (entry->d_type == DT_REG && 
            strncmp(entry->d_name, s_pcap_ctx.config.filename_prefix, prefix_len) == 0 &&
            strstr(entry->d_name, ".pcap") != NULL) {
            
            /* Copy filename to result array */
            strncpy(files[*num_files], entry->d_name, 255);
            (*num_files)++;
        }
    }
    
    closedir(dir);
    return ESP_OK;
}

esp_err_t esp_pcap_rotate_file(void) {
    esp_err_t ret = ESP_OK;
    
    if (!s_pcap_ctx.initialized || !s_pcap_ctx.capturing) {
        return ESP_ERR_INVALID_STATE;
    }
    
    /* Take mutex */
    if (xSemaphoreTake(s_pcap_ctx.mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }
    
    /* Close current file if open */
    if (s_pcap_ctx.current_file != NULL) {
        fclose(s_pcap_ctx.current_file);
        s_pcap_ctx.current_file = NULL;
    }
    
    /* Clean up old files */
    cleanup_old_files();
    
    /* Create new file */
    ret = create_pcap_file();
    
    /* Release mutex */
    xSemaphoreGive(s_pcap_ctx.mutex);
    
    return ret;
}

esp_err_t esp_pcap_delete_file(const char *filename) {
    char path[256];
    
    if (!s_pcap_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (filename == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Validate filename (should not contain path separators) */
    if (strchr(filename, '/') != NULL || strchr(filename, '\\') != NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Check if it starts with our prefix and has .pcap extension */
    size_t prefix_len = strlen(s_pcap_ctx.config.filename_prefix);
    if (strncmp(filename, s_pcap_ctx.config.filename_prefix, prefix_len) != 0 ||
        strstr(filename, ".pcap") == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Build full path */
    snprintf(path, sizeof(path), "%s/%s", s_pcap_ctx.config.base_path, filename);
    
    /* Delete file */
    if (remove(path) != 0) {
        ESP_LOGE(TAG, "Failed to delete file %s: %s", path, strerror(errno));
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Deleted PCAP file: %s", filename);
    return ESP_OK;
} 