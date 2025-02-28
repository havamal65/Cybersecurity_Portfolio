cmake_minimum_required(VERSION 3.5)

# Set the project name
project(esp32_security_device)

# Include the ESP-IDF components
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Add the main application
add_executable(${CMAKE_PROJECT_NAME} main/main_app.c)

# Include directories
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    main
    components/esp_security_core/include
    components/esp_pcap/include
)

# Link libraries
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
    esp_security_core
    esp_pcap
)

# Add dependencies for the project
set(COMPONENT_REQUIRES
    nvs_flash
    esp_wifi
    esp_event
    freertos
    lwip
    esp_netif
)

# This command actually creates the project
project(${CMAKE_PROJECT_NAME}) 