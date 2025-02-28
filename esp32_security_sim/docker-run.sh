#!/bin/bash
# Simple script to run the ESP32 Security Simulation in Docker

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Please install Docker first: https://www.docker.com/get-started"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Warning: docker-compose is not installed or not in PATH"
    echo "Using Docker directly instead of docker-compose"
    
    # Build Docker image
    echo "Building Docker image..."
    docker build -t esp32-security-sim .
    
    # Run Docker container
    echo "Starting ESP32 Security Simulation..."
    docker run -p 5000:5000 --rm esp32-security-sim "$@"
else
    # Use docker-compose
    echo "Starting ESP32 Security Simulation with docker-compose..."
    if [ $# -eq 0 ]; then
        # No arguments provided, just run with default settings
        docker-compose up
    else
        # Arguments provided, pass them to the container
        docker-compose run --rm --service-ports esp32-security-sim "$@"
    fi
fi 