@echo off
REM Simple script to run the ESP32 Security Simulation in Docker on Windows

REM Check if Docker is installed
where docker >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Docker is not installed or not in PATH
    echo Please install Docker Desktop first: https://www.docker.com/products/docker-desktop
    exit /b 1
)

REM Check if docker-compose is installed
where docker-compose >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Warning: docker-compose is not installed or not in PATH
    echo Using Docker directly instead of docker-compose
    
    REM Build Docker image
    echo Building Docker image...
    docker build -t esp32-security-sim .
    
    REM Run Docker container
    echo Starting ESP32 Security Simulation...
    docker run -p 5000:5000 --rm esp32-security-sim %*
) else (
    REM Use docker-compose
    echo Starting ESP32 Security Simulation with docker-compose...
    if "%~1"=="" (
        REM No arguments provided, just run with default settings
        docker-compose up
    ) else (
        REM Arguments provided, pass them to the container
        docker-compose run --rm --service-ports esp32-security-sim %*
    )
)

echo.
echo Access the dashboard at http://localhost:5000/
echo Press Ctrl+C to stop the simulation. 