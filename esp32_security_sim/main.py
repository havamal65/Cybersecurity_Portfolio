#!/usr/bin/env python3
"""
ESP32 Security Device Simulation - Main Entry Point

This script starts the ESP32 security device simulation, initializing all components
and providing a command-line interface to control the simulation.
"""

import logging
import argparse
import time
import signal
import sys
import json
import webbrowser
from pathlib import Path

# Import simulation components
from core.engine import SimulationEngine
from network.simulator import NetworkSimulator
from security.mac_randomization import MacRandomizer
from security.firewall import Firewall
from security.encryption import EncryptionManager
from detection.ids import IntrusionDetectionSystem
from dashboard.app import DashboardServer

def setup_logging(level):
    """
    Set up logging configuration with proper formatting.
    
    Args:
        level: Logging level (DEBUG, INFO, etc.)
    """
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('simulation.log')
        ]
    )

def parse_arguments():
    """
    Parse command-line arguments for controlling the simulation.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='ESP32 Security Device Simulation')
    
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-dashboard', action='store_true', help='Disable web dashboard')
    parser.add_argument('--no-network', action='store_true', help='Disable network simulation')
    parser.add_argument('--no-ids', action='store_true', help='Disable intrusion detection')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    parser.add_argument('--duration', type=int, default=0, help='Simulation duration in seconds (0 for unlimited)')
    parser.add_argument('--no-browser', action='store_true', help='Do not automatically open browser dashboard')
    
    return parser.parse_args()

def load_configuration(config_path):
    """
    Load configuration from a JSON file.
    
    Args:
        config_path (str): Path to configuration file
        
    Returns:
        dict: Configuration parameters
    """
    if not config_path:
        return {}
    
    config_path = Path(config_path)
    if not config_path.exists():
        logging.warning(f"Configuration file not found: {config_path}")
        return {}
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        return {}

def main():
    """Main entry point for the simulation."""
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
    
    # Load configuration
    config = load_configuration(args.config)
    
    # Create simulation engine
    engine_config = config.get('engine', {})
    engine_config['max_duration'] = args.duration
    sim_engine = SimulationEngine(engine_config)
    
    # Initialize components if enabled
    # Network simulation
    if not args.no_network:
        network_config = config.get('network', {})
        NetworkSimulator(sim_engine, network_config)
    
    # MAC randomization
    mac_config = config.get('mac_randomizer', {})
    MacRandomizer(sim_engine, mac_config)
    
    # Firewall
    firewall_config = config.get('firewall', {})
    Firewall(sim_engine, firewall_config)
    
    # Encryption
    encryption_config = config.get('encryption', {})
    EncryptionManager(sim_engine, encryption_config)
    
    # Intrusion detection
    if not args.no_ids:
        ids_config = config.get('ids', {})
        IntrusionDetectionSystem(sim_engine, ids_config)
    
    # Web dashboard settings
    dashboard_url = None
    if not args.no_dashboard:
        dashboard_config = config.get('dashboard', {})
        dashboard = DashboardServer(sim_engine, dashboard_config)
        
        # Prepare dashboard URL
        host = dashboard_config.get('host', '127.0.0.1')
        port = dashboard_config.get('port', 5000)
        dashboard_url = f"http://{host}:{port}/"
    
    # Handle termination signals
    def signal_handler(sig, frame):
        logging.info("Termination signal received, shutting down...")
        sim_engine.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the simulation
    logging.info("Starting ESP32 security device simulation")
    sim_engine.start()
    
    # Open browser if dashboard enabled and not explicitly disabled
    if dashboard_url and not args.no_browser:
        logging.info(f"Opening dashboard in browser: {dashboard_url}")
        # Use a small delay to ensure the server is ready
        time.sleep(1.5)
        webbrowser.open(dashboard_url)
    
    # Keep the main thread running
    try:
        print("\nESP32 Security Device Simulation is running.")
        if dashboard_url:
            print(f"Access the dashboard at {dashboard_url}")
        print("Press Ctrl+C to stop the simulation.\n")
        
        while sim_engine.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, shutting down...")
    finally:
        sim_engine.stop()
    
    logging.info("Simulation ended")

if __name__ == "__main__":
    main()
