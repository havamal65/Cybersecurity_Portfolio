#!/usr/bin/env python3
"""
Direct Entry Point for ESP32 Security Simulation

This script provides a direct entry point that imports packages
within function scope to avoid top-level import issues.
"""

import os
import sys
import importlib
import importlib.util
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('direct_run.log')
    ]
)

logger = logging.getLogger(__name__)

def check_package(package_name):
    """Check if a package can be imported and log its location."""
    try:
        package = importlib.import_module(package_name)
        file_location = getattr(package, "__file__", "Unknown location")
        logger.info(f"Successfully imported {package_name} from {file_location}")
        return True
    except ImportError as e:
        logger.error(f"Failed to import {package_name}: {e}")
        return False

def check_critical_dependencies():
    """Check if all critical dependencies are available."""
    critical_packages = [
        "flask", "werkzeug", "scapy", "cryptography"
    ]
    
    all_available = True
    for package in critical_packages:
        if not check_package(package):
            all_available = False
    
    return all_available

def ensure_site_packages():
    """Ensure the virtual environment site-packages is in sys.path."""
    venv_path = sys.prefix
    site_packages = os.path.join(venv_path, 'Lib', 'site-packages')
    
    if site_packages not in sys.path:
        logger.info(f"Adding {site_packages} to sys.path")
        sys.path.insert(0, site_packages)

def run_simulation():
    """Run the simulation directly."""
    logger.info("Starting ESP32 security simulation")
    
    # Ensure site-packages is in path
    ensure_site_packages()
    
    # Check if dependencies are available
    if not check_critical_dependencies():
        logger.error("Critical dependencies missing. Cannot continue.")
        return False
    
    try:
        # Import core components
        from core.engine import SimulationEngine
        logger.info("Successfully imported SimulationEngine")
        
        # Set up a basic simulation engine with no components
        engine = SimulationEngine({})
        
        # Try loading individual components one by one
        try:
            from network.simulator import NetworkSimulator
            logger.info("Successfully loaded NetworkSimulator")
            network = NetworkSimulator(engine, {})
        except ImportError as e:
            logger.warning(f"Could not load NetworkSimulator: {e}")
        
        try:
            from security.mac_randomization import MacRandomizer
            logger.info("Successfully loaded MacRandomizer")
            mac = MacRandomizer(engine, {})
        except ImportError as e:
            logger.warning(f"Could not load MacRandomizer: {e}")
        
        try:
            from security.firewall import Firewall
            logger.info("Successfully loaded Firewall")
            firewall = Firewall(engine, {})
        except ImportError as e:
            logger.warning(f"Could not load Firewall: {e}")
        
        try:
            from security.encryption import EncryptionManager
            logger.info("Successfully loaded EncryptionManager")
            encryption = EncryptionManager(engine, {})
        except ImportError as e:
            logger.warning(f"Could not load EncryptionManager: {e}")
        
        try:
            from detection.ids import IntrusionDetectionSystem
            logger.info("Successfully loaded IntrusionDetectionSystem")
            ids = IntrusionDetectionSystem(engine, {})
        except ImportError as e:
            logger.warning(f"Could not load IntrusionDetectionSystem: {e}")
        
        # Try loading the dashboard
        try:
            from dashboard.app import DashboardServer
            logger.info("Successfully loaded DashboardServer")
            dashboard = DashboardServer(engine, {})
        except ImportError as e:
            logger.warning(f"Could not load DashboardServer: {e}")
            logger.info("Continuing without dashboard")
        
        # Start the simulation for a few cycles
        logger.info("Running simulation for 10 cycles")
        engine.start()
        for i in range(10):
            engine.update()
        
        logger.info("Simulation completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error during simulation: {e}", exc_info=True)
        return False

def main():
    """Main entry point."""
    print("=" * 60)
    print("ESP32 Security Simulation - Direct Runner")
    print("=" * 60)
    
    print("Starting simulation with detailed logging...")
    print("Check direct_run.log for detailed information.")
    
    success = run_simulation()
    
    if success:
        print("\nSimulation completed successfully!")
    else:
        print("\nSimulation encountered errors.")
        print("Check direct_run.log for details.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
