#!/usr/bin/env python3
"""
ESP32 Security Simulation - Installation and Runner

This script handles installing dependencies and running the application
in the correct order with proper error handling.
"""

import subprocess
import sys
import os
import platform
import time
import shutil

def run_command(command, desc=None, check=True):
    """Run a command and return success status and output."""
    if desc:
        print(f"{desc}...")
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, check=check, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stdout.strip():
            print(result.stdout)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        if e.stderr.strip():
            print(f"Error: {e.stderr}")
        return False, e.stderr

def check_environment():
    """Check if running in a virtual environment."""
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    if not in_venv:
        print("WARNING: Not running in a virtual environment!")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print("Please activate your virtual environment and try again.")
            print("You can create and activate one with:")
            print("  python -m venv venv")
            if platform.system() == "Windows":
                print("  .\\venv\\Scripts\\activate")
            else:
                print("  source venv/bin/activate")
            return False
    return True

def install_basic_dependencies():
    """Install the most essential dependencies needed."""
    print("\n=== Installing Essential Dependencies ===")
    
    # First, upgrade pip
    run_command("python -m pip install --upgrade pip", "Upgrading pip")
    
    # Install Werkzeug first (Flask dependency)
    run_command("pip install werkzeug==2.0.1", "Installing Werkzeug")
    
    # Install Flask
    run_command("pip install flask==2.0.1", "Installing Flask")
    
    # Install a compatible version of numpy
    py_version = sys.version_info
    numpy_cmd = "pip install numpy"
    if py_version.major == 3:
        if py_version.minor < 7:
            numpy_cmd = "pip install numpy==1.16.6"  # For Python 3.6 or earlier
        elif py_version.minor < 9:
            numpy_cmd = "pip install numpy==1.21.6"  # For Python 3.7-3.8
        elif py_version.minor < 11:
            numpy_cmd = "pip install numpy==1.24.3"  # For Python 3.9-3.10
    
    run_command(numpy_cmd, f"Installing numpy for Python {py_version.major}.{py_version.minor}")
    
    # Install other core dependencies
    for pkg in ["requests", "pycryptodome"]:
        run_command(f"pip install {pkg}", f"Installing {pkg}")
    
    # Attempt to install scapy, but don't fail if it doesn't work
    run_command("pip install scapy==2.4.5", "Installing Scapy", check=False)

def update_simulator():
    """Replace the simulator.py file with our fixed version."""
    simulator_path = os.path.join("network", "simulator.py")
    fixed_simulator_path = os.path.join("network", "simulator_fixed.py")
    
    if not os.path.exists(fixed_simulator_path):
        print("Fixed simulator file not found. Skipping update.")
        return False
    
    # Make backup if needed
    if os.path.exists(simulator_path):
        backup_path = f"{simulator_path}.bak.{int(time.time())}"
        try:
            shutil.copy2(simulator_path, backup_path)
            print(f"Backed up original simulator to {backup_path}")
        except Exception as e:
            print(f"Warning: Failed to backup simulator: {e}")
    
    # Copy fixed version
    try:
        shutil.copy2(fixed_simulator_path, simulator_path)
        print(f"Updated {simulator_path} with fixed version")
        return True
    except Exception as e:
        print(f"Error updating simulator: {e}")
        return False

def run_application():
    """Run the main application."""
    print("\n=== Running the Application ===")
    print("Starting ESP32 Security Simulation...\n")
    
    try:
        # Use subprocess.run with check=False to avoid exception if it fails
        process = subprocess.run(["python", "main.py"], check=False)
        return process.returncode == 0
    except Exception as e:
        print(f"Error running application: {e}")
        return False

def main():
    """Main entry point."""
    print("\n" + "=" * 60)
    print("ESP32 Security Simulation - Install and Run")
    print("=" * 60)
    
    # Check Python version
    py_version = sys.version_info
    print(f"Python version: {py_version.major}.{py_version.minor}.{py_version.micro}")
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    # Install basic dependencies
    install_basic_dependencies()
    
    # Update simulator
    updated = update_simulator()
    if not updated:
        print("\nWARNING: Could not update the simulator code.")
        print("The application may not run correctly.")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print("Exiting. Please check the simulator file manually.")
            sys.exit(1)
    
    # Run the application
    success = run_application()
    
    if success:
        print("\n" + "=" * 60)
        print("Application completed successfully!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("Application encountered errors.")
        print("Please check the logs for details.")
        print("=" * 60)
        
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
