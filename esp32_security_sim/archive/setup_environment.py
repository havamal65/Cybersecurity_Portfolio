#!/usr/bin/env python3
"""
ESP32 Security Simulation Setup Script

This script sets up the development environment for the ESP32 security simulation
by installing required dependencies and checking for compatibility issues.
"""

import subprocess
import sys
import platform
import os
from pathlib import Path

def check_python_version():
    """Check if the current Python version is compatible with our requirements."""
    python_version = sys.version_info
    print(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    if (python_version.major == 3 and python_version.minor < 7) or \
       (python_version.major == 3 and python_version.minor > 10):
        print("WARNING: This project is designed for Python 3.7-3.10.")
        print(f"Your Python version is {python_version.major}.{python_version.minor}.{python_version.micro}")
        return False
    return True

def run_command(command, description):
    """Run a shell command and handle errors."""
    print(f"\n{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error during {description}:")
        print(f"Command: {command}")
        print(f"Exit code: {e.returncode}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return False

def setup_virtual_environment():
    """Set up a virtual environment if not already activated."""
    # Check if we're already in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("Already in a virtual environment")
        return True
    
    venv_path = Path("venv")
    if venv_path.exists():
        print("Virtual environment already exists")
    else:
        if not run_command("python -m venv venv", "Creating virtual environment"):
            return False
    
    # Provide activation instructions
    if platform.system() == "Windows":
        print("\nTo activate the virtual environment, run:")
        print(r".\venv\Scripts\activate")
    else:
        print("\nTo activate the virtual environment, run:")
        print("source venv/bin/activate")
    
    return True

def install_dependencies():
    """Install required dependencies."""
    # Upgrade pip first
    if not run_command("python -m pip install --upgrade pip", "Upgrading pip"):
        return False
    
    # Try the flexible requirements first
    if Path("requirements_flexible.txt").exists():
        success = run_command("pip install -r requirements_flexible.txt", 
                             "Installing dependencies from requirements_flexible.txt")
        if success:
            return True
    
    # If that fails or the file doesn't exist, try installing dependencies individually
    print("\nAttempting to install dependencies individually...")
    
    dependencies = [
        "flask>=2.0.0,<2.1.0",
        "scapy>=2.4.0",
        "cryptography>=36.0.0",
        "numpy>=1.19.0",
        "requests>=2.26.0",
        "flask-wtf>=1.0.0",
        "flask-sqlalchemy>=2.5.0",
        "netifaces>=0.11.0",
        "pytest>=6.2.0",
        "coverage>=6.1.0",
        "pycryptodome>=3.10.0"  # Instead of pycrypto
    ]
    
    success = True
    for dep in dependencies:
        if not run_command(f"pip install {dep}", f"Installing {dep}"):
            success = False
            print(f"Warning: Failed to install {dep}")
    
    return success

def update_requirements():
    """Update the requirements.txt file with the actually installed versions."""
    print("\nUpdating requirements.txt with actual installed versions...")
    if run_command("pip freeze > requirements_installed.txt", 
                  "Generating requirements_installed.txt"):
        print("Successfully created requirements_installed.txt with actual installed packages.")
        print("Review this file and update your main requirements.txt if needed.")
    else:
        print("Failed to generate requirements_installed.txt")

def main():
    """Main setup function."""
    print("=" * 80)
    print("ESP32 Security Simulation - Environment Setup")
    print("=" * 80)
    
    # Check Python version
    version_ok = check_python_version()
    if not version_ok:
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print("Setup aborted. Please use Python 3.7-3.10.")
            sys.exit(1)
    
    # Setup virtual environment
    if not setup_virtual_environment():
        print("Failed to set up virtual environment. Please check error messages above.")
        sys.exit(1)
    
    # Check if we're running in the virtual environment
    if not (hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)):
        print("\nWARNING: Not running in a virtual environment.")
        print("It's recommended to activate the virtual environment before installing dependencies.")
        response = input("Continue without virtual environment? (y/n): ").strip().lower()
        if response != 'y':
            print("Setup aborted. Please activate the virtual environment and run this script again.")
            sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\nWARNING: Some dependencies failed to install.")
        print("You may need to install them manually or troubleshoot the issues.")
    else:
        print("\nAll dependencies were installed successfully!")
    
    # Update requirements file
    update_requirements()
    
    print("\n" + "=" * 80)
    print("Setup completed!")
    print("You can now run the application with: python main.py")
    print("=" * 80)

if __name__ == "__main__":
    main()
