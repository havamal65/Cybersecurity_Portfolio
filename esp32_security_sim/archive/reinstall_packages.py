#!/usr/bin/env python3
"""
ESP32 Security Simulation - Package Reinstallation Script

This script reinstalls all required packages in the current Python environment,
ensuring they're installed in the correct location and properly available.
"""

import subprocess
import sys
import os
import platform
import time

def run_command(command, desc=None):
    """Run a command and return success status and output."""
    if desc:
        print(f"{desc}...")
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, check=True, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stdout.strip():
            print(result.stdout)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        if e.stderr.strip():
            print(f"Error: {e.stderr}")
        return False, e.stderr

def check_environment():
    """Check if running in a virtual environment and provide environment info."""
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    print("=== Python Environment Information ===")
    print(f"Python version: {sys.version}")
    print(f"Python executable: {sys.executable}")
    print(f"Running in virtual environment: {'Yes' if in_venv else 'No'}")
    
    if in_venv:
        print(f"Virtual environment path: {sys.prefix}")
    else:
        print("WARNING: Not running in a virtual environment!")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print("Please activate your virtual environment and try again.")
            print("You can activate it with:")
            if platform.system() == "Windows":
                print("  .\\venv\\Scripts\\activate")
            else:
                print("  source venv/bin/activate")
            return False
    
    # Check pip installation
    run_command("pip --version", "Checking pip version")
    
    # List currently installed packages
    run_command("pip list", "Currently installed packages")
    
    return True

def uninstall_packages():
    """Uninstall problematic packages to ensure clean reinstallation."""
    print("\n=== Uninstalling Packages ===")
    
    # List of packages to uninstall
    packages = ["flask", "werkzeug", "cryptography", "pycryptodome", "scapy"]
    
    for pkg in packages:
        run_command(f"pip uninstall -y {pkg}", f"Uninstalling {pkg}")
    
    return True

def install_core_dependencies():
    """Install core dependencies with specific versions."""
    print("\n=== Installing Core Dependencies ===")
    
    # First, upgrade pip and setuptools
    run_command("python -m pip install --upgrade pip setuptools wheel", 
               "Upgrading pip, setuptools, and wheel")
    
    # Install Flask with specific Werkzeug version to ensure compatibility
    success1, _ = run_command("pip install werkzeug==2.0.1", 
                            "Installing werkzeug==2.0.1")
    success2, _ = run_command("pip install flask==2.0.1", 
                            "Installing flask==2.0.1")
    
    # Install remaining core dependencies
    packages = [
        "scapy==2.4.5",
        "requests>=2.26.0",
        "flask-wtf>=1.0.0",
        "flask-sqlalchemy>=2.5.1"
    ]
    
    for pkg in packages:
        run_command(f"pip install {pkg}", f"Installing {pkg}")
    
    # Try to install cryptography or pycryptodome
    crypto_success = False
    
    # First, try cryptography with specific version
    success, _ = run_command("pip install cryptography==36.0.0", 
                           "Installing cryptography==36.0.0")
    if success:
        crypto_success = True
    else:
        # Try latest version if specific version fails
        success, _ = run_command("pip install cryptography", 
                               "Installing latest cryptography")
        if success:
            crypto_success = True
    
    # Install pycryptodome as an alternative
    run_command("pip install pycryptodome>=3.10.1", 
               "Installing pycryptodome>=3.10.1")
    
    return success1 and success2

def verify_installations():
    """Verify that key packages are installed and accessible."""
    print("\n=== Verifying Package Installations ===")
    
    def check_package(package_name):
        try:
            __import__(package_name)
            print(f"✓ {package_name} is installed and accessible")
            return True
        except ImportError as e:
            print(f"✗ {package_name} import error: {e}")
            return False
    
    # Check key packages
    packages = ["flask", "werkzeug", "scapy", "requests"]
    results = []
    
    for pkg in packages:
        results.append(check_package(pkg))
    
    # Check crypto packages
    crypto_results = []
    crypto_results.append(check_package("cryptography"))
    crypto_results.append(check_package("Crypto"))  # For pycryptodome
    
    if not any(crypto_results):
        print("WARNING: Neither cryptography nor pycryptodome is accessible!")
    
    return all(results)

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
    """Main function to reinstall packages."""
    print("\n" + "=" * 60)
    print("ESP32 Security Simulation - Package Reinstallation")
    print("=" * 60)
    
    # Check environment
    if not check_environment():
        return 1
    
    # Uninstall existing packages
    uninstall_success = uninstall_packages()
    
    # Install core dependencies
    install_success = install_core_dependencies()
    
    # Verify installations
    verify_success = verify_installations()
    
    if not verify_success:
        print("\nWARNING: Some packages could not be verified.")
        print("The application might not run correctly.")
    
    # Ask to run the application
    print("\n" + "=" * 60)
    print("Package reinstallation completed.")
    if verify_success:
        print("All key packages were successfully installed and verified.")
    else:
        print("Some packages could not be verified. Check the logs for details.")
    print("=" * 60)
    
    response = input("\nWould you like to run the application now? (y/n): ").strip().lower()
    if response == 'y':
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
    else:
        print("\nTo run the application later, use: python main.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
