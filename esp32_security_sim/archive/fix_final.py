#!/usr/bin/env python3
"""
ESP32 Security Simulation - Final Fix Script

This script applies the final fixes needed to get the application running,
including updating the encryption module and installing any missing dependencies.
"""

import subprocess
import sys
import os
import platform
import shutil
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
    """Check if running in a virtual environment."""
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    if not in_venv:
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
    return True

def update_encryption_module():
    """Replace the encryption.py file with the fixed version."""
    print("\n=== Updating Encryption Module ===")
    
    encryption_path = os.path.join("security", "encryption.py")
    fixed_path = os.path.join("security", "encryption_fixed.py")
    
    if not os.path.exists(fixed_path):
        print(f"Fixed encryption file not found at {fixed_path}")
        return False
        
    if os.path.exists(encryption_path):
        # Create backup
        backup_path = f"{encryption_path}.bak.{int(time.time())}"
        try:
            shutil.copy2(encryption_path, backup_path)
            print(f"Backed up original encryption module to {backup_path}")
        except Exception as e:
            print(f"Warning: Failed to backup encryption module: {e}")
    
    # Copy fixed version
    try:
        shutil.copy2(fixed_path, encryption_path)
        print(f"Updated {encryption_path} with fixed version")
        return True
    except Exception as e:
        print(f"Error updating encryption module: {e}")
        return False

def install_cryptography():
    """Install crypto packages needed."""
    print("\n=== Installing Cryptography Packages ===")
    
    # First update pip
    run_command("python -m pip install --upgrade pip", "Updating pip")
    
    # Check Python version and install appropriate packages
    py_version = sys.version_info
    print(f"Python version: {py_version.major}.{py_version.minor}.{py_version.micro}")
    
    # Try to install cryptography
    if py_version.minor >= 11:
        success, _ = run_command("pip install cryptography", 
                                "Installing latest cryptography")
    else:
        success, _ = run_command("pip install cryptography==36.0.0", 
                                "Installing cryptography==36.0.0")
    
    # Always install pycryptodome as a backup
    run_command("pip install pycryptodome>=3.10.1", 
               "Installing pycryptodome")
    
    return success

def handle_backend_issue():
    """Create a custom backend.py file if needed."""
    print("\n=== Handling Backend Dependencies ===")
    
    backend_path = os.path.join("security", "backend.py")
    backend_content = '''"""
Custom backend module for cryptography functionality.
This provides a fallback when the standard cryptography backend is not available.
"""

import logging

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.backends import default_backend
    logger.info("Using cryptography default backend")
except ImportError:
    logger.warning("Cryptography backend not available, using dummy implementation")
    
    def default_backend():
        """Dummy backend implementation."""
        return None
'''
    
    try:
        with open(backend_path, 'w') as f:
            f.write(backend_content)
        print(f"Created custom backend module at {backend_path}")
        return True
    except Exception as e:
        print(f"Error creating backend module: {e}")
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
    """Main function to apply final fixes."""
    print("\n" + "=" * 60)
    print("ESP32 Security Simulation - Final Fix")
    print("=" * 60)
    
    # Check if running in a virtual environment
    if not check_environment():
        return 1
    
    # Install cryptography packages
    install_cryptography()
    
    # Update encryption module
    update_success = update_encryption_module()
    if not update_success:
        print("Warning: Could not update encryption module")
        print("The application may not run correctly")
        
    # Handle backend issues
    handle_backend_issue()
    
    # Prompt to run the application
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
