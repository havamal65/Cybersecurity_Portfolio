#!/usr/bin/env python3
"""
ESP32 Security Simulation - Dependency Fix Script

This script intelligently installs compatible dependencies for your Python version,
addressing the numpy compatibility issues and ensuring a working environment.
"""

import subprocess
import sys
import os
import platform
import re

def get_python_version():
    """Get the current Python version as a tuple of (major, minor, micro)."""
    return sys.version_info[:3]

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
        return response == 'y'
    print("✓ Running in a virtual environment")
    return True

def get_compatible_numpy_version(py_version):
    """Determine a compatible numpy version based on Python version."""
    major, minor, _ = py_version
    
    if major != 3:
        return "numpy==1.16.6"  # Last version for Python 2.7
    
    if minor < 7:
        return "numpy==1.16.6"  # Last version for Python 3.6
    elif minor < 9:
        return "numpy==1.21.6"  # Good version for Python 3.7-3.8
    elif minor < 11:
        return "numpy==1.24.3"  # Good version for Python 3.9-3.10
    else:
        return "numpy>=1.26.0"  # For Python 3.11+

def get_compatible_packages(py_version):
    """Get a dictionary of packages with versions compatible with the Python version."""
    major, minor, _ = py_version
    
    packages = {
        "flask": "flask==2.0.1",
        "werkzeug": "werkzeug==2.0.1",  # Flask 2.0.1 compatible version
        "numpy": get_compatible_numpy_version(py_version),
        "scapy": "scapy==2.4.5",
        "cryptography": "cryptography==36.0.0",
        "requests": "requests==2.26.0",
        "flask-wtf": "flask-wtf==1.0.0",
        "flask-sqlalchemy": "flask-sqlalchemy==2.5.1",
        "pytest": "pytest==6.2.5",
        "coverage": "coverage==6.1.2"
    }
    
    # Special case for pycrypto (deprecated)
    packages["pycryptodome"] = "pycryptodome>=3.10.1"  # Modern replacement for pycrypto
    
    # netifaces can be problematic on some platforms, handle separately
    if platform.system() == "Windows":
        packages["netifaces"] = "netifaces==0.11.0"
    else:
        packages["netifaces"] = "netifaces>=0.10.9"
    
    return packages

def install_dependencies(py_version):
    """Install dependencies compatible with the Python version."""
    packages = get_compatible_packages(py_version)
    
    print("\n=== Installing compatible packages ===")
    
    # Install Werkzeug first (Flask dependency)
    if "werkzeug" in packages:
        success, _ = run_command(f"pip install {packages['werkzeug']}", 
                                 f"Installing {packages['werkzeug']}")
        if not success:
            print("Warning: Failed to install werkzeug, Flask may not work correctly")
    
    # Install core packages first
    core_packages = ["flask", "numpy", "scapy", "cryptography", "requests"]
    for pkg in core_packages:
        if pkg in packages:
            success, _ = run_command(f"pip install {packages[pkg]}", 
                                     f"Installing {packages[pkg]}")
            if not success:
                print(f"Warning: Failed to install {pkg}")
    
    # Install flask extensions
    flask_extensions = ["flask-wtf", "flask-sqlalchemy"]
    for pkg in flask_extensions:
        if pkg in packages:
            run_command(f"pip install {packages[pkg]}", 
                        f"Installing {packages[pkg]}")
    
    # Install testing packages
    testing_packages = ["pytest", "coverage"]
    for pkg in testing_packages:
        if pkg in packages:
            run_command(f"pip install {packages[pkg]}", 
                        f"Installing {packages[pkg]}")
    
    # Install pycryptodome instead of pycrypto
    if "pycryptodome" in packages:
        success, _ = run_command(f"pip install {packages['pycryptodome']}", 
                                 f"Installing {packages['pycryptodome']} (replacement for pycrypto)")
        if success:
            print("Note: Installed pycryptodome as a modern replacement for pycrypto")
    
    # Install netifaces last (can be problematic)
    if "netifaces" in packages:
        success, _ = run_command(f"pip install {packages['netifaces']}", 
                                 f"Installing {packages['netifaces']}")
        if not success:
            print("Warning: Failed to install netifaces")
            print("This is a common issue and might require manual installation or system libraries")
    
    print("\n=== Dependency installation complete ===")

def create_scapy_adapter():
    """Create the scapy adapter module if it doesn't exist."""
    adapter_path = os.path.join("network", "scapy_adapter.py")
    if not os.path.exists(adapter_path):
        adapter_dir = os.path.dirname(adapter_path)
        if not os.path.exists(adapter_dir):
            os.makedirs(adapter_dir)
            
        print("\nCreating scapy adapter module...")
        adapter_content = """\"\"\"
Scapy Adapter Module

This module provides a compatibility layer for Scapy. If Scapy is not available,
it will try to provide mock implementations of the required classes.
\"\"\"

import logging

logger = logging.getLogger(__name__)

# Try to import Scapy
try:
    from scapy.all import Ether, ARP, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
    logger.info("Scapy module loaded successfully")
except ImportError:
    logger.warning("Scapy module not available. Using mock implementation.")
    SCAPY_AVAILABLE = False
    
    # Mock Scapy classes for basic functionality
    class PacketMock:
        \"\"\"Base mock class for Scapy packets.\"\"\"
        
        def __init__(self, **kwargs):
            self.fields = kwargs
            self.payload = None
            
        def __truediv__(self, other):
            \"\"\"Implement the / operator to stack protocol layers.\"\"\"
            self.payload = other
            return self
            
        def __str__(self):
            \"\"\"Return a string representation.\"\"\"
            result = f"{self.__class__.__name__}("
            result += ", ".join(f"{k}={v}" for k, v in self.fields.items())
            result += ")"
            if self.payload:
                result += f" / {str(self.payload)}"
            return result
    
    class Ether(PacketMock):
        \"\"\"Mock Ethernet packet.\"\"\"
        pass
    
    class ARP(PacketMock):
        \"\"\"Mock ARP packet.\"\"\"
        pass
    
    class IP(PacketMock):
        \"\"\"Mock IP packet.\"\"\"
        pass
    
    class TCP(PacketMock):
        \"\"\"Mock TCP packet.\"\"\"
        pass
    
    class UDP(PacketMock):
        \"\"\"Mock UDP packet.\"\"\"
        pass
    
    class ICMP(PacketMock):
        \"\"\"Mock ICMP packet.\"\"\"
        pass
    
    class Raw(PacketMock):
        \"\"\"Mock Raw payload.\"\"\"
        pass

def is_scapy_available():
    \"\"\"Check if the real Scapy module is available.\"\"\"
    return SCAPY_AVAILABLE

# Export the classes and functions
__all__ = ['Ether', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'Raw', 'is_scapy_available']
"""
        with open(adapter_path, 'w') as f:
            f.write(adapter_content)
        print(f"Created {adapter_path}")

def update_simulator_import():
    """Update the simulator.py file to use the scapy adapter."""
    simulator_path = os.path.join("network", "simulator.py")
    if os.path.exists(simulator_path):
        with open(simulator_path, 'r') as f:
            content = f.read()
        
        # Check if already using the adapter
        if "from network.scapy_adapter import" in content:
            print("\nSimulator already using scapy adapter")
            return
        
        # Otherwise update the import
        updated_content = re.sub(
            r"from scapy\.all import Ether, ARP, IP, TCP, UDP, ICMP, Raw",
            "# Use our adapter instead of directly importing from scapy\n"
            "from network.scapy_adapter import Ether, ARP, IP, TCP, UDP, ICMP, Raw, is_scapy_available\n\n"
            "# Log whether we're using real Scapy or the mock implementation\n"
            "if is_scapy_available():\n"
            "    logger.info(\"Using real Scapy implementation\")\n"
            "else:\n"
            "    logger.warning(\"Using mock Scapy implementation - limited functionality\")",
            content
        )
        
        if updated_content != content:
            # Backup original file
            backup_path = f"{simulator_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(content)
            print(f"\nBacked up original simulator to {backup_path}")
            
            # Write updated content
            with open(simulator_path, 'w') as f:
                f.write(updated_content)
            print(f"Updated {simulator_path} to use scapy adapter")
        else:
            print("\nCould not update simulator imports - pattern not found")

def main():
    """Main function to fix the dependencies."""
    print("\n=== ESP32 Security Simulation - Dependency Fix ===\n")
    
    # Get Python version
    py_version = get_python_version()
    print(f"Python version: {py_version[0]}.{py_version[1]}.{py_version[2]}")
    
    # Check environment
    if not check_environment():
        print("Aborting. Please activate your virtual environment first.")
        return
    
    # Upgrade pip
    run_command("python -m pip install --upgrade pip", "Upgrading pip")
    
    # Install compatible dependencies
    install_dependencies(py_version)
    
    # Create scapy adapter
    create_scapy_adapter()
    
    # Update simulator import
    update_simulator_import()
    
    print("\n=== Setup Complete! ===")
    print("You should now be able to run: python main.py")
    print("\nIf you encounter any other issues, please check the error message")
    print("and refer to the project documentation.")

if __name__ == "__main__":
    main()
