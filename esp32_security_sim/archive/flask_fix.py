#!/usr/bin/env python3
"""
Flask Dependency Fix Script

This script installs compatible versions of Flask and Werkzeug
to resolve the 'url_quote' import error.
"""

import subprocess
import sys
import os

def run_command(command):
    """Run a pip command and print output."""
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, check=True, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return False, e.stderr

def check_environment():
    """Check if running in a virtual environment."""
    in_venv = sys.prefix != sys.base_prefix
    if not in_venv:
        print("WARNING: Not running in a virtual environment.")
        response = input("Continue anyway? (y/n): ").strip().lower()
        return response == 'y'
    return True

def main():
    """Fix Flask and Werkzeug compatibility."""
    print("\n===== Flask Dependency Fix =====\n")
    
    if not check_environment():
        print("Aborted. Please activate your virtual environment first.")
        return
    
    # First uninstall current versions
    print("\nUninstalling current Flask and Werkzeug versions...")
    run_command("pip uninstall -y flask werkzeug")
    
    # Install compatible versions
    # Flask 2.0.1 works with Werkzeug 2.0.1
    print("\nInstalling compatible versions...")
    success1, _ = run_command("pip install werkzeug==2.0.1")
    success2, _ = run_command("pip install flask==2.0.1")
    
    if success1 and success2:
        print("\nSuccess! Flask and Werkzeug have been installed with compatible versions.")
        print("You should now be able to run your application with: python main.py")
    else:
        print("\nThere was a problem fixing the dependencies.")
        print("You might need to manually install these packages:")
        print("  pip install werkzeug==2.0.1")
        print("  pip install flask==2.0.1")
    
    print("\n=========================\n")

if __name__ == "__main__":
    main()
