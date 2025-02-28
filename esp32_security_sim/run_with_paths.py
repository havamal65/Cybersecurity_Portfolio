#!/usr/bin/env python3
"""
ESP32 Security Simulation Runner with Path Configuration

This script explicitly sets up the Python path configuration before
running your application, ensuring packages are found correctly.
"""

import os
import sys
import subprocess
import site

def setup_paths():
    """Set up the Python path configuration."""
    print("Setting up Python path configuration...")
    
    # Get the virtual environment site-packages directory
    venv_path = sys.prefix
    venv_site_packages = os.path.join(venv_path, 'Lib', 'site-packages')
    
    # Print the current sys.path
    print("\nCurrent sys.path:")
    for p in sys.path:
        print(f"  {p}")
    
    # Add venv site-packages to the beginning of sys.path if not already there
    if venv_site_packages not in sys.path:
        print(f"\nAdding {venv_site_packages} to sys.path")
        sys.path.insert(0, venv_site_packages)
    else:
        print(f"\n{venv_site_packages} already in sys.path")
    
    # Verify Flask can be imported
    try:
        import flask
        print(f"\nFlask is available at: {flask.__file__}")
        print(f"Flask version: {flask.__version__}")
    except ImportError as e:
        print(f"\nFailed to import Flask: {e}")
        print("\nAttempting to diagnose the issue:")
        
        # Check if the Flask directory exists
        flask_dir = os.path.join(venv_site_packages, 'flask')
        if os.path.exists(flask_dir):
            print(f"Flask directory exists at {flask_dir}")
            # List contents to see if it's properly installed
            files = os.listdir(flask_dir)
            print(f"Flask directory contains {len(files)} files")
            print(f"Files include: {', '.join(files[:5])}...")
        else:
            print(f"Flask directory does not exist at {flask_dir}")
            
        # Check for Flask egg-info
        flask_info = None
        for item in os.listdir(venv_site_packages):
            if item.lower().startswith('flask-') and item.lower().endswith('.dist-info'):
                flask_info = item
                break
        
        if flask_info:
            print(f"Found Flask metadata at {os.path.join(venv_site_packages, flask_info)}")
        else:
            print("No Flask metadata found. Flask might not be properly installed.")
        
        return False
        
    return True

def run_application():
    """Run the main application with the configured paths."""
    # Run as a separate process to ensure proper path inheritance
    print("\nRunning main.py with configured paths...")
    result = subprocess.run(
        [sys.executable, "main.py"],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
        check=False
    )
    return result.returncode == 0

def main():
    """Main entry point."""
    print("=" * 60)
    print("ESP32 Security Simulation - Path Configuration Runner")
    print("=" * 60)
    
    # Setup the Python paths
    paths_configured = setup_paths()
    
    if not paths_configured:
        print("\nFailed to properly configure Python paths.")
        print("Let's try reinstalling Flask directly to the right location...")
        
        # Force reinstall Flask directly to the virtual environment
        subprocess.run([
            sys.executable, "-m", "pip", "install", "--force-reinstall", 
            "--no-cache-dir", "flask==2.0.1", "werkzeug==2.0.1"
        ], check=False)
        
        # Try setting up paths again
        paths_configured = setup_paths()
        
        if not paths_configured:
            print("\nPath configuration failed even after reinstallation.")
            print("Please check your virtual environment setup.")
            return 1
    
    # Run the application
    print("\nPaths configured successfully. Running application...")
    success = run_application()
    
    if success:
        print("\nApplication ran successfully!")
    else:
        print("\nApplication encountered errors.")
        print("Check the output above for details.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
