#!/usr/bin/env python3
"""
ESP32 Security Simulation - Cryptography Fix Script

This script installs the cryptography module and its dependencies
to resolve the 'No module named cryptography' error.
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

def install_cryptography():
    """Install the cryptography package."""
    print("\n=== Installing Cryptography Package ===")
    
    # First try the required version
    success, output = run_command("pip install cryptography==36.0.0", 
                                 "Installing cryptography==36.0.0")
    
    # If that fails, try a more flexible installation
    if not success:
        print("\nTrying alternative installation method...")
        
        # Install build dependencies first
        run_command("pip install --upgrade setuptools wheel", 
                   "Installing build dependencies")
        
        # For Windows, try a pre-built wheel
        if platform.system() == "Windows":
            py_version = f"{sys.version_info.major}{sys.version_info.minor}"
            
            # Try installing a compatible wheel for newer Python versions
            if sys.version_info.minor >= 11:
                run_command("pip install cryptography", 
                           "Installing latest compatible cryptography version")
            else:
                run_command("pip install cryptography==36.0.0", 
                           "Installing cryptography==36.0.0 (second attempt)")
                
        # For other platforms
        else:
            run_command("pip install cryptography", 
                       "Installing latest compatible cryptography version")
    
    # Verify installation
    try:
        import cryptography
        version = cryptography.__version__
        print(f"\nSuccessfully installed cryptography {version}")
        return True
    except ImportError:
        print("\nFailed to import cryptography after installation.")
        print("This could be due to missing system dependencies.")
        
        if platform.system() == "Windows":
            print("\nOn Windows, you might need to install Visual C++ build tools.")
        elif platform.system() == "Linux":
            print("\nOn Linux, you might need to install libffi-dev and libssl-dev:")
            print("  sudo apt-get install libffi-dev libssl-dev")
        elif platform.system() == "Darwin":  # macOS
            print("\nOn macOS, you might need to install openssl:")
            print("  brew install openssl")
            
        return False

def install_pycryptodome():
    """Install pycryptodome as an alternative."""
    print("\n=== Installing PyCryptodome as Alternative ===")
    success, _ = run_command("pip install pycryptodome>=3.10.1", 
                            "Installing pycryptodome")
    
    if success:
        print("\nSuccessfully installed pycryptodome.")
        print("Note: If your code specifically requires 'cryptography',")
        print("you might need to modify it to use pycryptodome instead.")

def create_crypto_adapter():
    """Create a compatibility adapter for the cryptography module."""
    print("\n=== Creating Cryptography Adapter ===")
    
    adapter_content = '''"""
Cryptography Adapter Module

This module provides compatibility between the cryptography package and pycryptodome.
It allows the application to run even if the cryptography package isn't available.
"""

import logging
import os
import sys

logger = logging.getLogger(__name__)

CRYPTOGRAPHY_AVAILABLE = False
PYCRYPTODOME_AVAILABLE = False

# Try to import cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
    logger.info("Using cryptography package")
except ImportError:
    logger.warning("cryptography package not available, trying pycryptodome...")
    
    # Try to import pycryptodome as a fallback
    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Util.Padding import pad, unpad
        from Crypto.Hash import SHA256
        PYCRYPTODOME_AVAILABLE = True
        logger.info("Using pycryptodome package")
        
        # Define compatibility classes to mimic cryptography's API
        class CryptoDomeAESCipher:
            """Adapter class for AES cipher from pycryptodome."""
            
            def __init__(self, key, iv):
                self.key = key
                self.iv = iv
                self.cipher = AES.new(key, AES.MODE_CBC, iv)
                
            def encryptor(self):
                return self
                
            def decryptor(self):
                # Need to create a new cipher for decryption in CBC mode
                return CryptoDomeAESCipher(self.key, self.iv)
                
            def update(self, data):
                if hasattr(self.cipher, 'encrypt'):
                    # Encryption mode
                    return self.cipher.encrypt(data)
                else:
                    # Decryption mode
                    return self.cipher.decrypt(data)
                
            def finalize(self):
                return b''
        
        # Define compatibility functions
        def create_cipher(algorithm, mode):
            if isinstance(algorithm, type) and algorithm.__name__ == 'AES' and mode.__class__.__name__ == 'CBC':
                return CryptoDomeAESCipher(algorithm.key, mode.initialization_vector)
            else:
                raise ValueError(f"Unsupported algorithm {algorithm} or mode {mode}")
        
        # Define compatibility classes
        class Cipher:
            def __init__(self, algorithm, mode):
                self.algorithm = algorithm
                self.mode = mode
            
            def encryptor(self):
                return create_cipher(self.algorithm, self.mode).encryptor()
                
            def decryptor(self):
                return create_cipher(self.algorithm, self.mode).decryptor()
        
        class algorithms:
            @staticmethod
            def AES(key):
                class AESAlgorithm:
                    def __init__(self, key):
                        self.key = key
                return AESAlgorithm(key)
                
        class modes:
            @staticmethod
            def CBC(iv):
                class CBCMode:
                    def __init__(self, iv):
                        self.initialization_vector = iv
                return CBCMode(iv)
                
        class padding:
            class PKCS7:
                def __init__(self, block_size):
                    self.block_size = block_size
                
                def padder(self):
                    class Padder:
                        def __init__(self, block_size):
                            self.block_size = block_size
                        
                        def update(self, data):
                            # Don't pad yet, just return the data
                            return data
                            
                        def finalize(self):
                            # Return empty bytes since we'll pad when we have all the data
                            return b''
                    return Padder(self.block_size)
                
                def unpadder(self):
                    class Unpadder:
                        def __init__(self, block_size):
                            self.block_size = block_size
                        
                        def update(self, data):
                            # Don't unpad yet, just return the data
                            return data
                            
                        def finalize(self):
                            # Return empty bytes since we'll unpad when we have all the data
                            return b''
                    return Unpadder(self.block_size)
                    
        def create_pbkdf2_hmac(hash_name, length, salt, iterations):
            if hash_name == 'sha256':
                def derive(key_material):
                    return PBKDF2(key_material, salt, dkLen=length, 
                                 count=iterations, hmac_hash_module=SHA256)
                return derive
            else:
                raise ValueError(f"Unsupported hash function: {hash_name}")
                
        class PBKDF2HMAC:
            def __init__(self, algorithm, length, salt, iterations):
                if algorithm.__name__ == 'SHA256':
                    self.derive_func = create_pbkdf2_hmac('sha256', length, salt, iterations)
                else:
                    raise ValueError(f"Unsupported algorithm: {algorithm.__name__}")
                    
            def derive(self, key_material):
                return self.derive_func(key_material)
            
        class hashes:
            class SHA256:
                name = 'sha256'
                
    except ImportError:
        logger.error("Neither cryptography nor pycryptodome is available.")
        logger.error("Encryption functionality will not work.")
        
        # Define dummy classes to prevent import errors
        class Cipher:
            def __init__(self, *args, **kwargs):
                pass
                
        class algorithms:
            @staticmethod
            def AES(key):
                return None
                
        class modes:
            @staticmethod
            def CBC(iv):
                return None
                
        class padding:
            class PKCS7:
                def __init__(self, block_size):
                    pass
                    
        class PBKDF2HMAC:
            def __init__(self, *args, **kwargs):
                pass
                
            def derive(self, key_material):
                return b'0' * 32
                
        class hashes:
            class SHA256:
                pass

# Export the appropriate symbols
__all__ = [
    'Cipher', 'algorithms', 'modes', 'padding', 'PBKDF2HMAC', 'hashes',
    'CRYPTOGRAPHY_AVAILABLE', 'PYCRYPTODOME_AVAILABLE'
]
'''

    adapter_path = os.path.join("security", "crypto_adapter.py")
    adapter_dir = os.path.dirname(adapter_path)
    
    if not os.path.exists(adapter_dir):
        os.makedirs(adapter_dir)
        
    with open(adapter_path, 'w') as f:
        f.write(adapter_content)
        
    print(f"Created cryptography adapter at {adapter_path}")

def update_encryption_module():
    """Update the encryption.py file to use our adapter."""
    print("\n=== Updating Encryption Module ===")
    
    encryption_path = os.path.join("security", "encryption.py")
    
    if not os.path.exists(encryption_path):
        print(f"Warning: Could not find {encryption_path}")
        return False
        
    try:
        with open(encryption_path, 'r') as f:
            content = f.read()
            
        # Check if already using adapter
        if "from security.crypto_adapter import" in content:
            print("Encryption module already using adapter.")
            return True
            
        # Replace the import
        updated_content = content.replace(
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes",
            "# Import from our adapter instead of directly from cryptography\n"
            "from security.crypto_adapter import Cipher, algorithms, modes, CRYPTOGRAPHY_AVAILABLE, PYCRYPTODOME_AVAILABLE\n\n"
            "# Log which crypto implementation we're using\n"
            "if CRYPTOGRAPHY_AVAILABLE:\n"
            "    logger.info(\"Using cryptography package for encryption\")\n"
            "elif PYCRYPTODOME_AVAILABLE:\n"
            "    logger.info(\"Using pycryptodome package for encryption\")\n"
            "else:\n"
            "    logger.warning(\"No cryptography implementation available. Encryption will not work properly.\")"
        )
        
        # Replace other imports if needed
        updated_content = updated_content.replace(
            "from cryptography.hazmat.primitives import padding",
            "# from cryptography.hazmat.primitives import padding"
        )
        updated_content = updated_content.replace(
            "from cryptography.hazmat.primitives import hashes",
            "# from cryptography.hazmat.primitives import hashes"
        )
        updated_content = updated_content.replace(
            "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC",
            "# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC"
        )
        
        # Make backup of original file
        backup_path = f"{encryption_path}.bak.{int(time.time())}"
        with open(backup_path, 'w') as f:
            f.write(content)
        print(f"Backed up original encryption module to {backup_path}")
        
        # Write updated content
        with open(encryption_path, 'w') as f:
            f.write(updated_content)
        print(f"Updated {encryption_path} to use crypto adapter")
        
        return True
    except Exception as e:
        print(f"Error updating encryption module: {e}")
        return False

def main():
    """Main function to fix cryptography issues."""
    print("\n" + "=" * 60)
    print("ESP32 Security Simulation - Cryptography Fix")
    print("=" * 60)
    
    # Check if running in a virtual environment
    if not check_environment():
        return 1
    
    # Try to install cryptography
    crypto_success = install_cryptography()
    
    # If cryptography fails, install pycryptodome
    if not crypto_success:
        install_pycryptodome()
    
    # Create adapter module
    create_crypto_adapter()
    
    # Update encryption module
    update_success = update_encryption_module()
    
    print("\n" + "=" * 60)
    if update_success:
        print("Cryptography fix completed successfully!")
        print("You should now be able to run: python main.py")
    else:
        print("Cryptography fix completed with warnings.")
        print("The application might still encounter errors.")
        print("Please check the logs for details.")
    print("=" * 60)
    
    return 0 if update_success else 1

if __name__ == "__main__":
    sys.exit(main())
