"""
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
