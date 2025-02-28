import logging
import time
import hashlib
import base64
import os

# Set up logger first
logger = logging.getLogger(__name__)

# Import from our adapter instead of directly from cryptography
from security.crypto_adapter import Cipher, algorithms, modes, CRYPTOGRAPHY_AVAILABLE, PYCRYPTODOME_AVAILABLE

# Log which crypto implementation we're using
if CRYPTOGRAPHY_AVAILABLE:
    logger.info("Using cryptography package for encryption")
elif PYCRYPTODOME_AVAILABLE:
    logger.info("Using pycryptodome package for encryption")
else:
    logger.warning("No cryptography implementation available. Encryption will not work properly.")

# Import the backend
try:
    from cryptography.hazmat.backends import default_backend
except ImportError:
    logger.warning("Could not import default_backend, using None instead")
    default_backend = lambda: None

class EncryptionManager:
    """
    Simulates encryption capabilities of the ESP32 security device.
    Handles key management and data encryption/decryption.
    """
    
    def __init__(self, engine, config=None):
        """
        Initialize the encryption manager.
        
        Args:
            engine: The simulation engine
            config (dict, optional): Configuration parameters
        """
        self.engine = engine
        self.config = config or {}
        
        # Default configuration
        self.default_config = {
            'key_rotation_interval': 3600,  # Key rotation interval in seconds
            'cipher_algorithm': 'AES',      # Cipher algorithm to use
            'key_size': 256,                # Key size in bits
            'use_hardware_acceleration': True,  # Simulate hardware acceleration
        }
        
        # Apply default config for missing values
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # Initialize encryption state
        self.encryption_key = self._generate_key()
        self.last_key_rotation = time.time()
        self.encrypted_packets = 0
        self.decrypted_packets = 0
        self.encryption_time_ms = 0  # Average encryption time in milliseconds
        
        # Register with engine
        self.engine.register_component('encryption', self)
        
        logger.info("Encryption manager initialized")
    
    def initialize(self):
        """Initialize the encryption manager."""
        logger.info("Encryption manager starting")
    
    def update(self, cycle):
        """
        Update the encryption manager for the current cycle.
        
        Args:
            cycle (int): Current simulation cycle
        """
        current_time = time.time()
        elapsed = current_time - self.last_key_rotation
        
        # Check if it's time to rotate the encryption key
        if elapsed >= self.config['key_rotation_interval']:
            old_key_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
            self.encryption_key = self._generate_key()
            new_key_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
            self.last_key_rotation = current_time
            
            logger.info(f"Encryption key rotated: {old_key_hash} -> {new_key_hash}")
    
    def _generate_key(self):
        """
        Generate a new encryption key.
        
        Returns:
            bytes: New encryption key
        """
        key_size_bytes = self.config['key_size'] // 8
        return os.urandom(key_size_bytes)
    
    def encrypt_data(self, data):
        """
        Encrypt data using the current encryption key.
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            tuple: (encrypted_data, iv)
        """
        # Generate a random initialization vector
        iv = os.urandom(16)
        
        # Create encryptor
        if self.config['cipher_algorithm'] == 'AES':
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            block_size = 16  # AES block size is 16 bytes
            padded_data = self._pad_data(data, block_size)
            
            # Encrypt data
            start_time = time.time()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            end_time = time.time()
            
            # Simulate hardware acceleration if enabled
            encryption_time = (end_time - start_time) * 1000  # Convert to milliseconds
            if self.config['use_hardware_acceleration']:
                # Hardware would be ~10x faster
                encryption_time /= 10
            
            # Update statistics
            self.encrypted_packets += 1
            self.encryption_time_ms = (self.encryption_time_ms * (self.encrypted_packets - 1) + encryption_time) / self.encrypted_packets
            
            return encrypted_data, iv
        else:
            raise ValueError(f"Unsupported cipher algorithm: {self.config['cipher_algorithm']}")
    
    def decrypt_data(self, encrypted_data, iv):
        """
        Decrypt data using the current encryption key.
        
        Args:
            encrypted_data (bytes): Encrypted data
            iv (bytes): Initialization vector
            
        Returns:
            bytes: Decrypted data
        """
        # Create decryptor
        if self.config['cipher_algorithm'] == 'AES':
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            start_time = time.time()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            end_time = time.time()
            
            # Simulate hardware acceleration if enabled
            decryption_time = (end_time - start_time) * 1000  # Convert to milliseconds
            if self.config['use_hardware_acceleration']:
                # Hardware would be ~10x faster
                decryption_time /= 10
            
            # Update statistics
            self.decrypted_packets += 1
            
            # Remove padding
            return self._unpad_data(padded_data)
        else:
            raise ValueError(f"Unsupported cipher algorithm: {self.config['cipher_algorithm']}")
    
    def _pad_data(self, data, block_size):
        """
        Pad data to block size using PKCS#7 padding.
        
        Args:
            data (bytes): Data to pad
            block_size (int): Block size
            
        Returns:
            bytes: Padded data
        """
        pad_len = block_size - (len(data) % block_size)
        padding = bytes([pad_len]) * pad_len
        return data + padding
    
    def _unpad_data(self, padded_data):
        """
        Remove PKCS#7 padding from data.
        
        Args:
            padded_data (bytes): Padded data
            
        Returns:
            bytes: Unpadded data
        """
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]
    
    def get_stats(self):
        """
        Get encryption statistics.
        
        Returns:
            dict: Encryption statistics
        """
        return {
            'encrypted_packets': self.encrypted_packets,
            'decrypted_packets': self.decrypted_packets,
            'average_encryption_time_ms': self.encryption_time_ms,
            'last_key_rotation': self.last_key_rotation,
            'key_hash': hashlib.sha256(self.encryption_key).hexdigest()[:8],
            'hardware_acceleration': self.config['use_hardware_acceleration'],
        }
    
    def rotate_key(self):
        """
        Manually rotate the encryption key.
        """
        old_key_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
        self.encryption_key = self._generate_key()
        new_key_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
        self.last_key_rotation = time.time()
        
        logger.info(f"Encryption key manually rotated: {old_key_hash} -> {new_key_hash}")
    
    def shutdown(self):
        """Shut down the encryption manager."""
        logger.info("Encryption manager shutting down")
