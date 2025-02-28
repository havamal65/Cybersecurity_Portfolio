import logging
import random
import time

logger = logging.getLogger(__name__)

class MacRandomizer:
    """
    Simulates MAC address randomization feature of the ESP32 security device.
    Changes the device's MAC address periodically to enhance privacy.
    """
    
    def __init__(self, engine, config=None):
        """
        Initialize the MAC randomizer.
        
        Args:
            engine: The simulation engine
            config (dict, optional): Configuration parameters
        """
        self.engine = engine
        self.config = config or {}
        
        # Default configuration
        self.default_config = {
            'randomization_interval': 300,  # Seconds between MAC changes
            'oui_list': [                   # List of OUIs to use
                '00:11:22',                 # Generic OUI for simulation
                'DC:A6:32',                 # Raspberry Pi
                'C8:3A:35',                 # Esp32 common OUI
                '0C:B8:15',                 # Another ESP OUI
            ]
        }
        
        # Apply default config for missing values
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # Initialize state
        self.current_mac = self._generate_mac()
        self.last_change_time = time.time()
        
        # Register with engine
        self.engine.register_component('mac_randomizer', self)
        
        logger.info("MAC randomizer initialized with address: %s", self.current_mac)
    
    def initialize(self):
        """Initialize the MAC randomizer."""
        logger.info("MAC randomizer starting with address: %s", self.current_mac)
    
    def update(self, cycle):
        """
        Update the MAC randomizer for the current cycle.
        
        Args:
            cycle (int): Current simulation cycle
        """
        current_time = time.time()
        elapsed = current_time - self.last_change_time
        
        # Check if it's time to change the MAC
        if elapsed >= self.config['randomization_interval']:
            old_mac = self.current_mac
            self.current_mac = self._generate_mac()
            self.last_change_time = current_time
            
            logger.info(f"MAC address changed: {old_mac} -> {self.current_mac}")
    
    def _generate_mac(self):
        """
        Generate a random MAC address.
        
        Returns:
            str: Random MAC address
        """
        # Choose a random OUI (first 3 bytes)
        oui = random.choice(self.config['oui_list'])
        
        # Generate random values for the last 3 bytes
        mac_end = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(3)])
        
        return f"{oui}:{mac_end}"
    
    def get_current_mac(self):
        """
        Get the current MAC address.
        
        Returns:
            str: Current MAC address
        """
        return self.current_mac
    
    def randomize_now(self):
        """
        Immediately randomize the MAC address.
        
        Returns:
            str: New MAC address
        """
        old_mac = self.current_mac
        self.current_mac = self._generate_mac()
        self.last_change_time = time.time()
        
        logger.info(f"MAC address manually changed: {old_mac} -> {self.current_mac}")
        return self.current_mac
    
    def shutdown(self):
        """Shut down the MAC randomizer."""
        logger.info("MAC randomizer shutting down")
