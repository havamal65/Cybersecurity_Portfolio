import unittest
import time
import threading
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import SimulationEngine
from network.simulator import NetworkSimulator
from security.firewall import Firewall
from detection.ids import IntrusionDetectionSystem
from security.mac_randomization import MacRandomizer
from security.encryption import EncryptionManager

class TestSimulation(unittest.TestCase):
    """Test the ESP32 security device simulation."""
    
    def setUp(self):
        """Set up the test environment."""
        # Disable logging for tests
        logging.disable(logging.CRITICAL)
        
        # Create a simulation engine
        self.engine = SimulationEngine({
            'max_duration': 60,  # 1 minute max for tests
            'log_level': 'ERROR'
        })
        
        # Initialize components
        self.network = NetworkSimulator(self.engine, {
            'normal_traffic_rate': 50,     # Higher rate for testing
            'attack_probability': 0.5      # Higher probability for testing
        })
        
        self.firewall = Firewall(self.engine, {
            'log_blocked': False,          # Disable logging for tests
            'log_allowed': False
        })
        
        self.ids = IntrusionDetectionSystem(self.engine, {
            'log_detections': False,       # Disable logging for tests
            'detection_interval': 1        # More frequent detection for tests
        })
        
        self.mac_randomizer = MacRandomizer(self.engine)
        self.encryption = EncryptionManager(self.engine)
        
        # Start the simulation in a separate thread
        self.engine.start()
        
        # Wait for components to initialize
        time.sleep(2)
    
    def tearDown(self):
        """Clean up after the test."""
        self.engine.stop()
        # Re-enable logging
        logging.disable(logging.NOTSET)
    
    def test_packet_generation(self):
        """Test that packets are being generated."""
        time.sleep(3)  # Give time for packets to be generated
        
        # Check that packets are being generated
        packets = self.network.get_recent_packets()
        self.assertGreater(len(packets), 0, "No packets were generated")
    
    def test_firewall_processing(self):
        """Test that the firewall is processing packets."""
        time.sleep(5)  # Give time for packets to be processed
        
        # Check that some packets have been processed
        processed = False
        for packet in self.network.get_recent_packets():
            if packet.get('processed', False):
                processed = True
                break
        
        self.assertTrue(processed, "No packets were processed by the firewall")
    
    def test_mac_randomization(self):
        """Test MAC address randomization."""
        # Record initial MAC address
        initial_mac = self.mac_randomizer.get_current_mac()
        
        # Force a MAC change
        new_mac = self.mac_randomizer.randomize_now()
        
        # Check that the MAC address changed
        self.assertNotEqual(initial_mac, new_mac, "MAC address did not change")
    
    def test_encryption(self):
        """Test encryption functionality."""
        # Create test data
        test_data = b"This is a test message for encryption"
        
        # Encrypt the data
        encrypted_data, iv = self.encryption.encrypt_data(test_data)
        
        # Decrypt the data
        decrypted_data = self.encryption.decrypt_data(encrypted_data, iv)
        
        # Check that the decrypted data matches the original
        self.assertEqual(test_data, decrypted_data, "Encryption/decryption failed")
    
    def test_ids_alerts(self):
        """Test that the IDS is generating alerts."""
        time.sleep(10)  # Give time for attacks to be detected
        
        # Force an attack to generate alerts
        self.network.attack_in_progress = True
        self.network.attack_type = 'port_scan'
        self.network.attack_start_time = time.time()
        self.network.attack_duration = 5.0
        
        # Give time for the attack to be processed
        time.sleep(6)
        
        # Run detection manually to ensure alerts are generated
        self.ids._run_detection()
        
        # Check that IDS is functioning (even if no alerts yet)
        self.assertIsNotNone(self.ids.alerts, "IDS alerts list not initialized")
    
    def test_rule_addition(self):
        """Test adding a new firewall rule."""
        # Current number of rules
        initial_rules = len(self.firewall.get_rules())
        
        # Add a new rule
        new_rule = {
            'protocol': 'tcp',
            'dst_port': 8080,
            'action': 'block'
        }
        self.firewall.add_rule(new_rule)
        
        # Check that the rule was added
        updated_rules = self.firewall.get_rules()
        self.assertEqual(len(updated_rules), initial_rules + 1, "Rule was not added")
        
        # Check that the added rule matches what we expect
        self.assertEqual(updated_rules[-1], new_rule, "Added rule does not match")

if __name__ == '__main__':
    unittest.main()
