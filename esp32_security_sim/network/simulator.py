import logging
import random
import time
from datetime import datetime

# Use our adapter instead of directly importing from scapy
from network.scapy_adapter import Ether, ARP, IP, TCP, UDP, ICMP, Raw, is_scapy_available

logger = logging.getLogger(__name__)

# Log whether we're using real Scapy or the mock implementation
if is_scapy_available():
    logger.info("Using real Scapy implementation")
else:
    logger.warning("Using mock Scapy implementation - limited functionality")

class NetworkSimulator:
    """
    Simulates network traffic for the ESP32 security device.
    Generates realistic packets that would be processed by the device.
    """
    
    def __init__(self, engine, config=None):
        """
        Initialize the network simulator.
        
        Args:
            engine: The simulation engine
            config (dict, optional): Configuration parameters
        """
        self.engine = engine
        self.config = config or {}
        
        # Default configuration
        self.default_config = {
            'normal_traffic_rate': 10,   # Packets per second for normal traffic
            'attack_probability': 0.05,  # Probability of generating an attack
            'local_network': '192.168.1.0/24',  # Local network
            'internet_hosts': [          # Simulated internet hosts
                '8.8.8.8',               # Google DNS
                '1.1.1.1',               # Cloudflare DNS
                '93.184.216.34',         # example.com
                '172.217.169.78',        # google.com
                '104.244.42.65',         # twitter.com
            ]
        }
        
        # Apply default config for missing values
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # Initialize state
        self.packets = []
        self.last_packet_time = time.time()
        self.attack_in_progress = False
        self.attack_type = None
        self.attack_start_time = None
        self.attack_duration = 0
        
        # Register with engine
        self.engine.register_component('network', self)
        
        logger.info("Network simulator initialized")
    
    def initialize(self):
        """Initialize the network simulator."""
        logger.info("Network simulator starting")
    
    def update(self, cycle):
        """
        Update the network simulator for the current cycle.
        
        Args:
            cycle (int): Current simulation cycle
        """
        current_time = time.time()
        elapsed = current_time - self.last_packet_time
        
        # Determine how many packets to generate based on elapsed time
        num_packets = int(elapsed * self.config['normal_traffic_rate'])
        
        # Generate normal traffic
        for _ in range(num_packets):
            packet = self._generate_normal_packet()
            self._process_packet(packet)
        
        # Possibly start or continue an attack
        if not self.attack_in_progress:
            if random.random() < self.config['attack_probability']:
                self._start_attack()
        else:
            # Continue existing attack
            attack_elapsed = current_time - self.attack_start_time
            if attack_elapsed < self.attack_duration:
                attack_packets = self._generate_attack_packets()
                for packet in attack_packets:
                    self._process_packet(packet)
            else:
                # End the attack
                logger.info(f"Attack of type {self.attack_type} ended after {attack_elapsed:.2f} seconds")
                self.attack_in_progress = False
        
        self.last_packet_time = current_time
    
    def _generate_normal_packet(self):
        """Generate a normal network packet."""
        # Choose random source and destination
        if random.random() < 0.7:  # 70% local network traffic
            src_ip = f"192.168.1.{random.randint(2, 254)}"
            if random.random() < 0.3:  # 30% of local traffic goes to internet
                dst_ip = random.choice(self.config['internet_hosts'])
            else:
                dst_ip = f"192.168.1.{random.randint(2, 254)}"
        else:  # 30% incoming traffic from internet
            src_ip = random.choice(self.config['internet_hosts'])
            dst_ip = f"192.168.1.{random.randint(2, 254)}"
        
        # Create packet based on protocol
        protocol = random.choices(
            ['tcp', 'udp', 'icmp'], 
            weights=[0.8, 0.15, 0.05], 
            k=1
        )[0]
        
        # Base IP packet
        packet = IP(src=src_ip, dst=dst_ip)
        
        if protocol == 'tcp':
            common_ports = [80, 443, 22, 25, 143, 3389, 8080]
            if random.random() < 0.8:  # 80% common ports
                dport = random.choice(common_ports)
            else:
                dport = random.randint(1024, 65535)
            
            packet = packet/TCP(
                sport=random.randint(1024, 65535),
                dport=dport,
                flags=random.choice(['S', 'SA', 'A', 'PA', 'FA'])
            )
            
            # Add some data for established connections
            if random.random() < 0.3:
                data_len = random.randint(10, 1000)
                packet = packet/Raw(load=b'X' * data_len)
                
        elif protocol == 'udp':
            common_ports = [53, 67, 68, 123, 161, 162]
            if random.random() < 0.7:  # 70% common ports
                dport = random.choice(common_ports)
            else:
                dport = random.randint(1024, 65535)
            
            packet = packet/UDP(
                sport=random.randint(1024, 65535),
                dport=dport
            )
            
            # Add some data
            if random.random() < 0.5:
                data_len = random.randint(10, 200)
                packet = packet/Raw(load=b'X' * data_len)
                
        elif protocol == 'icmp':
            packet = packet/ICMP(
                type=random.choice([0, 8]),  # Echo reply or request
                code=0
            )
        
        return packet
    
    def _start_attack(self):
        """Start a simulated network attack."""
        attack_types = [
            'port_scan',
            'dos_attack',
            'arp_spoofing',
            'brute_force',
            'data_exfiltration'
        ]
        
        self.attack_type = random.choice(attack_types)
        self.attack_in_progress = True
        self.attack_start_time = time.time()
        self.attack_duration = random.uniform(5.0, 20.0)  # Attack duration in seconds
        
        logger.info(f"Starting attack simulation: {self.attack_type}, duration: {self.attack_duration:.2f}s")
    
    def _generate_attack_packets(self):
        """Generate packets for the current attack type."""
        packets = []
        
        if self.attack_type == 'port_scan':
            # Target is a random local device
            target_ip = f"192.168.1.{random.randint(2, 254)}"
            # Attacker is usually external
            attacker_ip = random.choice(self.config['internet_hosts'])
            
            # Generate TCP SYN packets to different ports
            for _ in range(10):
                port = random.randint(1, 10000)
                packet = IP(src=attacker_ip, dst=target_ip)/TCP(dport=port, flags='S')
                packets.append(packet)
                
        elif self.attack_type == 'dos_attack':
            # Target is a random local device
            target_ip = f"192.168.1.{random.randint(2, 254)}"
            # Multiple attackers (spoofed IPs)
            
            # Generate high volume of SYN packets to a single port
            target_port = random.choice([80, 443, 8080, 22])
            for _ in range(50):
                # Use random source IPs to simulate spoofing
                src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}."
                src_ip += f"{random.randint(1, 254)}.{random.randint(1, 254)}"
                packet = IP(src=src_ip, dst=target_ip)/TCP(dport=target_port, flags='S')
                packets.append(packet)
                
        elif self.attack_type == 'arp_spoofing':
            # Simulate ARP spoofing - attacker pretends to be the gateway
            gateway_ip = '192.168.1.1'
            target_ip = f"192.168.1.{random.randint(2, 254)}"
            attacker_mac = "00:11:22:33:44:55"  # Fake MAC
            
            # Send spoofed ARP replies
            for _ in range(5):
                packet = Ether()/ARP(
                    op=2,  # ARP Reply
                    psrc=gateway_ip,  # Pretend to be the gateway
                    hwsrc=attacker_mac,  # Attacker's MAC
                    pdst=target_ip  # Target's IP
                )
                packets.append(packet)
                
        elif self.attack_type == 'brute_force':
            # Target is a random local device
            target_ip = f"192.168.1.{random.randint(2, 254)}"
            # Attacker is usually external
            attacker_ip = random.choice(self.config['internet_hosts'])
            
            # Generate login attempts (e.g., to SSH)
            target_port = 22  # SSH
            for _ in range(20):
                packet = IP(src=attacker_ip, dst=target_ip)/TCP(
                    sport=random.randint(1024, 65535),
                    dport=target_port,
                    flags='PA'
                )
                packets.append(packet)
                
        elif self.attack_type == 'data_exfiltration':
            # Attacker is internal, target is external
            src_ip = f"192.168.1.{random.randint(2, 254)}"
            dst_ip = random.choice(self.config['internet_hosts'])
            
            # Generate suspicious outbound connections with data
            for _ in range(3):
                packet = IP(src=src_ip, dst=dst_ip)/TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice([80, 443, 8080, 25]),
                    flags='PA'
                )/Raw(load=b'X' * random.randint(1000, 5000))
                packets.append(packet)
        
        return packets
    
    def _process_packet(self, packet):
        """
        Process a generated packet.
        
        Args:
            packet: Scapy packet object
        """
        # Store packet for processing by other components
        self.packets.append({
            'timestamp': datetime.now(),
            'packet': packet,
            'processed': False,
            'is_attack': self.attack_in_progress,
            'attack_type': self.attack_type if self.attack_in_progress else None
        })
        
        # Keep only the last 1000 packets
        if len(self.packets) > 1000:
            self.packets.pop(0)
    
    def get_recent_packets(self, count=100):
        """
        Get recent packets.
        
        Args:
            count (int): Number of packets to return
            
        Returns:
            list: Recent packets
        """
        return self.packets[-count:]
    
    def shutdown(self):
        """Shut down the network simulator."""
        logger.info("Network simulator shutting down")
