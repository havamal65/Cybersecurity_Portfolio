import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class Firewall:
    """
    Simulates a firewall for the ESP32 security device.
    Filters packets based on rules and detects suspicious traffic.
    """
    
    def __init__(self, engine, config=None):
        """
        Initialize the firewall.
        
        Args:
            engine: The simulation engine
            config (dict, optional): Configuration parameters
        """
        self.engine = engine
        self.config = config or {}
        
        # Default configuration
        self.default_config = {
            'default_policy': 'allow',  # Default policy: 'allow' or 'block'
            'rules': [
                # Format: {protocol, src_ip, src_port, dst_ip, dst_port, action}
                # Block incoming SSH
                {'protocol': 'tcp', 'dst_port': 22, 'src_ip': 'external', 'action': 'block'},
                # Allow HTTP/HTTPS
                {'protocol': 'tcp', 'dst_port': 80, 'action': 'allow'},
                {'protocol': 'tcp', 'dst_port': 443, 'action': 'allow'},
                # Block all telnet
                {'protocol': 'tcp', 'dst_port': 23, 'action': 'block'},
            ],
            'log_blocked': True,        # Log blocked packets
            'log_allowed': False,       # Log allowed packets
            'rate_limiting': {          # Rate limiting configuration
                'enabled': True,
                'max_connections': 50,  # Max connections per minute per IP
                'window': 60,           # Window size in seconds
            }
        }
        
        # Apply default config for missing values
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # Initialize state
        self.blocked_packets = []
        self.allowed_packets = []
        self.connection_tracker = {}  # Track connections for rate limiting
        
        # Register with engine
        self.engine.register_component('firewall', self)
        
        logger.info("Firewall initialized with %d rules", len(self.config['rules']))
    
    def initialize(self):
        """Initialize the firewall."""
        logger.info("Firewall starting")
    
    def update(self, cycle):
        """
        Update the firewall for the current cycle.
        
        Args:
            cycle (int): Current simulation cycle
        """
        # Get recent packets from network simulator
        if 'network' in self.engine.components:
            network = self.engine.components['network']
            packets = network.get_recent_packets()
            
            # Process unprocessed packets
            for packet_data in packets:
                if not packet_data['processed']:
                    self._process_packet(packet_data)
                    packet_data['processed'] = True
    
    def _process_packet(self, packet_data):
        """
        Process a packet and apply firewall rules.
        
        Args:
            packet_data (dict): Packet data including the packet and metadata
        """
        packet = packet_data['packet']
        timestamp = packet_data['timestamp']
        
        # Extract packet information
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return  # Skip if unable to extract info
        
        # Check if packet should be rate limited
        if self._should_rate_limit(packet_info):
            action = 'block'
            reason = 'rate_limited'
        else:
            # Apply firewall rules
            action, reason = self._apply_rules(packet_info)
        
        # Record the decision
        packet_data['firewall_action'] = action
        packet_data['firewall_reason'] = reason
        
        # Log if configured
        if action == 'block' and self.config['log_blocked']:
            self._log_packet(packet_info, action, reason, timestamp)
            self.blocked_packets.append(packet_data)
        elif action == 'allow' and self.config['log_allowed']:
            self._log_packet(packet_info, action, reason, timestamp)
            self.allowed_packets.append(packet_data)
    
    def _extract_packet_info(self, packet):
        """
        Extract relevant information from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Extracted packet information
        """
        packet_info = {
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'size': 0,  # Default size
            'is_internal_src': False,
            'is_internal_dst': False,
        }
        
        # Set packet size - safely handle both real and mock packets
        try:
            packet_info['size'] = len(packet)
        except (TypeError, AttributeError):
            # For mock objects, just use a default size
            packet_info['size'] = 100
        
        # Mock Scapy implementation compatibility
        # Check class name instead of using 'in' operator
        is_ip = packet.__class__.__name__ == 'IP'
        is_tcp = packet.payload.__class__.__name__ == 'TCP' if hasattr(packet, 'payload') and packet.payload else False
        is_udp = packet.payload.__class__.__name__ == 'UDP' if hasattr(packet, 'payload') and packet.payload else False
        is_icmp = packet.payload.__class__.__name__ == 'ICMP' if hasattr(packet, 'payload') and packet.payload else False
        is_arp = packet.__class__.__name__ == 'ARP'
        
        # Check for IP layer
        if is_ip:
            try:
                packet_info['src_ip'] = packet.fields.get('src')
                packet_info['dst_ip'] = packet.fields.get('dst')
                
                # Check if source/destination is internal
                if packet_info['src_ip']:
                    packet_info['is_internal_src'] = packet_info['src_ip'].startswith('192.168.1.')
                if packet_info['dst_ip']:
                    packet_info['is_internal_dst'] = packet_info['dst_ip'].startswith('192.168.1.')
                
                # Check for TCP layer
                if is_tcp:
                    packet_info['protocol'] = 'tcp'
                    packet_info['src_port'] = packet.payload.fields.get('sport')
                    packet_info['dst_port'] = packet.payload.fields.get('dport')
                    packet_info['flags'] = str(packet.payload.fields.get('flags', ''))
                    
                # Check for UDP layer
                elif is_udp:
                    packet_info['protocol'] = 'udp'
                    packet_info['src_port'] = packet.payload.fields.get('sport')
                    packet_info['dst_port'] = packet.payload.fields.get('dport')
                    
                # Check for ICMP layer
                elif is_icmp:
                    packet_info['protocol'] = 'icmp'
                    packet_info['icmp_type'] = packet.payload.fields.get('type')
                    packet_info['icmp_code'] = packet.payload.fields.get('code')
            except Exception as e:
                logger.error(f"Error extracting IP packet info: {e}")
        
        # Check for ARP layer
        elif is_arp:
            try:
                packet_info['protocol'] = 'arp'
                packet_info['src_ip'] = packet.fields.get('psrc')
                packet_info['dst_ip'] = packet.fields.get('pdst')
            except Exception as e:
                logger.error(f"Error extracting ARP packet info: {e}")
        
        return packet_info
    
    def _apply_rules(self, packet_info):
        """
        Apply firewall rules to a packet.
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            tuple: (action, reason)
        """
        # Check each rule
        for rule in self.config['rules']:
            if self._rule_matches(rule, packet_info):
                return rule['action'], 'rule_match'
        
        # If no rule matched, use default policy
        return self.config['default_policy'], 'default_policy'
    
    def _rule_matches(self, rule, packet_info):
        """
        Check if a rule matches a packet.
        
        Args:
            rule (dict): Firewall rule
            packet_info (dict): Packet information
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        # Check protocol
        if 'protocol' in rule and rule['protocol'] != packet_info['protocol']:
            return False
        
        # Check source IP
        if 'src_ip' in rule:
            if rule['src_ip'] == 'external' and packet_info['is_internal_src']:
                return False
            elif rule['src_ip'] == 'internal' and not packet_info['is_internal_src']:
                return False
            elif rule['src_ip'] not in ['external', 'internal']:
                # Check for CIDR notation or direct IP match
                if not self._ip_matches(rule['src_ip'], packet_info['src_ip']):
                    return False
        
        # Check destination IP
        if 'dst_ip' in rule:
            if rule['dst_ip'] == 'external' and packet_info['is_internal_dst']:
                return False
            elif rule['dst_ip'] == 'internal' and not packet_info['is_internal_dst']:
                return False
            elif rule['dst_ip'] not in ['external', 'internal']:
                # Check for CIDR notation or direct IP match
                if not self._ip_matches(rule['dst_ip'], packet_info['dst_ip']):
                    return False
        
        # Check source port
        if 'src_port' in rule and packet_info['src_port'] is not None:
            if isinstance(rule['src_port'], list):
                if packet_info['src_port'] not in rule['src_port']:
                    return False
            elif rule['src_port'] != packet_info['src_port']:
                return False
        
        # Check destination port
        if 'dst_port' in rule and packet_info['dst_port'] is not None:
            if isinstance(rule['dst_port'], list):
                if packet_info['dst_port'] not in rule['dst_port']:
                    return False
            elif rule['dst_port'] != packet_info['dst_port']:
                return False
        
        # Check TCP flags if applicable
        if 'flags' in rule and packet_info['flags'] is not None:
            if not all(flag in packet_info['flags'] for flag in rule['flags']):
                return False
        
        # All checks passed, rule matches
        return True
    
    def _ip_matches(self, rule_ip, packet_ip):
        """
        Check if an IP matches a rule's IP specification.
        Supports exact matches and simplified CIDR notation.
        
        Args:
            rule_ip (str): IP from rule (can be CIDR)
            packet_ip (str): IP from packet
            
        Returns:
            bool: True if matches, False otherwise
        """
        # Exact match
        if rule_ip == packet_ip:
            return True
        
        # CIDR notation
        if '/' in rule_ip:
            network, bits = rule_ip.split('/')
            bits = int(bits)
            
            # Convert IPs to integers for comparison
            # This is a simplified approach for the simulation
            rule_parts = [int(p) for p in network.split('.')]
            packet_parts = [int(p) for p in packet_ip.split('.')]
            
            # Compare the first 'bits' bits
            for i in range(4):
                # Skip if we've compared all required bits
                if bits <= i * 8:
                    break
                
                # Compare full bytes
                if bits >= (i + 1) * 8:
                    if rule_parts[i] != packet_parts[i]:
                        return False
                # Compare partial byte
                else:
                    mask_bits = bits - i * 8
                    mask = (0xFF << (8 - mask_bits)) & 0xFF
                    if (rule_parts[i] & mask) != (packet_parts[i] & mask):
                        return False
            
            # All compared bits match
            return True
        
        return False
    
    def _should_rate_limit(self, packet_info):
        """
        Check if a packet should be rate limited.
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            bool: True if the packet should be rate limited
        """
        if not self.config['rate_limiting']['enabled']:
            return False
        
        current_time = datetime.now().timestamp()
        src_ip = packet_info['src_ip']
        
        # Initialize connection tracking for this IP if needed
        if src_ip not in self.connection_tracker:
            self.connection_tracker[src_ip] = []
        
        # Add current connection
        self.connection_tracker[src_ip].append(current_time)
        
        # Remove old connections outside the window
        window_start = current_time - self.config['rate_limiting']['window']
        self.connection_tracker[src_ip] = [t for t in self.connection_tracker[src_ip] if t >= window_start]
        
        # Check if rate limit is exceeded
        return len(self.connection_tracker[src_ip]) > self.config['rate_limiting']['max_connections']
    
    def _log_packet(self, packet_info, action, reason, timestamp):
        """
        Log a packet decision.
        
        Args:
            packet_info (dict): Packet information
            action (str): Action taken ('allow' or 'block')
            reason (str): Reason for the action
            timestamp (datetime): Time when the packet was processed
        """
        log_msg = f"{timestamp} | {action.upper()} | {reason} | "
        log_msg += f"{packet_info['protocol']} | "
        log_msg += f"{packet_info['src_ip']}"
        
        if packet_info['src_port'] is not None:
            log_msg += f":{packet_info['src_port']}"
            
        log_msg += f" -> {packet_info['dst_ip']}"
        
        if packet_info['dst_port'] is not None:
            log_msg += f":{packet_info['dst_port']}"
        
        if action == 'block':
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
    
    def get_blocked_packets(self, count=100):
        """
        Get recently blocked packets.
        
        Args:
            count (int): Number of packets to return
            
        Returns:
            list: Recently blocked packets
        """
        return self.blocked_packets[-count:]
    
    def get_allowed_packets(self, count=100):
        """
        Get recently allowed packets.
        
        Args:
            count (int): Number of packets to return
            
        Returns:
            list: Recently allowed packets
        """
        return self.allowed_packets[-count:]
    
    def add_rule(self, rule):
        """
        Add a new firewall rule.
        
        Args:
            rule (dict): Firewall rule to add
        """
        # Validate rule
        required_fields = ['action']
        for field in required_fields:
            if field not in rule:
                raise ValueError(f"Missing required field in rule: {field}")
        
        if rule['action'] not in ['allow', 'block']:
            raise ValueError(f"Invalid action in rule: {rule['action']}")
        
        # Add rule to configuration
        self.config['rules'].append(rule)
        logger.info(f"Added new firewall rule: {rule}")
    
    def remove_rule(self, index):
        """
        Remove a firewall rule by index.
        
        Args:
            index (int): Rule index to remove
        """
        if 0 <= index < len(self.config['rules']):
            removed_rule = self.config['rules'].pop(index)
            logger.info(f"Removed firewall rule: {removed_rule}")
        else:
            logger.warning(f"Invalid rule index: {index}")
    
    def get_rules(self):
        """
        Get all firewall rules.
        
        Returns:
            list: Firewall rules
        """
        return self.config['rules']
    
    def set_default_policy(self, policy):
        """
        Set the default firewall policy.
        
        Args:
            policy (str): Default policy ('allow' or 'block')
        """
        if policy not in ['allow', 'block']:
            raise ValueError(f"Invalid policy: {policy}")
        
        self.config['default_policy'] = policy
        logger.info(f"Default firewall policy set to: {policy}")
    
    def get_stats(self):
        """
        Get firewall statistics.
        
        Returns:
            dict: Firewall statistics
        """
        return {
            'total_blocked_packets': len(self.blocked_packets),
            'total_allowed_packets': len(self.allowed_packets),
            'active_connections': sum(len(conns) for conns in self.connection_tracker.values()),
            'rate_limited_ips': [ip for ip, conns in self.connection_tracker.items() 
                                if len(conns) > self.config['rate_limiting']['max_connections']],
            'num_rules': len(self.config['rules']),
            'default_policy': self.config['default_policy']
        }
    
    def shutdown(self):
        """Shut down the firewall."""
        logger.info("Firewall shutting down")
