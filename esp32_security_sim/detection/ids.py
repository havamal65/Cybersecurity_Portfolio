import logging
import time
import re
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class IntrusionDetectionSystem:
    """
    Simulates an Intrusion Detection System (IDS) for the ESP32 security device.
    Detects suspicious network activity and potential attacks.
    """
    
    def __init__(self, engine, config=None):
        """
        Initialize the intrusion detection system.
        
        Args:
            engine: The simulation engine
            config (dict, optional): Configuration parameters
        """
        self.engine = engine
        self.config = config or {}
        
        # Default configuration
        self.default_config = {
            'signature_detection': True,     # Use signature-based detection
            'anomaly_detection': True,       # Use anomaly-based detection
            'log_detections': True,          # Log detected threats
            'alert_threshold': 0.7,          # Confidence threshold for alerts (0-1)
            'history_size': 1000,            # Number of packets to keep in history
            'detection_interval': 5,         # Seconds between detection runs
        }
        
        # Apply default config for missing values
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # Load attack signatures
        self.signatures = self._load_signatures()
        
        # Initialize state
        self.packet_history = deque(maxlen=self.config['history_size'])
        self.alerts = []
        self.last_detection_time = time.time()
        self.flow_tracker = defaultdict(list)  # Track flows for anomaly detection
        self.baseline = self._initialize_baseline()
        
        # Register with engine
        self.engine.register_component('ids', self)
        
        logger.info("Intrusion Detection System initialized with %d signatures", len(self.signatures))
    
    def initialize(self):
        """Initialize the intrusion detection system."""
        logger.info("Intrusion Detection System starting")
    
    def update(self, cycle):
        """
        Update the intrusion detection system for the current cycle.
        
        Args:
            cycle (int): Current simulation cycle
        """
        current_time = time.time()
        elapsed = current_time - self.last_detection_time
        
        # Get recent packets from network simulator
        if 'network' in self.engine.components:
            network = self.engine.components['network']
            recent_packets = network.get_recent_packets()
            
            # Add to packet history
            for packet_data in recent_packets:
                if packet_data not in self.packet_history:
                    self.packet_history.append(packet_data)
                    # Update flow tracker
                    self._update_flow_tracking(packet_data)
        
        # Run detection at regular intervals
        if elapsed >= self.config['detection_interval']:
            self._run_detection()
            self.last_detection_time = current_time
    
    def _load_signatures(self):
        """
        Load attack signatures.
        In a real system, these would be loaded from a file or database.
        
        Returns:
            list: Attack signatures
        """
        # Signature format: {name, description, pattern, severity, confidence}
        signatures = [
            {
                'name': 'port_scan_tcp',
                'description': 'TCP port scanning activity',
                'pattern': {
                    'type': 'frequency',
                    'protocol': 'tcp',
                    'flags': 'S',  # SYN packets
                    'threshold': 10,  # Number of connections in time window
                    'window': 60,  # Time window in seconds
                    'distinct_ports': True  # Must be to different ports
                },
                'severity': 'medium',
                'confidence': 0.8
            },
            {
                'name': 'dos_attack',
                'description': 'Denial of Service attack',
                'pattern': {
                    'type': 'frequency',
                    'threshold': 50,  # Number of packets in time window
                    'window': 10,  # Time window in seconds
                    'same_dst': True  # Must be to the same destination
                },
                'severity': 'high',
                'confidence': 0.9
            },
            {
                'name': 'arp_spoofing',
                'description': 'ARP spoofing attack',
                'pattern': {
                    'type': 'content',
                    'protocol': 'arp',
                    'operation': 'reply',  # ARP reply
                    'multiple_mac': True  # Same IP with different MAC addresses
                },
                'severity': 'high',
                'confidence': 0.85
            },
            {
                'name': 'brute_force_ssh',
                'description': 'SSH brute force attempt',
                'pattern': {
                    'type': 'frequency',
                    'protocol': 'tcp',
                    'dst_port': 22,
                    'threshold': 5,  # Number of connections in time window
                    'window': 60  # Time window in seconds
                },
                'severity': 'high',
                'confidence': 0.75
            },
            {
                'name': 'unusual_outbound_data',
                'description': 'Suspicious data exfiltration',
                'pattern': {
                    'type': 'anomaly',
                    'direction': 'outbound',
                    'size_threshold': 1000,  # Minimum data size
                    'rate_threshold': 5000  # Bytes per second
                },
                'severity': 'medium',
                'confidence': 0.6
            }
        ]
        
        return signatures
    
    def _initialize_baseline(self):
        """
        Initialize the baseline for anomaly detection.
        In a real system, this would be built over time.
        
        Returns:
            dict: Baseline statistics
        """
        return {
            'avg_packets_per_minute': 600,  # Expected normal traffic rate
            'std_packets_per_minute': 150,  # Standard deviation
            'typical_flows': {
                'web': {
                    'ports': [80, 443],
                    'avg_size': 500,
                    'std_size': 300
                },
                'dns': {
                    'ports': [53],
                    'avg_size': 100,
                    'std_size': 50
                },
                'background': {
                    'avg_size': 200,
                    'std_size': 100
                }
            }
        }
    
    def _update_flow_tracking(self, packet_data):
        """
        Update flow tracking for anomaly detection.
        
        Args:
            packet_data (dict): Packet data
        """
        packet = packet_data['packet']
        
        # Mock Scapy implementation compatibility
        # Check class name instead of using 'in' operator
        is_ip = packet.__class__.__name__ == 'IP'
        is_tcp = packet.payload.__class__.__name__ == 'TCP' if hasattr(packet, 'payload') and packet.payload else False
        is_udp = packet.payload.__class__.__name__ == 'UDP' if hasattr(packet, 'payload') and packet.payload else False
        
        # Skip if not an IP packet
        if not is_ip:
            return
        
        # Create flow key: protocol-src_ip-dst_ip-src_port-dst_port
        flow_key = None
        
        try:
            src_ip = packet.fields.get('src', 'unknown')
            dst_ip = packet.fields.get('dst', 'unknown')
            
            if is_tcp:
                sport = packet.payload.fields.get('sport', 0)
                dport = packet.payload.fields.get('dport', 0)
                flow_key = f"tcp-{src_ip}-{dst_ip}-{sport}-{dport}"
            elif is_udp:
                sport = packet.payload.fields.get('sport', 0)
                dport = packet.payload.fields.get('dport', 0)
                flow_key = f"udp-{src_ip}-{dst_ip}-{sport}-{dport}"
        except Exception as e:
            logger.error(f"Error creating flow key: {e}")
            return
        
        if flow_key:
            # Record packet in flow
            
            # Get packet size safely
            try:
                packet_size = len(packet)
            except (TypeError, AttributeError):
                # For mock objects, use a default size
                packet_size = 100
                
            self.flow_tracker[flow_key].append({
                'timestamp': time.time(),
                'size': packet_size,
                'packet_data': packet_data
            })
            
            # Limit flow history
            max_flow_history = 100
            if len(self.flow_tracker[flow_key]) > max_flow_history:
                self.flow_tracker[flow_key] = self.flow_tracker[flow_key][-max_flow_history:]
    
    def _run_detection(self):
        """Run intrusion detection on collected packets."""
        # Signature-based detection
        if self.config['signature_detection']:
            self._run_signature_detection()
        
        # Anomaly-based detection
        if self.config['anomaly_detection']:
            self._run_anomaly_detection()
    
    def _run_signature_detection(self):
        """Run signature-based detection."""
        for signature in self.signatures:
            if signature['pattern']['type'] == 'frequency':
                self._check_frequency_pattern(signature)
            elif signature['pattern']['type'] == 'content':
                self._check_content_pattern(signature)
    
    def _check_frequency_pattern(self, signature):
        """
        Check for frequency-based patterns.
        
        Args:
            signature (dict): Attack signature
        """
        pattern = signature['pattern']
        current_time = time.time()
        window_start = current_time - pattern['window']
        
        # Filter packets in the time window
        window_packets = [p for p in self.packet_history if p['timestamp'].timestamp() >= window_start]
        
        # Apply additional filters
        filtered_packets = []
        for packet_data in window_packets:
            packet = packet_data['packet']
            
            # Mock Scapy implementation compatibility - check packet types by class name
            is_ip = packet.__class__.__name__ == 'IP'
            is_tcp = False
            is_udp = False
            is_icmp = False
            
            if is_ip and hasattr(packet, 'payload') and packet.payload:
                is_tcp = packet.payload.__class__.__name__ == 'TCP'
                is_udp = packet.payload.__class__.__name__ == 'UDP'
                is_icmp = packet.payload.__class__.__name__ == 'ICMP'
            
            # Check protocol if specified
            if 'protocol' in pattern:
                if pattern['protocol'] == 'tcp' and not is_tcp:
                    continue
                elif pattern['protocol'] == 'udp' and not is_udp:
                    continue
                elif pattern['protocol'] == 'icmp' and not is_icmp:
                    continue
            
            # Check TCP flags if specified
            if 'flags' in pattern and is_tcp:
                flags = str(packet.payload.fields.get('flags', ''))
                if pattern['flags'] not in flags:
                    continue
            
            # Check destination port if specified
            if 'dst_port' in pattern:
                # Check if packet is TCP
                is_tcp = False
                is_udp = False
                tcp_dport = None
                udp_dport = None
                
                if hasattr(packet, 'payload'):
                    if packet.payload.__class__.__name__ == 'TCP':
                        is_tcp = True
                        tcp_dport = getattr(packet.payload, 'dport', None)
                    elif packet.payload.__class__.__name__ == 'UDP':
                        is_udp = True
                        udp_dport = getattr(packet.payload, 'dport', None)
                elif hasattr(packet, 'fields'):
                    if packet.__class__.__name__ == 'TCP':
                        is_tcp = True
                        tcp_dport = packet.fields.get('dport', None)
                    elif packet.__class__.__name__ == 'UDP':
                        is_udp = True
                        udp_dport = packet.fields.get('dport', None)
                
                # Skip if neither TCP nor UDP match the destination port
                if (is_tcp and tcp_dport != pattern['dst_port']) and (is_udp and udp_dport != pattern['dst_port']):
                    continue
                if not is_tcp and not is_udp:
                    continue
            
            filtered_packets.append(packet_data)
        
        # Check for pattern match
        match = False
        details = {}
        
        if 'distinct_ports' in pattern and pattern['distinct_ports']:
            # Group by source IP
            src_ips = {}
            for packet_data in filtered_packets:
                packet = packet_data['packet']
                
                # Check packet type
                is_ip = packet.__class__.__name__ == 'IP'
                if not is_ip:
                    continue
                
                src_ip = packet.fields.get('src', 'unknown')
                if src_ip not in src_ips:
                    src_ips[src_ip] = set()
                
                # Add destination port - check packet type
                is_tcp = False
                is_udp = False
                
                if hasattr(packet, 'payload') and packet.payload:
                    is_tcp = packet.payload.__class__.__name__ == 'TCP'
                    is_udp = packet.payload.__class__.__name__ == 'UDP'
                
                if is_tcp:
                    dport = packet.payload.fields.get('dport', 0)
                    src_ips[src_ip].add(dport)
                elif is_udp:
                    dport = packet.payload.fields.get('dport', 0)
                    src_ips[src_ip].add(dport)
            
            # Check for sources contacting multiple distinct ports
            for src_ip, ports in src_ips.items():
                if len(ports) >= pattern['threshold']:
                    match = True
                    details = {
                        'src_ip': src_ip,
                        'num_ports': len(ports),
                        'ports': list(ports)[:10]  # First 10 ports for brevity
                    }
                    break
        
        elif 'same_dst' in pattern and pattern['same_dst']:
            # Group by destination IP
            dst_ips = {}
            for packet_data in filtered_packets:
                packet = packet_data['packet']
                
                # Check packet type
                is_ip = packet.__class__.__name__ == 'IP'
                if not is_ip:
                    continue
                
                dst_ip = packet.fields.get('dst', 'unknown')
                if dst_ip not in dst_ips:
                    dst_ips[dst_ip] = 0
                
                dst_ips[dst_ip] += 1
            
            # Check for destinations receiving excessive traffic
            for dst_ip, count in dst_ips.items():
                if count >= pattern['threshold']:
                    match = True
                    details = {
                        'dst_ip': dst_ip,
                        'packet_count': count
                    }
                    break
        
        else:
            # Simple frequency check
            if len(filtered_packets) >= pattern['threshold']:
                match = True
                details = {
                    'packet_count': len(filtered_packets),
                    'window_seconds': pattern['window']
                }
        
        # Create alert if matched
        if match and signature['confidence'] >= self.config['alert_threshold']:
            self._create_alert(
                signature['name'],
                signature['description'],
                signature['severity'],
                signature['confidence'],
                details
            )
    
    def _check_content_pattern(self, signature):
        """
        Check for content-based patterns.
        
        Args:
            signature (dict): Attack signature
        """
        pattern = signature['pattern']
        
        # ARP spoofing detection
        if pattern['protocol'] == 'arp' and pattern.get('multiple_mac', False):
            # Track IP to MAC mappings
            ip_to_mac = {}
            duplicate_ips = set()
            
            for packet_data in self.packet_history:
                packet = packet_data['packet']
                # Check if packet is an ARP packet
                is_arp = False
                if hasattr(packet, 'payload'):
                    is_arp = packet.payload.__class__.__name__ == 'ARP'
                elif hasattr(packet, 'fields') and 'op' in packet.fields:
                    is_arp = True
                
                if not is_arp:
                    continue
                
                # Get ARP operation (op) and source IP/MAC
                if hasattr(packet, 'payload'):
                    arp_layer = packet.payload
                    op = getattr(arp_layer, 'op', 0)
                    psrc = getattr(arp_layer, 'psrc', None)
                    hwsrc = getattr(arp_layer, 'hwsrc', None)
                else:
                    op = packet.fields.get('op', 0)
                    psrc = packet.fields.get('psrc', None)
                    hwsrc = packet.fields.get('hwsrc', None)
                
                if op == 2:  # ARP reply
                    ip = psrc
                    mac = hwsrc
                    
                    if ip in ip_to_mac and ip_to_mac[ip] != mac:
                        duplicate_ips.add(ip)
                    
                    ip_to_mac[ip] = mac
            
            # Check for IP addresses with multiple MAC addresses
            if duplicate_ips:
                details = {
                    'affected_ips': list(duplicate_ips),
                    'mappings': {ip: ip_to_mac[ip] for ip in duplicate_ips}
                }
                
                self._create_alert(
                    signature['name'],
                    signature['description'],
                    signature['severity'],
                    signature['confidence'],
                    details
                )
    
    def _run_anomaly_detection(self):
        """Run anomaly-based detection."""
        current_time = time.time()
        
        # Check for unusual outbound data transfers
        for flow_key, packets in self.flow_tracker.items():
            if not flow_key.startswith('tcp-') and not flow_key.startswith('udp-'):
                continue
            
            # Parse flow key
            parts = flow_key.split('-')
            protocol = parts[0]
            src_ip = parts[1]
            dst_ip = parts[2]
            
            # Check if this is outbound traffic
            is_outbound = src_ip.startswith('192.168.1.')
            
            if is_outbound and not dst_ip.startswith('192.168.1.'):
                # Filter recent packets
                window = 60  # 1 minute window
                recent_packets = [p for p in packets if current_time - p['timestamp'] <= window]
                
                if not recent_packets:
                    continue
                
                # Calculate total data transferred
                total_bytes = sum(p['size'] for p in recent_packets)
                
                # Calculate transfer rate (bytes per second)
                first_timestamp = min(p['timestamp'] for p in recent_packets)
                last_timestamp = max(p['timestamp'] for p in recent_packets)
                duration = last_timestamp - first_timestamp
                rate = total_bytes / max(1, duration)  # Avoid division by zero
                
                # Check for anomalous data transfer
                for signature in self.signatures:
                    if signature['pattern']['type'] == 'anomaly' and signature['pattern']['direction'] == 'outbound':
                        if (total_bytes >= signature['pattern']['size_threshold'] and 
                            rate >= signature['pattern']['rate_threshold']):
                            
                            details = {
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'total_bytes': total_bytes,
                                'duration_seconds': duration,
                                'rate_bytes_per_second': rate,
                                'protocol': protocol
                            }
                            
                            self._create_alert(
                                signature['name'],
                                signature['description'],
                                signature['severity'],
                                signature['confidence'],
                                details
                            )
    
    def _create_alert(self, name, description, severity, confidence, details):
        """
        Create a security alert.
        
        Args:
            name (str): Alert name
            description (str): Alert description
            severity (str): Alert severity
            confidence (float): Alert confidence
            details (dict): Alert details
        """
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': time.time(),
            'name': name,
            'description': description,
            'severity': severity,
            'confidence': confidence,
            'details': details
        }
        
        self.alerts.append(alert)
        
        if self.config['log_detections']:
            logger.warning(
                f"Security Alert: {name} (Severity: {severity}, Confidence: {confidence:.2f})"
            )
            for key, value in details.items():
                logger.warning(f"  {key}: {value}")
    
    def get_alerts(self, count=None, min_severity=None):
        """
        Get security alerts.
        
        Args:
            count (int, optional): Maximum number of alerts to return
            min_severity (str, optional): Minimum severity level
            
        Returns:
            list: Security alerts
        """
        filtered_alerts = self.alerts
        
        if min_severity:
            severity_levels = {
                'low': 1,
                'medium': 2,
                'high': 3
            }
            min_level = severity_levels.get(min_severity.lower(), 0)
            filtered_alerts = [a for a in filtered_alerts 
                              if severity_levels.get(a['severity'].lower(), 0) >= min_level]
        
        if count is not None:
            filtered_alerts = filtered_alerts[-count:]
        
        return filtered_alerts
    
    def clear_alerts(self):
        """Clear all alerts."""
        num_alerts = len(self.alerts)
        self.alerts = []
        logger.info(f"Cleared {num_alerts} security alerts")
    
    def set_detection_mode(self, signature_detection=None, anomaly_detection=None):
        """
        Set detection modes.
        
        Args:
            signature_detection (bool, optional): Enable/disable signature-based detection
            anomaly_detection (bool, optional): Enable/disable anomaly-based detection
        """
        if signature_detection is not None:
            self.config['signature_detection'] = signature_detection
            logger.info(f"Signature-based detection {'enabled' if signature_detection else 'disabled'}")
        
        if anomaly_detection is not None:
            self.config['anomaly_detection'] = anomaly_detection
            logger.info(f"Anomaly-based detection {'enabled' if anomaly_detection else 'disabled'}")
    
    def shutdown(self):
        """Shut down the intrusion detection system."""
        logger.info("Intrusion Detection System shutting down")
