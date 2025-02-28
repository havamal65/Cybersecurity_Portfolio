"""
Scapy Adapter Module

This module provides a compatibility layer for Scapy. If Scapy is not available,
it will try to provide mock implementations of the required classes.
"""

import logging

logger = logging.getLogger(__name__)

# Try to import Scapy
try:
    from scapy.all import Ether, ARP, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
    logger.info("Scapy module loaded successfully")
except ImportError:
    logger.warning("Scapy module not available. Using mock implementation.")
    SCAPY_AVAILABLE = False
    
    # Mock Scapy classes for basic functionality
    class PacketMock:
        """Base mock class for Scapy packets."""
        
        def __init__(self, **kwargs):
            self.fields = kwargs
            self.payload = None
            
        def __truediv__(self, other):
            """Implement the / operator to stack protocol layers."""
            self.payload = other
            return self
            
        def __str__(self):
            """Return a string representation."""
            result = f"{self.__class__.__name__}("
            result += ", ".join(f"{k}={v}" for k, v in self.fields.items())
            result += ")"
            if self.payload:
                result += f" / {str(self.payload)}"
            return result
    
    class Ether(PacketMock):
        """Mock Ethernet packet."""
        pass
    
    class ARP(PacketMock):
        """Mock ARP packet."""
        pass
    
    class IP(PacketMock):
        """Mock IP packet."""
        pass
    
    class TCP(PacketMock):
        """Mock TCP packet."""
        pass
    
    class UDP(PacketMock):
        """Mock UDP packet."""
        pass
    
    class ICMP(PacketMock):
        """Mock ICMP packet."""
        pass
    
    class Raw(PacketMock):
        """Mock Raw payload."""
        pass

def is_scapy_available():
    """Check if the real Scapy module is available."""
    return SCAPY_AVAILABLE

# Export the classes and functions
__all__ = ['Ether', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'Raw', 'is_scapy_available']
