"""
Custom backend module for cryptography functionality.
This provides a fallback when the standard cryptography backend is not available.
"""

import logging

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.backends import default_backend
    logger.info("Using cryptography default backend")
except ImportError:
    logger.warning("Cryptography backend not available, using dummy implementation")
    
    def default_backend():
        """Dummy backend implementation."""
        return None
