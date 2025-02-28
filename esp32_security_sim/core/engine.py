import logging
import time
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

class SimulationEngine:
    """
    Core simulation engine for the ESP32 security device.
    Coordinates all simulation components and manages the simulation lifecycle.
    """
    
    def __init__(self, config=None):
        """
        Initialize the simulation engine.
        
        Args:
            config (dict, optional): Configuration parameters for the simulation.
        """
        self.config = config or {}
        self.running = False
        self.start_time = None
        self.components = {}
        self.simulation_thread = None
        
        # Default configuration
        self.default_config = {
            'simulation_speed': 1.0,  # Simulation speed multiplier
            'max_duration': 3600,     # Maximum simulation duration in seconds
            'log_level': 'INFO',      # Logging level
        }
        
        # Apply default config for missing values
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # Configure logging
        logger.setLevel(getattr(logging, self.config['log_level']))
        
        logger.info("Simulation engine initialized")
    
    def register_component(self, name, component):
        """
        Register a simulation component.
        
        Args:
            name (str): Name of the component
            component (object): Component instance
        """
        self.components[name] = component
        logger.debug(f"Registered component: {name}")
    
    def start(self):
        """Start the simulation."""
        if self.running:
            logger.warning("Simulation is already running")
            return
        
        self.running = True
        self.start_time = datetime.now()
        logger.info(f"Starting simulation at {self.start_time}")
        
        # Initialize all components
        for name, component in self.components.items():
            if hasattr(component, 'initialize'):
                component.initialize()
            logger.debug(f"Initialized component: {name}")
        
        # Start the simulation in a separate thread
        self.simulation_thread = threading.Thread(target=self._run_simulation)
        self.simulation_thread.daemon = True
        self.simulation_thread.start()
        
        logger.info("Simulation started")
    
    def stop(self):
        """Stop the simulation."""
        if not self.running:
            logger.warning("Simulation is not running")
            return
        
        self.running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=5.0)
        
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        logger.info(f"Simulation stopped after {duration:.2f} seconds")
        
        # Shutdown all components
        for name, component in self.components.items():
            if hasattr(component, 'shutdown'):
                component.shutdown()
            logger.debug(f"Shut down component: {name}")
    
    def _run_simulation(self):
        """Run the simulation loop."""
        try:
            cycle = 0
            while self.running:
                cycle_start = time.time()
                
                # Update all components
                for name, component in self.components.items():
                    if hasattr(component, 'update'):
                        component.update(cycle)
                
                cycle += 1
                
                # Sleep to maintain consistent simulation speed
                cycle_duration = time.time() - cycle_start
                sleep_time = max(0, (1.0 / self.config['simulation_speed']) - cycle_duration)
                time.sleep(sleep_time)
                
                # Check if simulation should end
                elapsed = (datetime.now() - self.start_time).total_seconds()
                if self.config['max_duration'] > 0 and elapsed >= self.config['max_duration']:
                    logger.info(f"Simulation reached maximum duration of {self.config['max_duration']} seconds")
                    self.running = False
        
        except Exception as e:
            logger.error(f"Error in simulation loop: {e}", exc_info=True)
            self.running = False
