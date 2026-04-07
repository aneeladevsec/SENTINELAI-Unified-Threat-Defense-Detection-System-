"""
Logger module for SentinelAI
Centralized logging with security event tracking
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
from logging.handlers import RotatingFileHandler


class SecurityEventLogger:
    """Custom logger for security events"""
    
    def __init__(self, log_file: str = "logs/sentinelai.log", level=logging.INFO):
        self.log_file = log_file
        self.level = level
        self.logger = self._setup_logger()
        self._ensure_log_dir()
    
    def _ensure_log_dir(self):
        """Create logs directory if it doesn't exist"""
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger with rotating file handler"""
        logger = logging.getLogger("sentinelai")
        logger.setLevel(self.level)
        
        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # File Handler with rotation
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=104857600,  # 100MB
            backupCount=10
        )
        file_handler.setLevel(self.level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def log_security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log a security event with structured data"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        if severity == "critical":
            self.logger.critical(json.dumps(event, indent=2))
        elif severity == "high":
            self.logger.error(json.dumps(event, indent=2))
        elif severity == "medium":
            self.logger.warning(json.dumps(event, indent=2))
        else:
            self.logger.info(json.dumps(event, indent=2))
    
    def log_detection(self, detection_data: Dict[str, Any]):
        """Log threat detection"""
        self.log_security_event(
            "THREAT_DETECTION",
            detection_data.get("severity", "medium"),
            detection_data
        )
    
    def log_defense_action(self, action_data: Dict[str, Any]):
        """Log defense action"""
        self.log_security_event(
            "DEFENSE_ACTION",
            "high",
            action_data
        )
    
    def log_error(self, component: str, error: Exception):
        """Log error"""
        self.logger.error(f"Error in {component}: {str(error)}", exc_info=True)
    
    def log_info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def log_warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def log_debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)


# Global logger instance
logger = SecurityEventLogger()
