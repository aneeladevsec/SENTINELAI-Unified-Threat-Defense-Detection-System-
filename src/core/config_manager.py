"""
Configuration Manager for SentinelAI
Handles loading and managing configuration from YAML files
"""

import yaml
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from dotenv import load_dotenv


class ConfigManager:
    """Configuration management class"""
    
    def __init__(self, config_path: str = "config/config.yaml", env_file: str = ".env"):
        self.config_path = Path(config_path)
        self.env_file = Path(env_file)
        self.config = {}
        self.rules = {}
        self._load_config()
        self._load_rules()
        load_dotenv(self.env_file)
    
    def _load_config(self):
        """Load configuration from YAML file"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
    
    def _load_rules(self):
        """Load rules configuration"""
        rules_path = Path("config/rules.yaml")
        if rules_path.exists():
            with open(rules_path, 'r') as f:
                self.rules = yaml.safe_load(f) or {}
    
    def get(self, path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
        
        return value if value is not None else default
    
    def get_rule(self, path: str, default: Any = None) -> Any:
        """Get rule configuration using dot notation"""
        keys = path.split('.')
        value = self.rules
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
        
        return value if value is not None else default
    
    def get_section(self, section: str) -> Dict:
        """Get entire configuration section"""
        return self.config.get(section, {})
    
    def get_environment(self, key: str, default: str = None) -> str:
        """Get environment variable"""
        return os.getenv(key, default)
    
    def reload(self):
        """Reload configuration"""
        self._load_config()
        self._load_rules()
        load_dotenv(self.env_file)


# Global config instance
config = ConfigManager()
