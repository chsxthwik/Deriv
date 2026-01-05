"""
Configuration management for CyberSecurity Toolkit
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Central configuration manager for the security toolkit"""

    DEFAULT_CONFIG = {
        "app_name": "CyberSecurity Toolkit",
        "version": "1.0.0",
        "debug": False,
        "log_level": "INFO",
        "log_file": "logs/security.log",
        "max_threads": 10,
        "timeout": 30,
        "password": {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": True,
            "entropy_threshold": 60
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_derivation": "PBKDF2",
            "iterations": 600000,
            "salt_length": 32
        },
        "network": {
            "port_scan_timeout": 2,
            "max_ports": 65535,
            "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443],
            "rate_limit": 100
        },
        "scanner": {
            "max_file_size": 10485760,  # 10MB
            "file_extensions": [".py", ".js", ".php", ".java", ".rb", ".go", ".ts", ".sql", ".html"],
            "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
        "web": {
            "host": "127.0.0.1",
            "port": 5000,
            "secret_key": None,
            "rate_limit": "100/hour"
        }
    }

    _instance = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._config = cls.DEFAULT_CONFIG.copy()
        return cls._instance

    def load_from_file(self, config_path: str) -> bool:
        """Load configuration from JSON file"""
        try:
            path = Path(config_path)
            if path.exists():
                with open(path, 'r') as f:
                    user_config = json.load(f)
                    self._deep_update(self._config, user_config)
                return True
        except Exception as e:
            print(f"Error loading config: {e}")
        return False

    def save_to_file(self, config_path: str) -> bool:
        """Save current configuration to file"""
        try:
            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump(self._config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
        return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value

    def _deep_update(self, base: dict, update: dict) -> dict:
        """Recursively update nested dictionary"""
        for key, value in update.items():
            if isinstance(value, dict) and key in base:
                self._deep_update(base[key], value)
            else:
                base[key] = value
        return base

    @property
    def all(self) -> Dict[str, Any]:
        """Return all configuration"""
        return self._config.copy()
