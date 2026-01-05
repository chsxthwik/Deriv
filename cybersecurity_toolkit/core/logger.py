"""
Security-focused logging system
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import json


class SecurityLogger:
    """Enhanced logger for security events and audit trails"""

    SECURITY_LEVELS = {
        'CRITICAL': 50,
        'ALERT': 45,
        'ERROR': 40,
        'WARNING': 30,
        'NOTICE': 25,
        'INFO': 20,
        'DEBUG': 10
    }

    def __init__(self, name: str = "SecurityToolkit", log_file: Optional[str] = None):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Add custom levels
        for level_name, level_value in self.SECURITY_LEVELS.items():
            if not hasattr(logging, level_name):
                logging.addLevelName(level_value, level_name)

        # Console handler with colors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)

        # File handler for audit trail
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)

    def security_event(self, event_type: str, details: dict, severity: str = "INFO"):
        """Log a structured security event"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        level = self.SECURITY_LEVELS.get(severity, logging.INFO)
        self.logger.log(level, f"SECURITY_EVENT: {json.dumps(event)}")
        return event

    def audit(self, action: str, user: str = "system", resource: str = "", result: str = "success"):
        """Log audit trail entry"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "user": user,
            "resource": resource,
            "result": result
        }
        self.logger.info(f"AUDIT: {json.dumps(audit_entry)}")
        return audit_entry

    def vulnerability(self, vuln_type: str, location: str, severity: str, description: str):
        """Log discovered vulnerability"""
        vuln = {
            "type": vuln_type,
            "location": location,
            "severity": severity,
            "description": description,
            "discovered_at": datetime.utcnow().isoformat()
        }
        level = self.SECURITY_LEVELS.get(severity, logging.WARNING)
        self.logger.log(level, f"VULNERABILITY: {json.dumps(vuln)}")
        return vuln

    def threat(self, threat_type: str, source: str, target: str, indicators: list):
        """Log threat detection"""
        threat = {
            "type": threat_type,
            "source": source,
            "target": target,
            "indicators": indicators,
            "detected_at": datetime.utcnow().isoformat()
        }
        self.logger.warning(f"THREAT: {json.dumps(threat)}")
        return threat

    def info(self, message: str):
        self.logger.info(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)

    def critical(self, message: str):
        self.logger.critical(message)

    def debug(self, message: str):
        self.logger.debug(message)
