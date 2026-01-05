"""
Helper utilities for CyberSecurity Toolkit
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional


def validate_ip(ip: str) -> bool:
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_url(url: str) -> bool:
    """Validate URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    # Remove null bytes
    text = text.replace('\x00', '')
    # Truncate
    text = text[:max_length]
    return text


def format_bytes(size: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration to human readable"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    else:
        return f"{seconds/86400:.2f} days"


def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def generate_report_header(title: str, width: int = 70) -> str:
    """Generate formatted report header"""
    lines = [
        "=" * width,
        title.center(width),
        "=" * width
    ]
    return "\n".join(lines)
