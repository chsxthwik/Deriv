"""
Log Analyzer Module
- Security event detection
- Failed login analysis
- Anomaly detection
- Attack pattern recognition
- Threat intelligence
"""

import re
import os
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
import ipaddress

import sys
sys.path.append('..')
from core.base import BaseModule


@dataclass
class LogEntry:
    """Parsed log entry"""
    timestamp: datetime
    source: str
    level: str
    message: str
    raw: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEvent:
    """Security event detection"""
    event_type: str
    severity: str
    timestamp: datetime
    source: str
    details: Dict[str, Any]
    indicators: List[str]


class LogAnalyzerModule(BaseModule):
    """Advanced security log analysis and threat detection"""

    # Common log formats
    LOG_PATTERNS = {
        'syslog': r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?\s*:\s*(.*)$',
        'apache_combined': r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"',
        'apache_error': r'^\[([^\]]+)\]\s+\[(\w+)\]\s+\[client\s+([^\]]+)\]\s+(.*)$',
        'nginx_access': r'^(\S+)\s+-\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)',
        'auth_log': r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?\s*:\s*(.*)$',
        'json': r'^\{.*\}$'
    }

    # Attack patterns
    ATTACK_PATTERNS = {
        'sql_injection': [
            r"(?:union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)",
            r"(?:or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
            r"(?:drop\s+table|truncate\s+table|alter\s+table)",
            r"(?:exec\s*\(|execute\s*\(|sp_executesql)",
            r"(?:waitfor\s+delay|benchmark\s*\(|sleep\s*\()"
        ],
        'xss': [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on(?:load|error|click|mouse)\s*=",
            r"<iframe[^>]*>",
            r"eval\s*\("
        ],
        'path_traversal': [
            r"\.\.[\\/]",
            r"(?:%2e%2e[\\/]|%252e%252e[\\/])",
            r"(?:/etc/passwd|/etc/shadow|/proc/)",
            r"(?:c:\\windows|c:\\boot\.ini)"
        ],
        'command_injection': [
            r";\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh)\s",
            r"\|\s*(?:cat|ls|id|whoami|bash|sh)\s",
            r"`[^`]+`",
            r"\$\([^)]+\)"
        ],
        'brute_force': [
            r"(?:failed\s+(?:password|login)|authentication\s+fail)",
            r"(?:invalid\s+user|unknown\s+user)",
            r"(?:too\s+many\s+authentication\s+failures)"
        ],
        'scanner': [
            r"(?:nikto|nmap|sqlmap|wpscan|burp|acunetix)",
            r"(?:masscan|zmap|dirbuster|gobuster)",
            r"(?:User-Agent:.*(?:bot|crawler|spider|scan))"
        ]
    }

    # Suspicious IPs patterns (private ranges for demo)
    SUSPICIOUS_PATTERNS = {
        'tor_exit': [],  # Would be populated from threat intel
        'known_bad': []
    }

    def __init__(self):
        super().__init__("LogAnalyzer")
        self.events = []
        self.ip_stats = defaultdict(lambda: {'requests': 0, 'failures': 0, 'attacks': 0})
        self.user_stats = defaultdict(lambda: {'logins': 0, 'failures': 0, 'last_seen': None})

    def get_info(self) -> Dict[str, str]:
        return {
            "name": "Log Analyzer Module",
            "version": "1.0.0",
            "description": "Security-focused log analysis and threat detection",
            "features": [
                "Multi-format log parsing (syslog, Apache, Nginx, JSON)",
                "SQL injection attack detection",
                "XSS attack detection",
                "Path traversal detection",
                "Command injection detection",
                "Brute force attack detection",
                "Scanner/crawler detection",
                "Failed login analysis",
                "Anomaly detection",
                "IP reputation analysis",
                "Timeline reconstruction"
            ]
        }

    def run(self, log_path: str = None, action: str = "analyze") -> Dict[str, Any]:
        """Execute log analysis"""
        self.start()

        if action == "analyze" and log_path:
            result = self.analyze_log_file(log_path)
        else:
            result = {"error": "Invalid action or missing log path"}

        self.add_result(result)
        self.finish()
        return self.get_summary()

    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        line = line.strip()
        if not line:
            return None

        # Try JSON format first
        if line.startswith('{'):
            try:
                data = json.loads(line)
                return LogEntry(
                    timestamp=datetime.fromisoformat(data.get('timestamp', data.get('@timestamp', ''))),
                    source=data.get('source', data.get('host', 'unknown')),
                    level=data.get('level', data.get('severity', 'INFO')),
                    message=data.get('message', str(data)),
                    raw=line,
                    metadata=data
                )
            except:
                pass

        # Try other formats
        for format_name, pattern in self.LOG_PATTERNS.items():
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                groups = match.groups()

                if format_name == 'syslog':
                    try:
                        ts = datetime.strptime(groups[0], '%b %d %H:%M:%S')
                        ts = ts.replace(year=datetime.now().year)
                    except:
                        ts = datetime.now()

                    return LogEntry(
                        timestamp=ts,
                        source=groups[1],
                        level='INFO',
                        message=groups[4] if len(groups) > 4 else '',
                        raw=line,
                        metadata={'process': groups[2], 'pid': groups[3] if len(groups) > 3 else None}
                    )

                elif format_name in ['apache_combined', 'nginx_access']:
                    try:
                        ts = datetime.strptime(groups[1].split()[0], '%d/%b/%Y:%H:%M:%S')
                    except:
                        ts = datetime.now()

                    return LogEntry(
                        timestamp=ts,
                        source=groups[0],
                        level='INFO',
                        message=groups[2],
                        raw=line,
                        metadata={
                            'client_ip': groups[0],
                            'request': groups[2],
                            'status': int(groups[3]),
                            'size': int(groups[4])
                        }
                    )

        # Fallback - basic parsing
        return LogEntry(
            timestamp=datetime.now(),
            source='unknown',
            level='INFO',
            message=line,
            raw=line
        )

    def detect_attacks(self, log_entry: LogEntry) -> List[SecurityEvent]:
        """Detect attack patterns in log entry"""
        events = []
        message = log_entry.message + log_entry.raw

        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    severity = 'CRITICAL' if attack_type in ['sql_injection', 'command_injection'] else 'HIGH'

                    events.append(SecurityEvent(
                        event_type=attack_type,
                        severity=severity,
                        timestamp=log_entry.timestamp,
                        source=log_entry.source,
                        details={
                            'pattern_matched': pattern,
                            'message': log_entry.message[:200]
                        },
                        indicators=[pattern]
                    ))
                    break  # One detection per attack type

        return events

    def analyze_log_file(self, log_path: str) -> Dict[str, Any]:
        """Analyze log file for security events"""
        if not os.path.exists(log_path):
            return {"error": f"Log file not found: {log_path}"}

        results = {
            "file": log_path,
            "analysis_time": datetime.now().isoformat(),
            "total_lines": 0,
            "parsed_lines": 0,
            "security_events": [],
            "attack_summary": defaultdict(int),
            "ip_analysis": {},
            "user_analysis": {},
            "timeline": [],
            "recommendations": []
        }

        # Reset stats
        self.ip_stats.clear()
        self.user_stats.clear()

        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    results["total_lines"] += 1

                    entry = self.parse_log_line(line)
                    if entry:
                        results["parsed_lines"] += 1

                        # Update IP stats
                        client_ip = entry.metadata.get('client_ip', entry.source)
                        if client_ip and self._is_valid_ip(client_ip):
                            self.ip_stats[client_ip]['requests'] += 1

                        # Detect failed logins
                        if self._is_failed_login(entry):
                            self.ip_stats[client_ip]['failures'] += 1
                            user = self._extract_username(entry)
                            if user:
                                self.user_stats[user]['failures'] += 1

                        # Detect attacks
                        attacks = self.detect_attacks(entry)
                        for attack in attacks:
                            results["security_events"].append({
                                "type": attack.event_type,
                                "severity": attack.severity,
                                "timestamp": attack.timestamp.isoformat(),
                                "source": attack.source,
                                "details": attack.details
                            })
                            results["attack_summary"][attack.event_type] += 1
                            self.ip_stats[client_ip]['attacks'] += 1

        except Exception as e:
            results["error"] = str(e)

        # Analyze IP behavior
        for ip, stats in self.ip_stats.items():
            if stats['attacks'] > 0 or stats['failures'] > 5:
                results["ip_analysis"][ip] = {
                    "total_requests": stats['requests'],
                    "failed_attempts": stats['failures'],
                    "attack_count": stats['attacks'],
                    "risk_level": self._calculate_ip_risk(stats)
                }

        # Analyze user behavior
        for user, stats in self.user_stats.items():
            if stats['failures'] > 3:
                results["user_analysis"][user] = {
                    "failed_logins": stats['failures'],
                    "status": "SUSPICIOUS" if stats['failures'] > 10 else "MONITOR"
                }

        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results)

        # Summary
        results["summary"] = {
            "total_events": len(results["security_events"]),
            "critical_events": sum(1 for e in results["security_events"] if e['severity'] == 'CRITICAL'),
            "high_events": sum(1 for e in results["security_events"] if e['severity'] == 'HIGH'),
            "suspicious_ips": len(results["ip_analysis"]),
            "suspicious_users": len(results["user_analysis"]),
            "risk_level": self._calculate_overall_risk(results)
        }

        return results

    def analyze_multiple_logs(self, log_paths: List[str]) -> Dict[str, Any]:
        """Analyze multiple log files and correlate events"""
        combined_results = {
            "files_analyzed": [],
            "total_events": [],
            "cross_file_correlations": [],
            "timeline": []
        }

        all_events = []

        for path in log_paths:
            result = self.analyze_log_file(path)
            combined_results["files_analyzed"].append({
                "path": path,
                "events": len(result.get("security_events", []))
            })
            all_events.extend(result.get("security_events", []))

        # Sort by timestamp
        all_events.sort(key=lambda x: x.get('timestamp', ''))
        combined_results["total_events"] = all_events

        # Detect attack campaigns (multiple events from same source)
        source_events = defaultdict(list)
        for event in all_events:
            source_events[event['source']].append(event)

        for source, events in source_events.items():
            if len(events) > 3:
                combined_results["cross_file_correlations"].append({
                    "source": source,
                    "event_count": len(events),
                    "event_types": list(set(e['type'] for e in events)),
                    "assessment": "Possible coordinated attack"
                })

        return combined_results

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            ipaddress.ip_address(ip.split(':')[0])  # Handle IP:port
            return True
        except ValueError:
            return False

    def _is_failed_login(self, entry: LogEntry) -> bool:
        """Check if entry represents failed login"""
        patterns = [
            r'failed\s+(?:password|login|auth)',
            r'authentication\s+fail',
            r'invalid\s+user',
            r'access\s+denied',
            r'unauthorized'
        ]
        message = entry.message.lower()
        return any(re.search(p, message) for p in patterns)

    def _extract_username(self, entry: LogEntry) -> Optional[str]:
        """Extract username from log entry"""
        patterns = [
            r'user[=:\s]+["\']?(\w+)',
            r'for\s+(?:user\s+)?["\']?(\w+)',
            r'invalid\s+user\s+(\w+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, entry.message, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _calculate_ip_risk(self, stats: Dict) -> str:
        """Calculate risk level for IP"""
        score = stats['attacks'] * 10 + stats['failures'] * 2

        if score >= 50:
            return "CRITICAL"
        elif score >= 20:
            return "HIGH"
        elif score >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_overall_risk(self, results: Dict) -> str:
        """Calculate overall risk level"""
        critical = results["summary"]["critical_events"]
        high = results["summary"]["high_events"]

        if critical > 5 or high > 20:
            return "CRITICAL"
        elif critical > 0 or high > 5:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self, results: Dict) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings"""
        recommendations = []

        attack_summary = results["attack_summary"]

        if attack_summary.get('sql_injection', 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Application Security",
                "recommendation": "SQL injection attempts detected. Review parameterized queries and input validation."
            })

        if attack_summary.get('xss', 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Application Security",
                "recommendation": "XSS attempts detected. Implement Content Security Policy and output encoding."
            })

        if attack_summary.get('brute_force', 0) > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Access Control",
                "recommendation": "Brute force attempts detected. Implement rate limiting and account lockout."
            })

        if len(results["ip_analysis"]) > 5:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Network Security",
                "recommendation": f"{len(results['ip_analysis'])} suspicious IPs detected. Consider implementing IP-based blocking."
            })

        if attack_summary.get('scanner', 0) > 0:
            recommendations.append({
                "priority": "LOW",
                "category": "Monitoring",
                "recommendation": "Automated scanning detected. Review firewall rules and consider WAF deployment."
            })

        return recommendations

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable security report"""
        report = []
        report.append("=" * 70)
        report.append("              SECURITY LOG ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"\nAnalysis Time: {results.get('analysis_time', 'N/A')}")
        report.append(f"Log File: {results.get('file', 'N/A')}")
        report.append(f"Lines Analyzed: {results.get('parsed_lines', 0)}/{results.get('total_lines', 0)}")

        report.append("\n" + "-" * 70)
        report.append("SUMMARY")
        report.append("-" * 70)

        summary = results.get("summary", {})
        report.append(f"Total Security Events: {summary.get('total_events', 0)}")
        report.append(f"Critical Events: {summary.get('critical_events', 0)}")
        report.append(f"High Severity Events: {summary.get('high_events', 0)}")
        report.append(f"Suspicious IPs: {summary.get('suspicious_ips', 0)}")
        report.append(f"Overall Risk Level: {summary.get('risk_level', 'UNKNOWN')}")

        if results.get("attack_summary"):
            report.append("\n" + "-" * 70)
            report.append("ATTACK BREAKDOWN")
            report.append("-" * 70)
            for attack_type, count in results["attack_summary"].items():
                report.append(f"  {attack_type}: {count}")

        if results.get("ip_analysis"):
            report.append("\n" + "-" * 70)
            report.append("SUSPICIOUS IP ADDRESSES")
            report.append("-" * 70)
            for ip, stats in list(results["ip_analysis"].items())[:10]:
                report.append(f"  {ip}: {stats['attack_count']} attacks, {stats['failed_attempts']} failures - {stats['risk_level']}")

        if results.get("recommendations"):
            report.append("\n" + "-" * 70)
            report.append("RECOMMENDATIONS")
            report.append("-" * 70)
            for rec in results["recommendations"]:
                report.append(f"\n[{rec['priority']}] {rec['category']}")
                report.append(f"  {rec['recommendation']}")

        report.append("\n" + "=" * 70)
        report.append("                     END OF REPORT")
        report.append("=" * 70)

        return "\n".join(report)
