"""
Network Security Module
- Port scanning (authorized testing only)
- DNS lookup and analysis
- SSL/TLS certificate analysis
- HTTP security header analysis
- IP reputation checking
"""

import socket
import ssl
import json
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from urllib.parse import urlparse
import struct
import ipaddress

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

import sys
sys.path.append('..')
from core.base import BaseModule


@dataclass
class PortScanResult:
    """Port scan result container"""
    port: int
    state: str
    service: str
    banner: str


class NetworkSecurityModule(BaseModule):
    """Network security analysis and testing tools"""

    # Common services by port
    COMMON_SERVICES = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        119: "NNTP",
        123: "NTP",
        135: "MS RPC",
        137: "NetBIOS Name",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "SMTP Submission",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1434: "MSSQL Browser",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        27017: "MongoDB"
    }

    # Security-sensitive ports
    HIGH_RISK_PORTS = {
        21: "FTP - unencrypted file transfer",
        23: "Telnet - unencrypted remote access",
        25: "SMTP - potential spam relay",
        135: "MS RPC - common attack vector",
        137: "NetBIOS - information disclosure",
        139: "NetBIOS - potential file sharing exposure",
        445: "SMB - ransomware attack vector",
        1433: "MSSQL - database exposure",
        3306: "MySQL - database exposure",
        3389: "RDP - brute force target",
        5900: "VNC - remote access exposure",
        6379: "Redis - often unsecured",
        27017: "MongoDB - often unsecured"
    }

    def __init__(self):
        super().__init__("NetworkSecurity")
        self.timeout = 2

    def get_info(self) -> Dict[str, str]:
        return {
            "name": "Network Security Module",
            "version": "1.0.0",
            "description": "Network security analysis and authorized penetration testing tools",
            "features": [
                "Port scanning (TCP connect)",
                "Service detection and banner grabbing",
                "DNS record analysis",
                "SSL/TLS certificate analysis",
                "HTTP security header analysis",
                "Network vulnerability assessment"
            ],
            "disclaimer": "Use only on systems you own or have explicit authorization to test"
        }

    def run(self, target: str = None, action: str = "scan") -> Dict[str, Any]:
        """Execute network security operations"""
        self.start()

        if action == "scan" and target:
            result = self.scan_common_ports(target)
        elif action == "dns" and target:
            result = self.dns_lookup(target)
        elif action == "ssl" and target:
            result = self.analyze_ssl(target)
        else:
            result = {"error": "Invalid action or missing target"}

        self.add_result(result)
        self.finish()
        return self.get_summary()

    def scan_port(self, host: str, port: int, timeout: float = 2) -> PortScanResult:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open, try to grab banner
                banner = ""
                service = self.COMMON_SERVICES.get(port, "Unknown")

                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:100]
                except:
                    pass

                sock.close()
                return PortScanResult(port, "open", service, banner)
            else:
                sock.close()
                return PortScanResult(port, "closed", "", "")

        except socket.timeout:
            return PortScanResult(port, "filtered", "", "")
        except Exception as e:
            return PortScanResult(port, "error", "", str(e))

    def scan_common_ports(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """Scan common ports on target host"""
        if ports is None:
            ports = list(self.COMMON_SERVICES.keys())

        # Resolve hostname
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"error": f"Could not resolve hostname: {host}"}

        results = {
            "target": host,
            "ip": ip,
            "scan_time": datetime.utcnow().isoformat(),
            "ports_scanned": len(ports),
            "open_ports": [],
            "filtered_ports": [],
            "security_concerns": []
        }

        # Parallel port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port, self.timeout): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                scan_result = future.result()

                if scan_result.state == "open":
                    port_info = {
                        "port": scan_result.port,
                        "service": scan_result.service,
                        "banner": scan_result.banner
                    }
                    results["open_ports"].append(port_info)

                    # Check for security concerns
                    if scan_result.port in self.HIGH_RISK_PORTS:
                        results["security_concerns"].append({
                            "port": scan_result.port,
                            "service": scan_result.service,
                            "risk": self.HIGH_RISK_PORTS[scan_result.port]
                        })

                elif scan_result.state == "filtered":
                    results["filtered_ports"].append(scan_result.port)

        # Sort results
        results["open_ports"].sort(key=lambda x: x["port"])
        results["filtered_ports"].sort()

        # Summary
        results["summary"] = {
            "total_open": len(results["open_ports"]),
            "total_filtered": len(results["filtered_ports"]),
            "security_issues": len(results["security_concerns"]),
            "risk_level": "HIGH" if results["security_concerns"] else "LOW"
        }

        return results

    def scan_port_range(self, host: str, start_port: int, end_port: int) -> Dict[str, Any]:
        """Scan a range of ports"""
        ports = list(range(start_port, min(end_port + 1, 65536)))
        return self.scan_common_ports(host, ports)

    def dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS record lookup"""
        results = {
            "domain": domain,
            "lookup_time": datetime.utcnow().isoformat(),
            "records": {},
            "security_analysis": []
        }

        # Basic socket lookup
        try:
            ip = socket.gethostbyname(domain)
            results["records"]["A"] = [ip]
        except socket.gaierror:
            results["records"]["A"] = []

        if DNS_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    records = []
                    for rdata in answers:
                        if record_type == 'MX':
                            records.append({
                                "priority": rdata.preference,
                                "host": str(rdata.exchange)
                            })
                        elif record_type == 'SOA':
                            records.append({
                                "mname": str(rdata.mname),
                                "rname": str(rdata.rname),
                                "serial": rdata.serial
                            })
                        else:
                            records.append(str(rdata))
                    results["records"][record_type] = records
                except Exception:
                    pass

            # Security analysis
            txt_records = results["records"].get("TXT", [])

            # Check for SPF
            spf_found = any("v=spf1" in str(r) for r in txt_records)
            if not spf_found:
                results["security_analysis"].append({
                    "check": "SPF Record",
                    "status": "MISSING",
                    "severity": "MEDIUM",
                    "recommendation": "Add SPF record to prevent email spoofing"
                })
            else:
                results["security_analysis"].append({
                    "check": "SPF Record",
                    "status": "FOUND",
                    "severity": "OK"
                })

            # Check for DMARC
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
                results["security_analysis"].append({
                    "check": "DMARC Record",
                    "status": "FOUND",
                    "severity": "OK"
                })
            except:
                results["security_analysis"].append({
                    "check": "DMARC Record",
                    "status": "MISSING",
                    "severity": "MEDIUM",
                    "recommendation": "Add DMARC record for email authentication"
                })
        else:
            results["note"] = "Install dnspython for comprehensive DNS analysis"

        return results

    def analyze_ssl(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate and configuration"""
        results = {
            "host": host,
            "port": port,
            "analysis_time": datetime.utcnow().isoformat(),
            "certificate": {},
            "security_issues": [],
            "protocol_support": {}
        }

        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Certificate info
                    results["certificate"] = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    }

                    # Check expiration
                    not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                    days_until_expiry = (datetime.fromtimestamp(not_after) - datetime.now()).days

                    results["certificate"]["days_until_expiry"] = days_until_expiry

                    if days_until_expiry < 0:
                        results["security_issues"].append({
                            "severity": "CRITICAL",
                            "issue": "Certificate has expired",
                            "days_expired": abs(days_until_expiry)
                        })
                    elif days_until_expiry < 30:
                        results["security_issues"].append({
                            "severity": "HIGH",
                            "issue": "Certificate expiring soon",
                            "days_remaining": days_until_expiry
                        })

                    # Connection info
                    results["connection"] = {
                        "protocol": version,
                        "cipher_suite": cipher[0],
                        "cipher_bits": cipher[2]
                    }

                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', '3DES', 'NULL']
                    for weak in weak_ciphers:
                        if weak in cipher[0]:
                            results["security_issues"].append({
                                "severity": "HIGH",
                                "issue": f"Weak cipher in use: {weak}",
                                "cipher": cipher[0]
                            })

            # Test protocol versions
            protocols = [
                ('SSLv3', ssl.PROTOCOL_SSLv23),
                ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
                ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
                ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
            ]

            deprecated_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1']

            for proto_name, proto in protocols:
                if proto is None:
                    continue
                try:
                    ctx = ssl.SSLContext(proto)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock) as ssock:
                            results["protocol_support"][proto_name] = True
                            if proto_name in deprecated_protocols:
                                results["security_issues"].append({
                                    "severity": "MEDIUM",
                                    "issue": f"Deprecated protocol supported: {proto_name}",
                                    "recommendation": "Disable deprecated TLS versions"
                                })
                except:
                    results["protocol_support"][proto_name] = False

            # Overall grade
            if any(i["severity"] == "CRITICAL" for i in results["security_issues"]):
                results["grade"] = "F"
            elif any(i["severity"] == "HIGH" for i in results["security_issues"]):
                results["grade"] = "C"
            elif any(i["severity"] == "MEDIUM" for i in results["security_issues"]):
                results["grade"] = "B"
            else:
                results["grade"] = "A"

        except ssl.SSLError as e:
            results["error"] = f"SSL Error: {str(e)}"
            results["grade"] = "F"
        except socket.error as e:
            results["error"] = f"Connection Error: {str(e)}"
        except Exception as e:
            results["error"] = f"Analysis Error: {str(e)}"

        return results

    def analyze_http_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        import urllib.request

        results = {
            "url": url,
            "analysis_time": datetime.utcnow().isoformat(),
            "headers": {},
            "security_headers": {},
            "missing_headers": [],
            "score": 0
        }

        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'HIGH',
                'description': 'Enforces HTTPS connections'
            },
            'Content-Security-Policy': {
                'severity': 'HIGH',
                'description': 'Prevents XSS and injection attacks'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'description': 'Prevents clickjacking'
            },
            'X-Content-Type-Options': {
                'severity': 'MEDIUM',
                'description': 'Prevents MIME sniffing'
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'description': 'Legacy XSS filter'
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'severity': 'MEDIUM',
                'description': 'Controls browser features'
            }
        }

        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'SecurityScanner/1.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = dict(response.headers)
                results["headers"] = headers
                results["status_code"] = response.status

                # Check each security header
                max_score = len(security_headers) * 10
                current_score = 0

                for header, info in security_headers.items():
                    if header in headers or header.lower() in [h.lower() for h in headers]:
                        # Find actual header value
                        actual_header = next((h for h in headers if h.lower() == header.lower()), header)
                        results["security_headers"][header] = {
                            "present": True,
                            "value": headers.get(actual_header, ""),
                            "description": info['description']
                        }
                        current_score += 10
                    else:
                        results["missing_headers"].append({
                            "header": header,
                            "severity": info['severity'],
                            "description": info['description']
                        })

                results["score"] = int((current_score / max_score) * 100)

                # Determine grade
                if results["score"] >= 90:
                    results["grade"] = "A"
                elif results["score"] >= 70:
                    results["grade"] = "B"
                elif results["score"] >= 50:
                    results["grade"] = "C"
                elif results["score"] >= 30:
                    results["grade"] = "D"
                else:
                    results["grade"] = "F"

        except Exception as e:
            results["error"] = str(e)

        return results

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Basic IP reputation check"""
        results = {
            "ip": ip,
            "check_time": datetime.utcnow().isoformat(),
            "analysis": {}
        }

        try:
            # Validate IP
            ip_obj = ipaddress.ip_address(ip)
            results["analysis"]["is_private"] = ip_obj.is_private
            results["analysis"]["is_loopback"] = ip_obj.is_loopback
            results["analysis"]["is_multicast"] = ip_obj.is_multicast
            results["analysis"]["is_reserved"] = ip_obj.is_reserved
            results["analysis"]["is_global"] = ip_obj.is_global
            results["analysis"]["version"] = ip_obj.version

            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)
                results["analysis"]["reverse_dns"] = hostname[0]
            except:
                results["analysis"]["reverse_dns"] = None

            # Check common blacklists (DNS-based)
            blacklists = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'b.barracudacentral.org'
            ]

            results["blacklist_checks"] = {}
            reversed_ip = '.'.join(reversed(ip.split('.')))

            for bl in blacklists:
                try:
                    socket.gethostbyname(f"{reversed_ip}.{bl}")
                    results["blacklist_checks"][bl] = "LISTED"
                except socket.gaierror:
                    results["blacklist_checks"][bl] = "NOT LISTED"

            # Risk assessment
            listed_count = sum(1 for v in results["blacklist_checks"].values() if v == "LISTED")
            if listed_count > 0:
                results["risk_level"] = "HIGH"
                results["warning"] = f"IP found on {listed_count} blacklist(s)"
            else:
                results["risk_level"] = "LOW"

        except ValueError as e:
            results["error"] = f"Invalid IP address: {e}"

        return results

    def traceroute(self, host: str, max_hops: int = 30) -> Dict[str, Any]:
        """Simple traceroute implementation"""
        results = {
            "target": host,
            "max_hops": max_hops,
            "hops": []
        }

        try:
            dest_ip = socket.gethostbyname(host)
            results["target_ip"] = dest_ip
        except socket.gaierror:
            return {"error": f"Could not resolve: {host}"}

        # Note: Full traceroute requires raw sockets (root/admin privileges)
        # This is a simplified version that just resolves the path
        results["note"] = "Full traceroute requires administrator privileges"

        return results
