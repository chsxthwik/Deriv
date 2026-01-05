"""
Code Vulnerability Scanner Module
- SQL Injection detection
- XSS (Cross-Site Scripting) detection
- Command Injection detection
- Path Traversal detection
- Sensitive Data Exposure detection
- Insecure Deserialization detection
- Security Misconfiguration detection
"""

import re
import os
import ast
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import sys
sys.path.append('..')
from core.base import BaseModule


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Vulnerability:
    """Vulnerability finding"""
    vuln_type: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    cwe_id: str = ""
    owasp_category: str = ""


@dataclass
class ScanResult:
    """Scan result container"""
    files_scanned: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: float = 0


class CodeVulnerabilityScanner(BaseModule):
    """Advanced source code vulnerability scanner"""

    # SQL Injection patterns
    SQL_PATTERNS = [
        # String concatenation in SQL
        (r'["\']SELECT.*\+.*["\']', "SQL query with string concatenation"),
        (r'["\']INSERT.*\+.*["\']', "SQL INSERT with string concatenation"),
        (r'["\']UPDATE.*\+.*["\']', "SQL UPDATE with string concatenation"),
        (r'["\']DELETE.*\+.*["\']', "SQL DELETE with string concatenation"),
        # Format string SQL
        (r'execute\s*\(\s*["\'].*%s.*["\']', "SQL query with format string"),
        (r'\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', "SQL with .format()"),
        (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{', "SQL with f-string"),
        # Raw SQL execution
        (r'cursor\.execute\s*\([^,\)]+\+', "Direct SQL execution with concatenation"),
        (r'raw\s*\(\s*["\'].*%', "Django raw SQL with formatting"),
        (r'\.query\s*\(\s*["\'].*\+', "Query with string concatenation"),
    ]

    # XSS patterns
    XSS_PATTERNS = [
        # Direct HTML output
        (r'innerHTML\s*=\s*[^"\']*\+', "innerHTML with dynamic content"),
        (r'document\.write\s*\(', "document.write usage"),
        (r'\.html\s*\([^)]*\+', "jQuery .html() with concatenation"),
        (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        # Template injection
        (r'\{\{\s*.*\|safe\s*\}\}', "Django safe filter (potential XSS)"),
        (r'<%=\s*.*%>', "ERB unescaped output"),
        (r'v-html\s*=', "Vue v-html directive"),
        # URL-based XSS
        (r'location\.href\s*=\s*[^"\']+', "Dynamic URL assignment"),
        (r'window\.location\s*=', "Window location assignment"),
    ]

    # Command Injection patterns
    CMD_PATTERNS = [
        (r'os\.system\s*\(', "os.system() call"),
        (r'os\.popen\s*\(', "os.popen() call"),
        (r'subprocess\.call\s*\([^,\)]+\+', "subprocess with concatenation"),
        (r'subprocess\.run\s*\([^,\)]+\+', "subprocess.run with concatenation"),
        (r'subprocess\.Popen\s*\([^,\)]+shell\s*=\s*True', "Popen with shell=True"),
        (r'exec\s*\([^)]*\+', "exec() with dynamic content"),
        (r'eval\s*\(', "eval() usage"),
        (r'child_process\.exec\s*\(', "Node child_process.exec"),
        (r'Runtime\.getRuntime\(\)\.exec', "Java Runtime.exec"),
        (r'ProcessBuilder', "Java ProcessBuilder"),
        (r'\$\(.*\)', "Shell command substitution"),
        (r'`.*\$\{', "Template literal command execution"),
    ]

    # Path Traversal patterns
    PATH_PATTERNS = [
        (r'open\s*\([^)]*\+', "File open with concatenation"),
        (r'\.\./', "Path traversal sequence"),
        (r'\.\.\\\\', "Windows path traversal"),
        (r'file_get_contents\s*\([^)]*\$', "PHP file_get_contents with variable"),
        (r'include\s*\([^)]*\$', "PHP include with variable"),
        (r'require\s*\([^)]*\$', "PHP require with variable"),
        (r'readFile\s*\([^)]*\+', "Node readFile with concatenation"),
        (r'send_file\s*\([^)]*\+', "Flask send_file with concatenation"),
    ]

    # Sensitive Data patterns
    SENSITIVE_PATTERNS = [
        (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
        (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
        (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret"),
        (r'AWS_ACCESS_KEY', "AWS access key"),
        (r'AWS_SECRET', "AWS secret key"),
        (r'private_key\s*=', "Private key in code"),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Embedded private key"),
        (r'-----BEGIN\s+CERTIFICATE-----', "Embedded certificate"),
        (r'jdbc:.*password=', "Database password in connection string"),
        (r'mongodb://[^:]+:[^@]+@', "MongoDB credentials in URI"),
        (r'mysql://[^:]+:[^@]+@', "MySQL credentials in URI"),
        (r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "JWT token in code"),
    ]

    # Insecure practices
    INSECURE_PATTERNS = [
        (r'verify\s*=\s*False', "SSL verification disabled"),
        (r'check_hostname\s*=\s*False', "Hostname verification disabled"),
        (r'MD5\s*\(', "Weak MD5 hash usage"),
        (r'hashlib\.md5', "Python MD5 usage"),
        (r'sha1\s*\(', "Weak SHA1 hash usage"),
        (r'random\s*\(', "Insecure random (use secrets module)"),
        (r'pickle\.loads?\s*\(', "Unsafe pickle deserialization"),
        (r'yaml\.load\s*\([^)]*\)', "Unsafe YAML load"),
        (r'json\.loads.*eval', "JSON with eval"),
        (r'CORS\s*\(\s*\*\s*\)', "Permissive CORS"),
        (r'Access-Control-Allow-Origin:\s*\*', "Permissive CORS header"),
        (r'DEBUG\s*=\s*True', "Debug mode enabled"),
        (r'allowAll|permitAll', "Permissive access control"),
    ]

    # Crypto issues
    CRYPTO_PATTERNS = [
        (r'DES\s*\(', "Weak DES encryption"),
        (r'RC4', "Weak RC4 encryption"),
        (r'ECB', "Insecure ECB mode"),
        (r'AES.*128', "AES-128 (prefer AES-256)"),
        (r'RSA.*1024', "Weak RSA key size"),
        (r'random\.random', "Cryptographically weak random"),
        (r'Math\.random', "JavaScript Math.random for crypto"),
    ]

    def __init__(self):
        super().__init__("CodeVulnerabilityScanner")
        self.supported_extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.php': 'php',
            '.java': 'java',
            '.rb': 'ruby',
            '.go': 'go',
            '.cs': 'csharp',
            '.sql': 'sql',
            '.html': 'html',
            '.htm': 'html',
            '.vue': 'vue',
        }

    def get_info(self) -> Dict[str, str]:
        return {
            "name": "Code Vulnerability Scanner",
            "version": "1.0.0",
            "description": "Static analysis security scanner for source code",
            "features": [
                "SQL Injection detection",
                "XSS (Cross-Site Scripting) detection",
                "Command Injection detection",
                "Path Traversal detection",
                "Sensitive Data Exposure detection",
                "Insecure Cryptography detection",
                "Security Misconfiguration detection"
            ],
            "supported_languages": list(set(self.supported_extensions.values())),
            "cwe_coverage": [
                "CWE-89: SQL Injection",
                "CWE-79: XSS",
                "CWE-78: OS Command Injection",
                "CWE-22: Path Traversal",
                "CWE-312: Cleartext Storage",
                "CWE-327: Broken Crypto",
                "CWE-502: Deserialization"
            ]
        }

    def run(self, path: str = None, action: str = "scan") -> Dict[str, Any]:
        """Execute code scanning"""
        self.start()

        if action == "scan" and path:
            result = self.scan_path(path)
        else:
            result = {"error": "Invalid action or missing path"}

        self.add_result(result)
        self.finish()
        return self.get_summary()

    def scan_path(self, path: str) -> Dict[str, Any]:
        """Scan file or directory for vulnerabilities"""
        path_obj = Path(path)

        if path_obj.is_file():
            return self.scan_file(str(path_obj))
        elif path_obj.is_dir():
            return self.scan_directory(str(path_obj))
        else:
            return {"error": f"Path not found: {path}"}

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, Any]:
        """Scan directory for vulnerabilities"""
        results = {
            "directory": directory,
            "files_scanned": 0,
            "vulnerabilities": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_type": {}
        }

        path = Path(directory)
        pattern = '**/*' if recursive else '*'

        for file_path in path.glob(pattern):
            if file_path.is_file() and file_path.suffix in self.supported_extensions:
                file_results = self.scan_file(str(file_path))

                if "vulnerabilities" in file_results:
                    results["files_scanned"] += 1
                    results["vulnerabilities"].extend(file_results["vulnerabilities"])

        # Calculate summary
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "INFO").lower()
            results["summary"][severity] = results["summary"].get(severity, 0) + 1

            vuln_type = vuln.get("type", "Unknown")
            results["by_type"][vuln_type] = results["by_type"].get(vuln_type, 0) + 1

        # Risk score
        results["risk_score"] = (
            results["summary"]["critical"] * 10 +
            results["summary"]["high"] * 5 +
            results["summary"]["medium"] * 2 +
            results["summary"]["low"] * 1
        )

        return results

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file for vulnerabilities"""
        results = {
            "file": file_path,
            "vulnerabilities": [],
            "language": None
        }

        ext = Path(file_path).suffix.lower()
        if ext not in self.supported_extensions:
            results["skipped"] = "Unsupported file type"
            return results

        results["language"] = self.supported_extensions[ext]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            results["error"] = str(e)
            return results

        # Run all pattern checks
        self._check_patterns(results, file_path, lines, self.SQL_PATTERNS,
                            "SQL Injection", Severity.CRITICAL, "CWE-89", "A03:2021")

        self._check_patterns(results, file_path, lines, self.XSS_PATTERNS,
                            "Cross-Site Scripting (XSS)", Severity.HIGH, "CWE-79", "A03:2021")

        self._check_patterns(results, file_path, lines, self.CMD_PATTERNS,
                            "Command Injection", Severity.CRITICAL, "CWE-78", "A03:2021")

        self._check_patterns(results, file_path, lines, self.PATH_PATTERNS,
                            "Path Traversal", Severity.HIGH, "CWE-22", "A01:2021")

        self._check_patterns(results, file_path, lines, self.SENSITIVE_PATTERNS,
                            "Sensitive Data Exposure", Severity.HIGH, "CWE-312", "A02:2021")

        self._check_patterns(results, file_path, lines, self.INSECURE_PATTERNS,
                            "Insecure Configuration", Severity.MEDIUM, "CWE-16", "A05:2021")

        self._check_patterns(results, file_path, lines, self.CRYPTO_PATTERNS,
                            "Weak Cryptography", Severity.MEDIUM, "CWE-327", "A02:2021")

        # Python-specific checks
        if results["language"] == "python":
            self._check_python_specific(results, file_path, content, lines)

        return results

    def _check_patterns(self, results: Dict, file_path: str, lines: List[str],
                       patterns: List[Tuple[str, str]], vuln_type: str,
                       severity: Severity, cwe_id: str, owasp: str):
        """Check content against patterns"""
        for line_num, line in enumerate(lines, 1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = {
                        "type": vuln_type,
                        "severity": severity.name,
                        "file": file_path,
                        "line": line_num,
                        "code": line.strip()[:100],
                        "description": description,
                        "cwe_id": cwe_id,
                        "owasp_category": owasp,
                        "recommendation": self._get_recommendation(vuln_type)
                    }
                    results["vulnerabilities"].append(vuln)

    def _check_python_specific(self, results: Dict, file_path: str,
                               content: str, lines: List[str]):
        """Python-specific security checks"""
        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                # Check for dangerous imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ['pickle', 'shelve', 'marshal']:
                            results["vulnerabilities"].append({
                                "type": "Insecure Deserialization",
                                "severity": "HIGH",
                                "file": file_path,
                                "line": node.lineno,
                                "code": f"import {alias.name}",
                                "description": f"Potentially unsafe {alias.name} module import",
                                "cwe_id": "CWE-502",
                                "owasp_category": "A08:2021",
                                "recommendation": "Avoid deserializing untrusted data"
                            })

                # Check for eval/exec with variables
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec']:
                            if node.args and not isinstance(node.args[0], ast.Constant):
                                results["vulnerabilities"].append({
                                    "type": "Code Injection",
                                    "severity": "CRITICAL",
                                    "file": file_path,
                                    "line": node.lineno,
                                    "code": lines[node.lineno - 1].strip()[:100],
                                    "description": f"{node.func.id}() with dynamic content",
                                    "cwe_id": "CWE-94",
                                    "owasp_category": "A03:2021",
                                    "recommendation": "Never use eval/exec with user input"
                                })

                # Check for assert statements (removed in optimized mode)
                if isinstance(node, ast.Assert):
                    results["vulnerabilities"].append({
                        "type": "Security Misconfiguration",
                        "severity": "LOW",
                        "file": file_path,
                        "line": node.lineno,
                        "code": lines[node.lineno - 1].strip()[:100],
                        "description": "Assert statement (disabled with -O flag)",
                        "cwe_id": "CWE-617",
                        "owasp_category": "A05:2021",
                        "recommendation": "Don't rely on assert for security checks"
                    })

        except SyntaxError:
            pass  # Not valid Python

    def _get_recommendation(self, vuln_type: str) -> str:
        """Get remediation recommendation for vulnerability type"""
        recommendations = {
            "SQL Injection": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            "Cross-Site Scripting (XSS)": "Encode output properly. Use Content Security Policy. Avoid innerHTML with user data.",
            "Command Injection": "Avoid shell=True. Use subprocess with argument lists. Validate and sanitize all input.",
            "Path Traversal": "Validate file paths. Use os.path.basename(). Implement allowlist for accessible files.",
            "Sensitive Data Exposure": "Use environment variables or secure vaults for secrets. Never hardcode credentials.",
            "Insecure Configuration": "Follow security best practices. Disable debug mode in production.",
            "Weak Cryptography": "Use strong algorithms (AES-256, RSA-2048+). Use cryptographically secure random."
        }
        return recommendations.get(vuln_type, "Review and remediate according to security best practices.")

    def generate_report(self, scan_results: Dict[str, Any], format: str = "text") -> str:
        """Generate vulnerability report"""
        if format == "json":
            import json
            return json.dumps(scan_results, indent=2)

        # Text report
        report = []
        report.append("=" * 60)
        report.append("       CODE VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        report.append("")

        if "directory" in scan_results:
            report.append(f"Scanned: {scan_results['directory']}")
        elif "file" in scan_results:
            report.append(f"Scanned: {scan_results['file']}")

        report.append(f"Files Analyzed: {scan_results.get('files_scanned', 1)}")
        report.append(f"Total Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}")
        report.append("")

        # Summary
        if "summary" in scan_results:
            report.append("SEVERITY BREAKDOWN:")
            report.append("-" * 30)
            for sev, count in scan_results["summary"].items():
                if count > 0:
                    report.append(f"  {sev.upper():12} : {count}")
            report.append("")

        # Findings
        report.append("VULNERABILITY FINDINGS:")
        report.append("-" * 60)

        for i, vuln in enumerate(scan_results.get("vulnerabilities", []), 1):
            report.append(f"\n[{i}] {vuln['type']}")
            report.append(f"    Severity: {vuln['severity']}")
            report.append(f"    Location: {vuln['file']}:{vuln['line']}")
            report.append(f"    Code: {vuln['code']}")
            report.append(f"    CWE: {vuln.get('cwe_id', 'N/A')}")
            report.append(f"    Recommendation: {vuln.get('recommendation', 'N/A')}")

        report.append("\n" + "=" * 60)
        report.append("                    END OF REPORT")
        report.append("=" * 60)

        return "\n".join(report)
