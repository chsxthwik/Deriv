# CyberSecurity Toolkit v1.0.0

A comprehensive, professional-grade cybersecurity toolkit for security analysis, vulnerability scanning, and cryptographic operations.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗         ║
║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝         ║
║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║              ║
║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║              ║
║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗         ║
║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝         ║
║                                                                              ║
║                         SECURITY TOOLKIT                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Features

### 1. Password Security Module
- **Password Strength Analysis**: Comprehensive analysis with entropy calculation
- **Secure Password Generation**: Cryptographically secure random passwords
- **Passphrase Generation**: Memorable multi-word passphrases
- **Hash Generation**: MD5, SHA1, SHA256, SHA512, SHA3, bcrypt, Argon2, PBKDF2
- **Crack Time Estimation**: Estimates time to crack based on entropy

### 2. File Security Module
- **AES-256-GCM Encryption/Decryption**: Military-grade file encryption
- **File Integrity Verification**: Multiple hash algorithm support
- **Secure File Deletion**: Multi-pass overwrite (DoD 5220.22-M style)
- **File Type Detection**: Magic bytes analysis
- **Steganography Detection**: Detect hidden data in images
- **Metadata Analysis**: Comprehensive file information

### 3. Network Security Module
- **Port Scanning**: TCP connect scan with service detection
- **DNS Analysis**: Complete DNS record lookup with security analysis
- **SSL/TLS Certificate Analysis**: Certificate validation and security grading
- **HTTP Security Header Analysis**: Check for missing security headers
- **IP Reputation Checking**: Blacklist verification

### 4. Code Vulnerability Scanner
- **SQL Injection Detection** (CWE-89)
- **XSS Detection** (CWE-79)
- **Command Injection Detection** (CWE-78)
- **Path Traversal Detection** (CWE-22)
- **Sensitive Data Exposure** (CWE-312)
- **Weak Cryptography Detection** (CWE-327)
- **Insecure Deserialization** (CWE-502)
- **Multi-language Support**: Python, JavaScript, PHP, Java, Go, Ruby

### 5. Cryptographic Tools Module
- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA key generation and encryption
- **Digital Signatures**: RSA-PSS, HMAC
- **Key Derivation**: PBKDF2, Scrypt
- **Encoding/Decoding**: Base64, Hex
- **JWT Analysis**: Token structure and security analysis
- **Secure Token Generation**: Cryptographically secure random tokens

### 6. Log Analyzer Module
- **Multi-format Parsing**: Syslog, Apache, Nginx, JSON
- **Attack Detection**: SQL injection, XSS, command injection, brute force
- **Failed Login Analysis**: Track suspicious authentication attempts
- **Anomaly Detection**: Identify unusual patterns
- **IP Reputation Analysis**: Track malicious IP behavior
- **Security Recommendations**: Actionable remediation guidance

### 7. Web Dashboard
- Modern, responsive web interface
- Real-time security analysis
- Interactive tools for all modules
- Dark theme optimized for security professionals

## Installation

```bash
# Clone the repository
cd cybersecurity_toolkit

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command Line Interface

```bash
# Show help
python main.py --help

# Password operations
python main.py password analyze "MyPassword123!"
python main.py password generate --length 20
python main.py password passphrase --words 4
python main.py password hash "MyPassword" --algorithm sha256

# File operations
python main.py file hash /path/to/file
python main.py file analyze /path/to/file
python main.py file encrypt input.txt output.enc -p "password"
python main.py file decrypt output.enc decrypted.txt -p "password"

# Network operations (authorized testing only!)
python main.py network scan localhost
python main.py network dns example.com
python main.py network ssl example.com
python main.py network headers https://example.com

# Code scanning
python main.py scan /path/to/code
python main.py scan /path/to/project -r -o report.txt

# Cryptographic operations
python main.py crypto keygen --type aes256
python main.py crypto hash "Hello World"
python main.py crypto encode "Hello" --type base64
python main.py crypto decode "SGVsbG8=" --type base64
python main.py crypto jwt "eyJhbGciOiJIUzI1NiIs..."

# Log analysis
python main.py log /var/log/auth.log
python main.py log access.log -o security_report.txt

# Start web dashboard
python main.py web
python main.py web --port 8080 --host 0.0.0.0
```

### Web Dashboard

```bash
# Start the web server
python main.py web

# Access at http://127.0.0.1:5000
```

### Python API

```python
from modules.password_security import PasswordSecurityModule
from modules.file_security import FileSecurityModule
from modules.network_security import NetworkSecurityModule
from modules.code_scanner import CodeVulnerabilityScanner
from modules.crypto_tools import CryptoToolsModule
from modules.log_analyzer import LogAnalyzerModule

# Password Security
pwd = PasswordSecurityModule()
analysis = pwd.analyze_password("MySecurePassword123!")
print(f"Strength: {analysis['strength']}, Score: {analysis['score']}/100")

password = pwd.generate_password(length=20)
print(f"Generated: {password}")

hashes = pwd.hash_password("password", "all")
print(f"SHA256: {hashes['sha256']}")

# File Security
file_sec = FileSecurityModule()
hashes = file_sec.calculate_hashes("/path/to/file")
analysis = file_sec.analyze_file("/path/to/file")
file_sec.encrypt_file("input.txt", "output.enc", "password")
file_sec.decrypt_file("output.enc", "decrypted.txt", "password")

# Network Security
net = NetworkSecurityModule()
scan = net.scan_common_ports("localhost")
dns = net.dns_lookup("example.com")
ssl = net.analyze_ssl("example.com")
headers = net.analyze_http_headers("https://example.com")

# Code Scanner
scanner = CodeVulnerabilityScanner()
results = scanner.scan_path("/path/to/code")
report = scanner.generate_report(results)

# Crypto Tools
crypto = CryptoToolsModule()
key = crypto.generate_key("aes256")
hashes = crypto.hash_data("Hello World")
encoded = crypto.encode_base64("Hello")
jwt_info = crypto.analyze_jwt("eyJhbGciOiJIUzI1NiIs...")

# Log Analyzer
analyzer = LogAnalyzerModule()
results = analyzer.analyze_log_file("/var/log/auth.log")
report = analyzer.generate_report(results)
```

## Project Structure

```
cybersecurity_toolkit/
├── core/
│   ├── __init__.py
│   ├── base.py          # Base module class
│   ├── config.py        # Configuration management
│   └── logger.py        # Security logging
├── modules/
│   ├── __init__.py
│   ├── password_security.py   # Password analysis & generation
│   ├── file_security.py       # File encryption & analysis
│   ├── network_security.py    # Network scanning & analysis
│   ├── code_scanner.py        # Vulnerability scanning
│   ├── crypto_tools.py        # Cryptographic operations
│   └── log_analyzer.py        # Log analysis & threat detection
├── web/
│   └── app.py           # Flask web application
├── templates/
│   └── index.html       # Web dashboard template
├── static/
│   ├── css/
│   └── js/
├── utils/
│   ├── __init__.py
│   └── helpers.py       # Utility functions
├── tests/
├── logs/
├── main.py              # CLI entry point
├── requirements.txt
└── README.md
```

## Security Considerations

### Disclaimer
This toolkit is designed for **authorized security testing only**. Users must:
- Only test systems they own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Use responsibly and ethically

### Best Practices
- Never store generated keys/passwords in logs
- Use environment variables for sensitive configuration
- Run network scans only on authorized targets
- Keep the toolkit updated

## CWE Coverage

| CWE ID | Vulnerability Type | Module |
|--------|-------------------|--------|
| CWE-89 | SQL Injection | Code Scanner |
| CWE-79 | Cross-Site Scripting (XSS) | Code Scanner |
| CWE-78 | OS Command Injection | Code Scanner |
| CWE-22 | Path Traversal | Code Scanner |
| CWE-312 | Cleartext Storage of Sensitive Info | Code Scanner |
| CWE-327 | Use of Broken Crypto Algorithm | Code Scanner |
| CWE-502 | Deserialization of Untrusted Data | Code Scanner |
| CWE-16 | Configuration | Code Scanner |

## OWASP Top 10 Coverage

- A01:2021 – Broken Access Control
- A02:2021 – Cryptographic Failures
- A03:2021 – Injection
- A05:2021 – Security Misconfiguration
- A08:2021 – Software and Data Integrity Failures

## Requirements

- Python 3.8+
- See requirements.txt for dependencies

## License

This project is for educational and authorized security testing purposes only.

## Contributing

Contributions are welcome! Please ensure all code follows security best practices.

## Support

For issues and feature requests, please open an issue on the repository.

---

**Remember: With great power comes great responsibility. Use this toolkit ethically and legally.**
