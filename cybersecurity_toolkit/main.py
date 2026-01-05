#!/usr/bin/env python3
"""
CyberSecurity Toolkit - Main CLI Application
A comprehensive security analysis and testing toolkit

Usage:
    python main.py [command] [options]

Commands:
    password    - Password security operations
    file        - File security operations
    network     - Network security operations
    scan        - Code vulnerability scanning
    crypto      - Cryptographic operations
    log         - Log analysis
    web         - Start web dashboard
    info        - Show toolkit information
"""

import sys
import os
import argparse
import json
from typing import Optional

# Add toolkit to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.logger import SecurityLogger
from modules.password_security import PasswordSecurityModule
from modules.file_security import FileSecurityModule
from modules.network_security import NetworkSecurityModule
from modules.code_scanner import CodeVulnerabilityScanner
from modules.crypto_tools import CryptoToolsModule
from modules.log_analyzer import LogAnalyzerModule


BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗         ║
║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝         ║
║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║              ║
║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║              ║
║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗         ║
║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝         ║
║                                                                              ║
║                    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗   ║
║                    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝   ║
║                       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║      ║
║                       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║      ║
║                       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║      ║
║                       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝      ║
║                                                                              ║
║                         Version 1.0.0 | Professional Edition                 ║
║                     For Authorized Security Testing Only                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


class CyberSecurityCLI:
    """Main CLI application for CyberSecurity Toolkit"""

    def __init__(self):
        self.config = Config()
        self.logger = SecurityLogger("CLI", "logs/cli.log")

        # Initialize modules
        self.password_module = PasswordSecurityModule()
        self.file_module = FileSecurityModule()
        self.network_module = NetworkSecurityModule()
        self.code_scanner = CodeVulnerabilityScanner()
        self.crypto_module = CryptoToolsModule()
        self.log_analyzer = LogAnalyzerModule()

    def run(self):
        """Main entry point"""
        parser = self._create_parser()
        args = parser.parse_args()

        if args.version:
            print("CyberSecurity Toolkit v1.0.0")
            return

        if not hasattr(args, 'command') or args.command is None:
            print(BANNER)
            parser.print_help()
            return

        # Route to appropriate command handler
        command_handlers = {
            'password': self._handle_password,
            'file': self._handle_file,
            'network': self._handle_network,
            'scan': self._handle_scan,
            'crypto': self._handle_crypto,
            'log': self._handle_log,
            'web': self._handle_web,
            'info': self._handle_info
        }

        handler = command_handlers.get(args.command)
        if handler:
            handler(args)
        else:
            parser.print_help()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='CyberSecurity Toolkit - Professional Security Analysis Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s password analyze "MyPassword123!"
  %(prog)s password generate --length 20
  %(prog)s file hash /path/to/file
  %(prog)s network scan localhost
  %(prog)s scan /path/to/code
  %(prog)s crypto encode --input "Hello" --type base64
  %(prog)s web
            """
        )

        parser.add_argument('-v', '--version', action='store_true', help='Show version')
        parser.add_argument('--json', action='store_true', help='Output in JSON format')

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Password subcommand
        pwd_parser = subparsers.add_parser('password', help='Password security operations')
        pwd_sub = pwd_parser.add_subparsers(dest='action')

        analyze = pwd_sub.add_parser('analyze', help='Analyze password strength')
        analyze.add_argument('password', help='Password to analyze')

        generate = pwd_sub.add_parser('generate', help='Generate secure password')
        generate.add_argument('-l', '--length', type=int, default=16, help='Password length')
        generate.add_argument('--no-upper', action='store_true', help='Exclude uppercase')
        generate.add_argument('--no-lower', action='store_true', help='Exclude lowercase')
        generate.add_argument('--no-digits', action='store_true', help='Exclude digits')
        generate.add_argument('--no-special', action='store_true', help='Exclude special chars')

        passphrase = pwd_sub.add_parser('passphrase', help='Generate passphrase')
        passphrase.add_argument('-w', '--words', type=int, default=4, help='Number of words')
        passphrase.add_argument('-s', '--separator', default='-', help='Word separator')

        hash_pwd = pwd_sub.add_parser('hash', help='Hash password')
        hash_pwd.add_argument('password', help='Password to hash')
        hash_pwd.add_argument('-a', '--algorithm', default='all', help='Hash algorithm')

        # File subcommand
        file_parser = subparsers.add_parser('file', help='File security operations')
        file_sub = file_parser.add_subparsers(dest='action')

        file_hash = file_sub.add_parser('hash', help='Calculate file hashes')
        file_hash.add_argument('path', help='File path')

        file_analyze = file_sub.add_parser('analyze', help='Analyze file security')
        file_analyze.add_argument('path', help='File path')

        file_encrypt = file_sub.add_parser('encrypt', help='Encrypt file')
        file_encrypt.add_argument('input', help='Input file')
        file_encrypt.add_argument('output', help='Output file')
        file_encrypt.add_argument('-p', '--password', required=True, help='Encryption password')

        file_decrypt = file_sub.add_parser('decrypt', help='Decrypt file')
        file_decrypt.add_argument('input', help='Input file')
        file_decrypt.add_argument('output', help='Output file')
        file_decrypt.add_argument('-p', '--password', required=True, help='Decryption password')

        # Network subcommand
        net_parser = subparsers.add_parser('network', help='Network security operations')
        net_sub = net_parser.add_subparsers(dest='action')

        net_scan = net_sub.add_parser('scan', help='Scan ports')
        net_scan.add_argument('target', help='Target host')
        net_scan.add_argument('-p', '--ports', help='Comma-separated ports')

        net_dns = net_sub.add_parser('dns', help='DNS lookup')
        net_dns.add_argument('domain', help='Domain name')

        net_ssl = net_sub.add_parser('ssl', help='SSL/TLS analysis')
        net_ssl.add_argument('host', help='Host to analyze')
        net_ssl.add_argument('-p', '--port', type=int, default=443, help='Port number')

        net_headers = net_sub.add_parser('headers', help='HTTP header analysis')
        net_headers.add_argument('url', help='URL to analyze')

        # Scan (code) subcommand
        scan_parser = subparsers.add_parser('scan', help='Scan code for vulnerabilities')
        scan_parser.add_argument('path', help='File or directory path')
        scan_parser.add_argument('-r', '--recursive', action='store_true', help='Recursive scan')
        scan_parser.add_argument('-o', '--output', help='Output file for report')

        # Crypto subcommand
        crypto_parser = subparsers.add_parser('crypto', help='Cryptographic operations')
        crypto_sub = crypto_parser.add_subparsers(dest='action')

        crypto_keygen = crypto_sub.add_parser('keygen', help='Generate encryption key')
        crypto_keygen.add_argument('-t', '--type', default='aes256', choices=['aes256', 'aes128', 'chacha20'])

        crypto_hash = crypto_sub.add_parser('hash', help='Hash data')
        crypto_hash.add_argument('data', help='Data to hash')

        crypto_encode = crypto_sub.add_parser('encode', help='Encode data')
        crypto_encode.add_argument('data', help='Data to encode')
        crypto_encode.add_argument('-t', '--type', default='base64', choices=['base64', 'hex'])

        crypto_decode = crypto_sub.add_parser('decode', help='Decode data')
        crypto_decode.add_argument('data', help='Data to decode')
        crypto_decode.add_argument('-t', '--type', default='base64', choices=['base64', 'hex'])

        crypto_jwt = crypto_sub.add_parser('jwt', help='Analyze JWT token')
        crypto_jwt.add_argument('token', help='JWT token')

        # Log subcommand
        log_parser = subparsers.add_parser('log', help='Log analysis')
        log_parser.add_argument('path', help='Log file path')
        log_parser.add_argument('-o', '--output', help='Output report file')

        # Web subcommand
        web_parser = subparsers.add_parser('web', help='Start web dashboard')
        web_parser.add_argument('-p', '--port', type=int, default=5000, help='Port number')
        web_parser.add_argument('--host', default='127.0.0.1', help='Host address')

        # Info subcommand
        info_parser = subparsers.add_parser('info', help='Show toolkit information')

        return parser

    def _output(self, data: dict, as_json: bool = False):
        """Output result"""
        if as_json:
            print(json.dumps(data, indent=2, default=str))
        else:
            self._pretty_print(data)

    def _pretty_print(self, data: dict, indent: int = 0):
        """Pretty print dictionary"""
        for key, value in data.items():
            prefix = "  " * indent
            if isinstance(value, dict):
                print(f"{prefix}{key}:")
                self._pretty_print(value, indent + 1)
            elif isinstance(value, list):
                print(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        self._pretty_print(item, indent + 1)
                        print()
                    else:
                        print(f"{prefix}  - {item}")
            else:
                print(f"{prefix}{key}: {value}")

    def _handle_password(self, args):
        """Handle password commands"""
        as_json = getattr(args, 'json', False)

        if args.action == 'analyze':
            result = self.password_module.analyze_password(args.password)
            self._output(result, as_json)

        elif args.action == 'generate':
            password = self.password_module.generate_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_lower=not args.no_lower,
                use_digits=not args.no_digits,
                use_special=not args.no_special
            )
            analysis = self.password_module.analyze_password(password)
            self._output({"password": password, "analysis": analysis}, as_json)

        elif args.action == 'passphrase':
            passphrase = self.password_module.generate_passphrase(args.words, args.separator)
            analysis = self.password_module.analyze_password(passphrase)
            self._output({"passphrase": passphrase, "analysis": analysis}, as_json)

        elif args.action == 'hash':
            result = self.password_module.hash_password(args.password, args.algorithm)
            self._output(result, as_json)

    def _handle_file(self, args):
        """Handle file commands"""
        as_json = getattr(args, 'json', False)

        if args.action == 'hash':
            result = self.file_module.calculate_hashes(args.path)
            self._output(result, as_json)

        elif args.action == 'analyze':
            result = self.file_module.analyze_file(args.path)
            self._output(result, as_json)

        elif args.action == 'encrypt':
            result = self.file_module.encrypt_file(args.input, args.output, args.password)
            self._output(result, as_json)

        elif args.action == 'decrypt':
            result = self.file_module.decrypt_file(args.input, args.output, args.password)
            self._output(result, as_json)

    def _handle_network(self, args):
        """Handle network commands"""
        as_json = getattr(args, 'json', False)

        print("\n[!] DISCLAIMER: Only scan systems you own or have explicit authorization to test.\n")

        if args.action == 'scan':
            ports = None
            if args.ports:
                ports = [int(p.strip()) for p in args.ports.split(',')]
            result = self.network_module.scan_common_ports(args.target, ports)
            self._output(result, as_json)

        elif args.action == 'dns':
            result = self.network_module.dns_lookup(args.domain)
            self._output(result, as_json)

        elif args.action == 'ssl':
            result = self.network_module.analyze_ssl(args.host, args.port)
            self._output(result, as_json)

        elif args.action == 'headers':
            result = self.network_module.analyze_http_headers(args.url)
            self._output(result, as_json)

    def _handle_scan(self, args):
        """Handle code scanning"""
        as_json = getattr(args, 'json', False)

        print(f"\n[*] Scanning: {args.path}")
        result = self.code_scanner.scan_path(args.path)

        if args.output:
            report = self.code_scanner.generate_report(result)
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to: {args.output}")
        else:
            if as_json:
                print(json.dumps(result, indent=2))
            else:
                print(self.code_scanner.generate_report(result))

    def _handle_crypto(self, args):
        """Handle crypto commands"""
        as_json = getattr(args, 'json', False)

        if args.action == 'keygen':
            result = self.crypto_module.generate_key(args.type)
            self._output(result, as_json)

        elif args.action == 'hash':
            result = self.crypto_module.hash_data(args.data)
            self._output(result, as_json)

        elif args.action == 'encode':
            if args.type == 'base64':
                result = self.crypto_module.encode_base64(args.data)
            else:
                result = {"hex": self.crypto_module.encode_hex(args.data)}
            self._output(result, as_json)

        elif args.action == 'decode':
            if args.type == 'base64':
                result = self.crypto_module.decode_base64(args.data)
            else:
                result = self.crypto_module.decode_hex(args.data)
            self._output(result, as_json)

        elif args.action == 'jwt':
            result = self.crypto_module.analyze_jwt(args.token)
            self._output(result, as_json)

    def _handle_log(self, args):
        """Handle log analysis"""
        as_json = getattr(args, 'json', False)

        print(f"\n[*] Analyzing: {args.path}")
        result = self.log_analyzer.analyze_log_file(args.path)

        if args.output:
            report = self.log_analyzer.generate_report(result)
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to: {args.output}")
        else:
            if as_json:
                print(json.dumps(result, indent=2, default=str))
            else:
                print(self.log_analyzer.generate_report(result))

    def _handle_web(self, args):
        """Start web dashboard"""
        print(BANNER)
        print(f"\n[*] Starting web dashboard on http://{args.host}:{args.port}")
        print("[*] Press Ctrl+C to stop\n")

        from web.app import app
        app.run(host=args.host, port=args.port, debug=False)

    def _handle_info(self, args):
        """Show toolkit information"""
        print(BANNER)

        modules = [
            self.password_module,
            self.file_module,
            self.network_module,
            self.code_scanner,
            self.crypto_module,
            self.log_analyzer
        ]

        print("\n[+] Available Modules:\n")
        for module in modules:
            info = module.get_info()
            print(f"  {info['name']}")
            print(f"    Version: {info['version']}")
            print(f"    {info['description']}")
            print()


def main():
    """Main entry point"""
    # Ensure logs directory exists
    os.makedirs('logs', exist_ok=True)

    cli = CyberSecurityCLI()
    cli.run()


if __name__ == '__main__':
    main()
