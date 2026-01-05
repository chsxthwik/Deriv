"""
File Security Module
- File encryption/decryption (AES-256-GCM)
- File integrity verification
- Secure file deletion
- File metadata analysis
- Steganography detection
"""

import os
import hashlib
import secrets
import json
import mimetypes
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, BinaryIO
from datetime import datetime
from dataclasses import dataclass
import base64
import struct

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

import sys
sys.path.append('..')
from core.base import BaseModule


@dataclass
class FileInfo:
    """File information container"""
    path: str
    name: str
    size: int
    extension: str
    mime_type: str
    created: datetime
    modified: datetime
    permissions: str
    is_hidden: bool
    is_encrypted: bool


class FileSecurityModule(BaseModule):
    """Comprehensive file security operations"""

    MAGIC_BYTES = {
        b'\x89PNG\r\n\x1a\n': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF87a': 'GIF Image',
        b'GIF89a': 'GIF Image',
        b'%PDF': 'PDF Document',
        b'PK\x03\x04': 'ZIP Archive',
        b'PK\x05\x06': 'ZIP Archive (empty)',
        b'\x1f\x8b\x08': 'GZIP Archive',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x7fELF': 'ELF Executable',
        b'MZ': 'Windows Executable',
        b'\xca\xfe\xba\xbe': 'Java Class File',
        b'SQLite format 3': 'SQLite Database',
    }

    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.jar', '.msi', '.scr', '.pif', '.com', '.hta'
    }

    # Encryption file header
    ENCRYPTED_HEADER = b'CYBERENC_V1'

    def __init__(self):
        super().__init__("FileSecurity")

    def get_info(self) -> Dict[str, str]:
        return {
            "name": "File Security Module",
            "version": "1.0.0",
            "description": "File encryption, integrity verification, and security analysis",
            "features": [
                "AES-256-GCM encryption/decryption",
                "File integrity checking (multiple hash algorithms)",
                "Secure file deletion (multiple overwrite passes)",
                "File metadata analysis",
                "Magic bytes detection",
                "Suspicious file detection",
                "Steganography detection"
            ]
        }

    def run(self, file_path: str = None, action: str = "analyze") -> Dict[str, Any]:
        """Execute file security operations"""
        self.start()

        if action == "analyze" and file_path:
            result = self.analyze_file(file_path)
        elif action == "hash" and file_path:
            result = self.calculate_hashes(file_path)
        else:
            result = {"error": "Invalid action or missing file path"}

        self.add_result(result)
        self.finish()
        return self.get_summary()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required for encryption")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_path: str, output_path: str, password: str) -> Dict[str, Any]:
        """Encrypt file using AES-256-GCM"""
        if not CRYPTO_AVAILABLE:
            return {"success": False, "error": "cryptography library not installed"}

        try:
            # Generate random salt and nonce
            salt = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)

            # Derive key from password
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)

            # Read input file
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            # Store original filename as associated data
            original_name = os.path.basename(input_path).encode()

            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, plaintext, original_name)

            # Write encrypted file with header
            with open(output_path, 'wb') as f:
                f.write(self.ENCRYPTED_HEADER)
                f.write(struct.pack('>I', len(original_name)))
                f.write(original_name)
                f.write(salt)
                f.write(nonce)
                f.write(ciphertext)

            # Calculate integrity hash
            output_hash = self.calculate_single_hash(output_path, 'sha256')

            return {
                "success": True,
                "input_file": input_path,
                "output_file": output_path,
                "input_size": len(plaintext),
                "output_size": os.path.getsize(output_path),
                "algorithm": "AES-256-GCM",
                "integrity_hash": output_hash
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> Dict[str, Any]:
        """Decrypt file encrypted with AES-256-GCM"""
        if not CRYPTO_AVAILABLE:
            return {"success": False, "error": "cryptography library not installed"}

        try:
            with open(input_path, 'rb') as f:
                # Verify header
                header = f.read(len(self.ENCRYPTED_HEADER))
                if header != self.ENCRYPTED_HEADER:
                    return {"success": False, "error": "Invalid encrypted file format"}

                # Read original filename length and name
                name_len = struct.unpack('>I', f.read(4))[0]
                original_name = f.read(name_len)

                # Read salt and nonce
                salt = f.read(32)
                nonce = f.read(12)

                # Read ciphertext
                ciphertext = f.read()

            # Derive key
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)

            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, original_name)

            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            return {
                "success": True,
                "input_file": input_path,
                "output_file": output_path,
                "original_name": original_name.decode(),
                "decrypted_size": len(plaintext)
            }

        except Exception as e:
            error_msg = str(e)
            if "authentication" in error_msg.lower() or "tag" in error_msg.lower():
                error_msg = "Decryption failed - incorrect password or corrupted file"
            return {"success": False, "error": error_msg}

    def calculate_single_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate single hash of a file"""
        hash_func = getattr(hashlib, algorithm)()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    def calculate_hashes(self, file_path: str) -> Dict[str, Any]:
        """Calculate multiple hashes for file integrity verification"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']
        hashes = {}

        # Read file once, calculate all hashes
        hash_objects = {alg: getattr(hashlib, alg)() for alg in algorithms}

        file_size = os.path.getsize(file_path)

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)

        for alg, hash_obj in hash_objects.items():
            hashes[alg] = hash_obj.hexdigest()

        return {
            "file": file_path,
            "size_bytes": file_size,
            "hashes": hashes,
            "verification_commands": {
                "linux_sha256": f"sha256sum \"{file_path}\"",
                "windows_sha256": f"certutil -hashfile \"{file_path}\" SHA256"
            }
        }

    def verify_integrity(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> Dict[str, Any]:
        """Verify file integrity against expected hash"""
        actual_hash = self.calculate_single_hash(file_path, algorithm)
        is_valid = actual_hash.lower() == expected_hash.lower()

        return {
            "file": file_path,
            "algorithm": algorithm,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "is_valid": is_valid,
            "status": "INTEGRITY_VERIFIED" if is_valid else "INTEGRITY_FAILED"
        }

    def secure_delete(self, file_path: str, passes: int = 3) -> Dict[str, Any]:
        """Securely delete file by overwriting with random data"""
        if not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            file_size = os.path.getsize(file_path)

            # Multiple overwrite passes
            for pass_num in range(passes):
                with open(file_path, 'wb') as f:
                    # Write random data
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(8192, remaining)
                        f.write(secrets.token_bytes(chunk_size))
                        remaining -= chunk_size
                    f.flush()
                    os.fsync(f.fileno())

            # Final pass with zeros
            with open(file_path, 'wb') as f:
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())

            # Delete the file
            os.remove(file_path)

            return {
                "success": True,
                "file": file_path,
                "size_deleted": file_size,
                "overwrite_passes": passes + 1,
                "method": "DoD 5220.22-M style secure deletion"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """Detect file type using magic bytes"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        with open(file_path, 'rb') as f:
            header = f.read(32)

        detected_type = "Unknown"
        for magic, file_type in self.MAGIC_BYTES.items():
            if header.startswith(magic):
                detected_type = file_type
                break

        extension = os.path.splitext(file_path)[1].lower()
        mime_type, _ = mimetypes.guess_type(file_path)

        # Check for extension mismatch (possible disguised file)
        is_suspicious = False
        warning = None

        if detected_type != "Unknown":
            expected_extensions = {
                'PNG Image': ['.png'],
                'JPEG Image': ['.jpg', '.jpeg'],
                'GIF Image': ['.gif'],
                'PDF Document': ['.pdf'],
                'ZIP Archive': ['.zip', '.docx', '.xlsx', '.pptx'],
                'Windows Executable': ['.exe', '.dll'],
            }

            expected = expected_extensions.get(detected_type, [])
            if expected and extension not in expected:
                is_suspicious = True
                warning = f"Extension mismatch: file appears to be {detected_type} but has {extension} extension"

        return {
            "file": file_path,
            "detected_type": detected_type,
            "extension": extension,
            "mime_type": mime_type,
            "magic_bytes": header[:16].hex(),
            "is_suspicious": is_suspicious,
            "warning": warning
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file security analysis"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        path = Path(file_path)
        stat = path.stat()

        # Basic info
        analysis = {
            "file": str(path.absolute()),
            "name": path.name,
            "size_bytes": stat.st_size,
            "size_human": self._human_readable_size(stat.st_size),
            "extension": path.suffix.lower(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "permissions": oct(stat.st_mode)[-3:],
            "is_hidden": path.name.startswith('.'),
        }

        # File type detection
        type_info = self.detect_file_type(file_path)
        analysis["type_detection"] = type_info

        # Hash
        analysis["sha256"] = self.calculate_single_hash(file_path, 'sha256')

        # Security checks
        security_issues = []

        if path.suffix.lower() in self.SUSPICIOUS_EXTENSIONS:
            security_issues.append({
                "severity": "HIGH",
                "issue": "Potentially dangerous file type",
                "details": f"Extension {path.suffix} is commonly used by malware"
            })

        if type_info.get("is_suspicious"):
            security_issues.append({
                "severity": "MEDIUM",
                "issue": "File type mismatch",
                "details": type_info.get("warning")
            })

        # Check if file is encrypted by our tool
        try:
            with open(file_path, 'rb') as f:
                header = f.read(len(self.ENCRYPTED_HEADER))
                if header == self.ENCRYPTED_HEADER:
                    analysis["is_encrypted"] = True
                    analysis["encryption"] = "CyberSec Toolkit AES-256-GCM"
        except:
            pass

        analysis["security_issues"] = security_issues
        analysis["risk_level"] = "HIGH" if security_issues else "LOW"

        return analysis

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, Any]:
        """Scan directory for security issues"""
        results = {
            "directory": directory,
            "total_files": 0,
            "total_size": 0,
            "suspicious_files": [],
            "executable_files": [],
            "hidden_files": [],
            "large_files": [],
            "by_extension": {}
        }

        path = Path(directory)
        pattern = '**/*' if recursive else '*'

        for file_path in path.glob(pattern):
            if file_path.is_file():
                results["total_files"] += 1
                size = file_path.stat().st_size
                results["total_size"] += size

                ext = file_path.suffix.lower()
                results["by_extension"][ext] = results["by_extension"].get(ext, 0) + 1

                if ext in self.SUSPICIOUS_EXTENSIONS:
                    results["suspicious_files"].append(str(file_path))

                if file_path.name.startswith('.'):
                    results["hidden_files"].append(str(file_path))

                if size > 100 * 1024 * 1024:  # > 100MB
                    results["large_files"].append({
                        "path": str(file_path),
                        "size": self._human_readable_size(size)
                    })

        results["total_size_human"] = self._human_readable_size(results["total_size"])

        return results

    def detect_steganography(self, image_path: str) -> Dict[str, Any]:
        """Basic steganography detection for images"""
        if not os.path.exists(image_path):
            return {"error": f"File not found: {image_path}"}

        indicators = []
        risk_score = 0

        with open(image_path, 'rb') as f:
            data = f.read()

        # Check for appended data after image end markers
        if data.startswith(b'\x89PNG'):
            iend_pos = data.find(b'IEND')
            if iend_pos != -1 and iend_pos + 12 < len(data):
                appended_size = len(data) - (iend_pos + 12)
                if appended_size > 0:
                    indicators.append(f"Data appended after PNG IEND marker ({appended_size} bytes)")
                    risk_score += 30

        elif data.startswith(b'\xff\xd8\xff'):
            eoi_pos = data.rfind(b'\xff\xd9')
            if eoi_pos != -1 and eoi_pos + 2 < len(data):
                appended_size = len(data) - (eoi_pos + 2)
                if appended_size > 0:
                    indicators.append(f"Data appended after JPEG EOI marker ({appended_size} bytes)")
                    risk_score += 30

        # Check for suspicious strings in binary data
        suspicious_strings = [b'PK\x03\x04', b'MZ', b'#!/', b'<?php']
        for sus in suspicious_strings:
            if sus in data[100:]:  # Skip header
                indicators.append(f"Suspicious byte sequence found: {sus[:10]}")
                risk_score += 20

        # Statistical analysis - check for unusual byte distribution
        byte_freq = {}
        for byte in data:
            byte_freq[byte] = byte_freq.get(byte, 0) + 1

        # Calculate entropy
        import math
        entropy = 0
        total = len(data)
        for count in byte_freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        if entropy > 7.9:  # Very high entropy might indicate hidden encrypted data
            indicators.append(f"Unusually high entropy ({entropy:.2f} bits/byte)")
            risk_score += 15

        return {
            "file": image_path,
            "steganography_indicators": indicators,
            "risk_score": min(100, risk_score),
            "entropy": round(entropy, 2),
            "conclusion": "Possible hidden data detected" if risk_score > 30 else "No obvious steganography detected"
        }

    def _human_readable_size(self, size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
