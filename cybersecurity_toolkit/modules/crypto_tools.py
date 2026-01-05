"""
Cryptographic Tools Module
- Symmetric encryption (AES, ChaCha20)
- Asymmetric encryption (RSA)
- Digital signatures
- Key generation
- Hash functions
- Encoding/Decoding utilities
- JWT analysis
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

import sys
sys.path.append('..')
from core.base import BaseModule


class CryptoToolsModule(BaseModule):
    """Comprehensive cryptographic operations toolkit"""

    def __init__(self):
        super().__init__("CryptoTools")

    def get_info(self) -> Dict[str, str]:
        return {
            "name": "Cryptographic Tools Module",
            "version": "1.0.0",
            "description": "Professional-grade cryptographic operations",
            "features": [
                "AES-256-GCM encryption/decryption",
                "ChaCha20-Poly1305 encryption",
                "RSA key pair generation",
                "Digital signatures (RSA, HMAC)",
                "Secure key derivation (PBKDF2, Scrypt)",
                "Hash functions (SHA-256, SHA-512, SHA-3)",
                "HMAC generation/verification",
                "Base64/Hex encoding",
                "JWT token analysis"
            ]
        }

    def run(self, action: str = "info") -> Dict[str, Any]:
        """Execute cryptographic operations"""
        self.start()
        result = self.get_info()
        self.add_result(result)
        self.finish()
        return self.get_summary()

    # ========== Symmetric Encryption ==========

    def generate_key(self, key_type: str = "aes256") -> Dict[str, str]:
        """Generate cryptographic key"""
        if key_type == "aes256":
            key = secrets.token_bytes(32)
            return {
                "type": "AES-256",
                "key_hex": key.hex(),
                "key_base64": base64.b64encode(key).decode(),
                "bits": 256
            }
        elif key_type == "aes128":
            key = secrets.token_bytes(16)
            return {
                "type": "AES-128",
                "key_hex": key.hex(),
                "key_base64": base64.b64encode(key).decode(),
                "bits": 128
            }
        elif key_type == "chacha20":
            key = secrets.token_bytes(32)
            return {
                "type": "ChaCha20",
                "key_hex": key.hex(),
                "key_base64": base64.b64encode(key).decode(),
                "bits": 256
            }
        elif key_type == "fernet":
            if CRYPTO_AVAILABLE:
                key = Fernet.generate_key()
                return {
                    "type": "Fernet",
                    "key": key.decode(),
                    "note": "URL-safe base64 encoded"
                }
        else:
            return {"error": f"Unknown key type: {key_type}"}

    def derive_key(self, password: str, salt: bytes = None,
                   algorithm: str = "pbkdf2", key_length: int = 32) -> Dict[str, Any]:
        """Derive encryption key from password"""
        if salt is None:
            salt = secrets.token_bytes(32)

        if not CRYPTO_AVAILABLE:
            # Fallback to hashlib
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000, key_length)
            return {
                "algorithm": "PBKDF2-SHA256",
                "key_hex": key.hex(),
                "key_base64": base64.b64encode(key).decode(),
                "salt_hex": salt.hex(),
                "salt_base64": base64.b64encode(salt).decode(),
                "iterations": 600000
            }

        if algorithm == "pbkdf2":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=600000,
            )
            key = kdf.derive(password.encode())
            return {
                "algorithm": "PBKDF2-SHA256",
                "key_hex": key.hex(),
                "key_base64": base64.b64encode(key).decode(),
                "salt_hex": salt.hex(),
                "salt_base64": base64.b64encode(salt).decode(),
                "iterations": 600000
            }

        elif algorithm == "scrypt":
            kdf = Scrypt(
                salt=salt,
                length=key_length,
                n=2**17,
                r=8,
                p=1,
            )
            key = kdf.derive(password.encode())
            return {
                "algorithm": "Scrypt",
                "key_hex": key.hex(),
                "key_base64": base64.b64encode(key).decode(),
                "salt_hex": salt.hex(),
                "salt_base64": base64.b64encode(salt).decode(),
                "parameters": {"n": 2**17, "r": 8, "p": 1}
            }

        return {"error": f"Unknown algorithm: {algorithm}"}

    def encrypt_aes_gcm(self, plaintext: Union[str, bytes], key: bytes) -> Dict[str, str]:
        """Encrypt using AES-256-GCM"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "algorithm": "AES-256-GCM",
            "nonce_hex": nonce.hex(),
            "nonce_base64": base64.b64encode(nonce).decode(),
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_base64": base64.b64encode(ciphertext).decode(),
            "combined_base64": base64.b64encode(nonce + ciphertext).decode()
        }

    def decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, nonce: bytes) -> Dict[str, Any]:
        """Decrypt AES-256-GCM ciphertext"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return {
                "success": True,
                "plaintext": plaintext.decode('utf-8'),
                "plaintext_hex": plaintext.hex()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def encrypt_chacha20(self, plaintext: Union[str, bytes], key: bytes) -> Dict[str, str]:
        """Encrypt using ChaCha20-Poly1305"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        nonce = secrets.token_bytes(12)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, None)

        return {
            "algorithm": "ChaCha20-Poly1305",
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "combined_base64": base64.b64encode(nonce + ciphertext).decode()
        }

    # ========== Asymmetric Encryption ==========

    def generate_rsa_keypair(self, key_size: int = 2048) -> Dict[str, str]:
        """Generate RSA key pair"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return {
            "algorithm": f"RSA-{key_size}",
            "private_key": private_pem,
            "public_key": public_pem,
            "key_size": key_size,
            "warning": "Store private key securely!"
        }

    def rsa_encrypt(self, plaintext: str, public_key_pem: str) -> Dict[str, str]:
        """Encrypt with RSA public key"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            ciphertext = public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return {
                "ciphertext_hex": ciphertext.hex(),
                "ciphertext_base64": base64.b64encode(ciphertext).decode()
            }
        except Exception as e:
            return {"error": str(e)}

    def rsa_decrypt(self, ciphertext: bytes, private_key_pem: str) -> Dict[str, Any]:
        """Decrypt with RSA private key"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )

            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return {"success": True, "plaintext": plaintext.decode()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ========== Digital Signatures ==========

    def sign_rsa(self, message: str, private_key_pem: str) -> Dict[str, str]:
        """Create RSA digital signature"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )

            signature = private_key.sign(
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return {
                "signature_hex": signature.hex(),
                "signature_base64": base64.b64encode(signature).decode(),
                "algorithm": "RSA-PSS-SHA256"
            }
        except Exception as e:
            return {"error": str(e)}

    def verify_rsa_signature(self, message: str, signature: bytes,
                            public_key_pem: str) -> Dict[str, bool]:
        """Verify RSA digital signature"""
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library required"}

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return {"valid": True, "message": "Signature is valid"}
        except Exception:
            return {"valid": False, "message": "Signature is invalid"}

    def generate_hmac(self, message: str, key: bytes,
                     algorithm: str = "sha256") -> Dict[str, str]:
        """Generate HMAC"""
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)

        mac = hmac.new(key, message.encode(), hash_func)

        return {
            "algorithm": f"HMAC-{algorithm.upper()}",
            "hmac_hex": mac.hexdigest(),
            "hmac_base64": base64.b64encode(mac.digest()).decode()
        }

    def verify_hmac(self, message: str, key: bytes, expected_hmac: str,
                   algorithm: str = "sha256") -> Dict[str, bool]:
        """Verify HMAC"""
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)
        mac = hmac.new(key, message.encode(), hash_func)

        try:
            expected_bytes = bytes.fromhex(expected_hmac)
        except ValueError:
            expected_bytes = base64.b64decode(expected_hmac)

        is_valid = hmac.compare_digest(mac.digest(), expected_bytes)

        return {
            "valid": is_valid,
            "message": "HMAC is valid" if is_valid else "HMAC is invalid"
        }

    # ========== Hashing ==========

    def hash_data(self, data: Union[str, bytes], algorithms: List[str] = None) -> Dict[str, str]:
        """Hash data with multiple algorithms"""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']

        if isinstance(data, str):
            data = data.encode('utf-8')

        results = {}
        for alg in algorithms:
            try:
                hash_func = getattr(hashlib, alg)()
                hash_func.update(data)
                results[alg] = hash_func.hexdigest()
            except AttributeError:
                results[alg] = "Algorithm not available"

        return results

    # ========== Encoding/Decoding ==========

    def encode_base64(self, data: Union[str, bytes]) -> Dict[str, str]:
        """Base64 encode data"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        return {
            "standard": base64.b64encode(data).decode(),
            "urlsafe": base64.urlsafe_b64encode(data).decode(),
            "original_length": len(data),
            "encoded_length": len(base64.b64encode(data))
        }

    def decode_base64(self, encoded: str) -> Dict[str, Any]:
        """Base64 decode data"""
        try:
            # Try standard base64
            decoded = base64.b64decode(encoded)
            try:
                text = decoded.decode('utf-8')
            except UnicodeDecodeError:
                text = None

            return {
                "success": True,
                "decoded_text": text,
                "decoded_hex": decoded.hex(),
                "length": len(decoded)
            }
        except Exception as e:
            # Try URL-safe base64
            try:
                decoded = base64.urlsafe_b64decode(encoded)
                return {
                    "success": True,
                    "decoded_text": decoded.decode('utf-8', errors='ignore'),
                    "decoded_hex": decoded.hex(),
                    "encoding": "urlsafe"
                }
            except:
                return {"success": False, "error": str(e)}

    def encode_hex(self, data: Union[str, bytes]) -> str:
        """Hex encode data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return data.hex()

    def decode_hex(self, hex_string: str) -> Dict[str, Any]:
        """Hex decode data"""
        try:
            decoded = bytes.fromhex(hex_string)
            return {
                "success": True,
                "decoded_text": decoded.decode('utf-8', errors='ignore'),
                "decoded_bytes": list(decoded)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ========== JWT Analysis ==========

    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token structure"""
        parts = token.split('.')

        if len(parts) != 3:
            return {"error": "Invalid JWT format - expected 3 parts"}

        result = {
            "valid_structure": True,
            "parts": {
                "header": None,
                "payload": None,
                "signature": parts[2][:20] + "..." if len(parts[2]) > 20 else parts[2]
            },
            "security_issues": []
        }

        # Decode header
        try:
            # Add padding if needed
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_b64)
            result["parts"]["header"] = json.loads(header_json)

            # Check for weak algorithm
            alg = result["parts"]["header"].get("alg", "")
            if alg == "none":
                result["security_issues"].append({
                    "severity": "CRITICAL",
                    "issue": "Algorithm set to 'none' - signature not verified"
                })
            elif alg in ["HS256", "HS384", "HS512"]:
                result["security_issues"].append({
                    "severity": "INFO",
                    "issue": f"Using symmetric algorithm ({alg}) - ensure secret is secure"
                })

        except Exception as e:
            result["parts"]["header_error"] = str(e)

        # Decode payload
        try:
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            result["parts"]["payload"] = json.loads(payload_json)

            # Check expiration
            exp = result["parts"]["payload"].get("exp")
            if exp:
                exp_time = datetime.fromtimestamp(exp)
                result["expiration"] = exp_time.isoformat()
                if exp_time < datetime.now():
                    result["security_issues"].append({
                        "severity": "HIGH",
                        "issue": "Token has expired"
                    })

            # Check issued at
            iat = result["parts"]["payload"].get("iat")
            if iat:
                result["issued_at"] = datetime.fromtimestamp(iat).isoformat()

        except Exception as e:
            result["parts"]["payload_error"] = str(e)

        return result

    def generate_secure_token(self, length: int = 32, format: str = "hex") -> str:
        """Generate cryptographically secure random token"""
        token_bytes = secrets.token_bytes(length)

        if format == "hex":
            return token_bytes.hex()
        elif format == "base64":
            return base64.b64encode(token_bytes).decode()
        elif format == "urlsafe":
            return base64.urlsafe_b64encode(token_bytes).decode().rstrip('=')
        else:
            return token_bytes.hex()
