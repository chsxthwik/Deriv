"""
Tests for Cryptographic Tools Module
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crypto_tools import CryptoToolsModule


def test_key_generation():
    """Test encryption key generation"""
    module = CryptoToolsModule()

    # Test AES-256 key
    key = module.generate_key("aes256")
    assert key["type"] == "AES-256"
    assert key["bits"] == 256
    assert len(key["key_hex"]) == 64  # 32 bytes = 64 hex chars


def test_key_derivation():
    """Test key derivation from password"""
    module = CryptoToolsModule()

    result = module.derive_key("testpassword")
    assert "key_hex" in result
    assert "salt_hex" in result
    assert result["iterations"] == 600000


def test_hashing():
    """Test multi-algorithm hashing"""
    module = CryptoToolsModule()

    hashes = module.hash_data("Hello World")

    assert "sha256" in hashes
    assert "sha512" in hashes
    assert "md5" in hashes


def test_base64_encoding():
    """Test Base64 encoding/decoding"""
    module = CryptoToolsModule()

    original = "Hello, World!"

    encoded = module.encode_base64(original)
    assert "standard" in encoded

    decoded = module.decode_base64(encoded["standard"])
    assert decoded["success"] == True
    assert decoded["decoded_text"] == original


def test_hex_encoding():
    """Test hex encoding/decoding"""
    module = CryptoToolsModule()

    original = "Hello"

    encoded = module.encode_hex(original)
    assert encoded == "48656c6c6f"

    decoded = module.decode_hex(encoded)
    assert decoded["success"] == True
    assert decoded["decoded_text"] == original


def test_jwt_analysis():
    """Test JWT token analysis"""
    module = CryptoToolsModule()

    # Sample JWT token
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    result = module.analyze_jwt(token)

    assert result["valid_structure"] == True
    assert result["parts"]["header"]["alg"] == "HS256"
    assert result["parts"]["payload"]["name"] == "John Doe"


def test_secure_token_generation():
    """Test secure token generation"""
    module = CryptoToolsModule()

    # Hex token
    hex_token = module.generate_secure_token(32, "hex")
    assert len(hex_token) == 64

    # Base64 token
    b64_token = module.generate_secure_token(32, "base64")
    assert len(b64_token) > 0


def test_hmac_generation():
    """Test HMAC generation"""
    module = CryptoToolsModule()

    message = "Hello World"
    key = b"secret_key"

    hmac_result = module.generate_hmac(message, key, "sha256")

    assert "hmac_hex" in hmac_result
    assert "hmac_base64" in hmac_result


if __name__ == "__main__":
    test_key_generation()
    test_key_derivation()
    test_hashing()
    test_base64_encoding()
    test_hex_encoding()
    test_jwt_analysis()
    test_secure_token_generation()
    test_hmac_generation()
    print("All crypto tools tests passed!")
