"""
Tests for Password Security Module
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.password_security import PasswordSecurityModule


def test_password_analysis():
    """Test password strength analysis"""
    module = PasswordSecurityModule()

    # Test weak password
    weak = module.analyze_password("123456")
    assert weak["strength"] in ["VERY_WEAK", "WEAK"]
    assert weak["weaknesses"]["is_common_password"] == True

    # Test strong password
    strong = module.analyze_password("K9#mPx$2vL@nQ5wZ")
    assert strong["score"] >= 60
    assert strong["composition"]["uppercase"] == True
    assert strong["composition"]["lowercase"] == True
    assert strong["composition"]["digits"] == True
    assert strong["composition"]["special_chars"] == True


def test_password_generation():
    """Test secure password generation"""
    module = PasswordSecurityModule()

    # Test basic generation
    password = module.generate_password(length=16)
    assert len(password) == 16

    # Test options
    password = module.generate_password(
        length=20,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_special=True
    )
    assert len(password) == 20

    # Verify entropy
    analysis = module.analyze_password(password)
    assert analysis["entropy_bits"] > 50


def test_passphrase_generation():
    """Test passphrase generation"""
    module = PasswordSecurityModule()

    passphrase = module.generate_passphrase(num_words=4, separator="-")
    words = passphrase.split("-")
    assert len(words) == 5  # 4 words + 1 number


def test_password_hashing():
    """Test password hashing"""
    module = PasswordSecurityModule()

    hashes = module.hash_password("testpassword", "all")

    assert "sha256" in hashes
    assert "sha512" in hashes
    assert len(hashes["sha256"]) == 64  # SHA256 produces 64 hex chars
    assert len(hashes["sha512"]) == 128  # SHA512 produces 128 hex chars


def test_entropy_calculation():
    """Test entropy calculation"""
    module = PasswordSecurityModule()

    # Simple password - low entropy
    low_entropy = module.calculate_entropy("aaaaaa")

    # Complex password - high entropy
    high_entropy = module.calculate_entropy("K9#mPx$2vL@nQ5wZ")

    assert high_entropy > low_entropy


if __name__ == "__main__":
    test_password_analysis()
    test_password_generation()
    test_passphrase_generation()
    test_password_hashing()
    test_entropy_calculation()
    print("All password security tests passed!")
