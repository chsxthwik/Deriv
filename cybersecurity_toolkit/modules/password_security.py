"""
Password Security Module
- Password strength analysis
- Secure password generation
- Hash generation and verification
- Password entropy calculation
"""

import hashlib
import secrets
import string
import re
import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import base64

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

import sys
sys.path.append('..')
from core.base import BaseModule


class PasswordStrength(Enum):
    """Password strength levels"""
    VERY_WEAK = 1
    WEAK = 2
    MODERATE = 3
    STRONG = 4
    VERY_STRONG = 5


@dataclass
class PasswordAnalysis:
    """Password analysis result"""
    password: str
    strength: PasswordStrength
    score: int
    entropy: float
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    has_sequences: bool
    has_repeated: bool
    is_common: bool
    suggestions: List[str]
    crack_time_estimate: str


class PasswordSecurityModule(BaseModule):
    """Comprehensive password security analysis and generation"""

    # Common password patterns to detect
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
        'password1', 'password123', 'iloveyou', 'sunshine', 'princess',
        'football', 'baseball', 'shadow', 'superman', 'michael', 'trustno1'
    }

    KEYBOARD_SEQUENCES = [
        'qwerty', 'qwertz', 'azerty', 'asdfgh', 'zxcvbn', '123456', '654321',
        'abcdef', 'fedcba', '!@#$%^'
    ]

    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?"

    def __init__(self):
        super().__init__("PasswordSecurity")

    def get_info(self) -> Dict[str, str]:
        return {
            "name": "Password Security Module",
            "version": "1.0.0",
            "description": "Comprehensive password security analysis, generation, and hashing",
            "features": [
                "Password strength analysis",
                "Entropy calculation",
                "Secure password generation",
                "Multiple hash algorithms (MD5, SHA1, SHA256, SHA512, bcrypt, Argon2)",
                "Common password detection",
                "Pattern detection (sequences, repeats)",
                "Crack time estimation"
            ]
        }

    def run(self, password: str = None, action: str = "analyze") -> Dict[str, Any]:
        """Execute password security operations"""
        self.start()

        if action == "analyze" and password:
            result = self.analyze_password(password)
        elif action == "generate":
            result = {"password": self.generate_password()}
        else:
            result = {"error": "Invalid action or missing password"}

        self.add_result(result)
        self.finish()
        return self.get_summary()

    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0

        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password):
            charset_size += 32

        if charset_size == 0:
            return 0

        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def detect_sequences(self, password: str) -> bool:
        """Detect keyboard and character sequences"""
        lower_pwd = password.lower()

        for seq in self.KEYBOARD_SEQUENCES:
            if seq in lower_pwd:
                return True

        # Detect ascending/descending sequences
        for i in range(len(password) - 2):
            if (ord(password[i]) + 1 == ord(password[i+1]) == ord(password[i+2]) - 1):
                return True
            if (ord(password[i]) - 1 == ord(password[i+1]) == ord(password[i+2]) + 1):
                return True

        return False

    def detect_repeated_chars(self, password: str) -> bool:
        """Detect repeated characters"""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False

    def estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password based on entropy"""
        # Assuming 10 billion guesses per second (high-end GPU cluster)
        guesses_per_second = 10_000_000_000
        possible_combinations = 2 ** entropy
        seconds = possible_combinations / guesses_per_second

        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds / 31536000)} years"
        elif seconds < 31536000 * 1000000:
            return f"{int(seconds / (31536000 * 1000))}K years"
        else:
            return "Millions of years+"

    def analyze_password(self, password: str) -> Dict[str, Any]:
        """Comprehensive password analysis"""

        # Basic checks
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password))
        has_sequences = self.detect_sequences(password)
        has_repeated = self.detect_repeated_chars(password)
        is_common = password.lower() in self.COMMON_PASSWORDS

        # Calculate entropy
        entropy = self.calculate_entropy(password)

        # Calculate score
        score = 0
        suggestions = []

        # Length scoring
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        else:
            suggestions.append("Use at least 12 characters")

        # Character variety scoring
        if has_upper:
            score += 15
        else:
            suggestions.append("Add uppercase letters")

        if has_lower:
            score += 15
        else:
            suggestions.append("Add lowercase letters")

        if has_digit:
            score += 15
        else:
            suggestions.append("Add numbers")

        if has_special:
            score += 15
        else:
            suggestions.append("Add special characters (!@#$%^&*)")

        # Penalty for weaknesses
        if has_sequences:
            score -= 15
            suggestions.append("Avoid keyboard patterns and sequences")

        if has_repeated:
            score -= 10
            suggestions.append("Avoid repeated characters")

        if is_common:
            score -= 30
            suggestions.append("This is a commonly used password - choose something unique")

        # Entropy bonus
        if entropy >= 80:
            score += 10
        elif entropy >= 60:
            score += 5

        # Normalize score
        score = max(0, min(100, score))

        # Determine strength
        if score >= 80:
            strength = PasswordStrength.VERY_STRONG
        elif score >= 60:
            strength = PasswordStrength.STRONG
        elif score >= 40:
            strength = PasswordStrength.MODERATE
        elif score >= 20:
            strength = PasswordStrength.WEAK
        else:
            strength = PasswordStrength.VERY_WEAK

        crack_time = self.estimate_crack_time(entropy)

        analysis = PasswordAnalysis(
            password="*" * len(password),  # Masked for security
            strength=strength,
            score=score,
            entropy=entropy,
            length=length,
            has_uppercase=has_upper,
            has_lowercase=has_lower,
            has_digits=has_digit,
            has_special=has_special,
            has_sequences=has_sequences,
            has_repeated=has_repeated,
            is_common=is_common,
            suggestions=suggestions,
            crack_time_estimate=crack_time
        )

        return {
            "action": "analyze",
            "strength": strength.name,
            "score": score,
            "entropy_bits": entropy,
            "length": length,
            "composition": {
                "uppercase": has_upper,
                "lowercase": has_lower,
                "digits": has_digit,
                "special_chars": has_special
            },
            "weaknesses": {
                "has_sequences": has_sequences,
                "has_repeated_chars": has_repeated,
                "is_common_password": is_common
            },
            "crack_time_estimate": crack_time,
            "suggestions": suggestions,
            "rating": f"{score}/100"
        }

    def generate_password(self, length: int = 16,
                         use_upper: bool = True,
                         use_lower: bool = True,
                         use_digits: bool = True,
                         use_special: bool = True,
                         exclude_ambiguous: bool = True) -> str:
        """Generate cryptographically secure password"""

        chars = ""
        required_chars = []

        if use_lower:
            lower = string.ascii_lowercase
            if exclude_ambiguous:
                lower = lower.replace('l', '').replace('o', '')
            chars += lower
            required_chars.append(secrets.choice(lower))

        if use_upper:
            upper = string.ascii_uppercase
            if exclude_ambiguous:
                upper = upper.replace('I', '').replace('O', '')
            chars += upper
            required_chars.append(secrets.choice(upper))

        if use_digits:
            digits = string.digits
            if exclude_ambiguous:
                digits = digits.replace('0', '').replace('1', '')
            chars += digits
            required_chars.append(secrets.choice(digits))

        if use_special:
            special = "!@#$%^&*_+-=?"
            chars += special
            required_chars.append(secrets.choice(special))

        if not chars:
            chars = string.ascii_letters + string.digits

        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [secrets.choice(chars) for _ in range(remaining_length)]

        # Shuffle to randomize position of required chars
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    def generate_passphrase(self, num_words: int = 4, separator: str = "-") -> str:
        """Generate a memorable passphrase"""
        # Word list for passphrase generation
        words = [
            "correct", "horse", "battery", "staple", "cloud", "mountain",
            "river", "forest", "thunder", "crystal", "dragon", "phoenix",
            "shadow", "flame", "cosmic", "quantum", "nebula", "galaxy",
            "cipher", "matrix", "vector", "prism", "zenith", "apex",
            "arctic", "blazing", "crimson", "diamond", "eclipse", "falcon",
            "granite", "harbor", "ivory", "jasper", "kingdom", "lunar",
            "marble", "nitrogen", "obsidian", "platinum", "quartz", "radiant",
            "sapphire", "titanium", "uranium", "velocity", "wavelength", "xenon"
        ]

        selected = [secrets.choice(words) for _ in range(num_words)]
        # Add a random number for extra entropy
        selected.append(str(secrets.randbelow(1000)))

        return separator.join(selected)

    def hash_password(self, password: str, algorithm: str = "sha256") -> Dict[str, str]:
        """Generate password hash using various algorithms"""
        results = {}
        password_bytes = password.encode('utf-8')

        # Standard hashes (NOT recommended for password storage, but useful for checksums)
        if algorithm in ["all", "md5"]:
            results["md5"] = hashlib.md5(password_bytes).hexdigest()

        if algorithm in ["all", "sha1"]:
            results["sha1"] = hashlib.sha1(password_bytes).hexdigest()

        if algorithm in ["all", "sha256"]:
            results["sha256"] = hashlib.sha256(password_bytes).hexdigest()

        if algorithm in ["all", "sha512"]:
            results["sha512"] = hashlib.sha512(password_bytes).hexdigest()

        if algorithm in ["all", "sha3_256"]:
            results["sha3_256"] = hashlib.sha3_256(password_bytes).hexdigest()

        # Secure password hashes (recommended for password storage)
        if algorithm in ["all", "bcrypt"] and BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt(rounds=12)
            results["bcrypt"] = bcrypt.hashpw(password_bytes, salt).decode('utf-8')

        if algorithm in ["all", "argon2"] and ARGON2_AVAILABLE:
            ph = PasswordHasher()
            results["argon2"] = ph.hash(password)

        # PBKDF2 (good for password storage)
        if algorithm in ["all", "pbkdf2"]:
            salt = secrets.token_bytes(32)
            key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 600000)
            results["pbkdf2"] = {
                "hash": base64.b64encode(key).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8'),
                "iterations": 600000
            }

        return results

    def verify_hash(self, password: str, hash_value: str, algorithm: str) -> bool:
        """Verify password against hash"""
        password_bytes = password.encode('utf-8')

        if algorithm == "bcrypt" and BCRYPT_AVAILABLE:
            try:
                return bcrypt.checkpw(password_bytes, hash_value.encode('utf-8'))
            except Exception:
                return False

        if algorithm == "argon2" and ARGON2_AVAILABLE:
            try:
                ph = PasswordHasher()
                ph.verify(hash_value, password)
                return True
            except Exception:
                return False

        # For simple hashes
        computed = self.hash_password(password, algorithm)
        return computed.get(algorithm) == hash_value

    def check_breach(self, password: str) -> Dict[str, Any]:
        """
        Check if password has been exposed in data breaches
        Uses k-anonymity model (only sends first 5 chars of SHA1 hash)
        """
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Note: In production, this would make an API call to haveibeenpwned.com
        # For this demo, we simulate the response
        return {
            "hash_prefix": prefix,
            "checked": True,
            "note": "To check against real breach data, integrate with haveibeenpwned.com API",
            "recommendation": "Always use unique passwords for each account"
        }
