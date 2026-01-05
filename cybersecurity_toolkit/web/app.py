"""
CyberSecurity Toolkit - Web Dashboard
Flask-based web interface for security tools
"""

import os
import sys
import json
import secrets
from datetime import datetime
from functools import wraps

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, send_from_directory, session
from flask_cors import CORS

from modules.password_security import PasswordSecurityModule
from modules.file_security import FileSecurityModule
from modules.network_security import NetworkSecurityModule
from modules.code_scanner import CodeVulnerabilityScanner
from modules.crypto_tools import CryptoToolsModule
from modules.log_analyzer import LogAnalyzerModule
from core.config import Config
from core.logger import SecurityLogger

# Initialize Flask app
app = Flask(__name__,
           template_folder='../templates',
           static_folder='../static')

app.secret_key = secrets.token_hex(32)
CORS(app)

# Initialize modules
password_module = PasswordSecurityModule()
file_module = FileSecurityModule()
network_module = NetworkSecurityModule()
code_scanner = CodeVulnerabilityScanner()
crypto_module = CryptoToolsModule()
log_analyzer = LogAnalyzerModule()
logger = SecurityLogger("WebDashboard", "logs/web.log")


def rate_limit(f):
    """Simple rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production, implement proper rate limiting
        return f(*args, **kwargs)
    return decorated_function


# ========== Web Routes ==========

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/api/info')
def api_info():
    """API information endpoint"""
    return jsonify({
        "name": "CyberSecurity Toolkit API",
        "version": "1.0.0",
        "modules": [
            password_module.get_info(),
            file_module.get_info(),
            network_module.get_info(),
            code_scanner.get_info(),
            crypto_module.get_info(),
            log_analyzer.get_info()
        ]
    })


# ========== Password Security API ==========

@app.route('/api/password/analyze', methods=['POST'])
@rate_limit
def analyze_password():
    """Analyze password strength"""
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Password is required"}), 400

    result = password_module.analyze_password(password)
    logger.audit("password_analysis", resource="api")

    return jsonify(result)


@app.route('/api/password/generate', methods=['POST'])
@rate_limit
def generate_password():
    """Generate secure password"""
    data = request.get_json() or {}

    length = data.get('length', 16)
    use_upper = data.get('uppercase', True)
    use_lower = data.get('lowercase', True)
    use_digits = data.get('digits', True)
    use_special = data.get('special', True)

    password = password_module.generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_special=use_special
    )

    # Also analyze the generated password
    analysis = password_module.analyze_password(password)

    return jsonify({
        "password": password,
        "analysis": analysis
    })


@app.route('/api/password/passphrase', methods=['POST'])
@rate_limit
def generate_passphrase():
    """Generate memorable passphrase"""
    data = request.get_json() or {}

    num_words = data.get('words', 4)
    separator = data.get('separator', '-')

    passphrase = password_module.generate_passphrase(num_words, separator)
    analysis = password_module.analyze_password(passphrase)

    return jsonify({
        "passphrase": passphrase,
        "analysis": analysis
    })


@app.route('/api/password/hash', methods=['POST'])
@rate_limit
def hash_password():
    """Hash password with various algorithms"""
    data = request.get_json()
    password = data.get('password', '')
    algorithm = data.get('algorithm', 'all')

    if not password:
        return jsonify({"error": "Password is required"}), 400

    result = password_module.hash_password(password, algorithm)
    return jsonify(result)


# ========== Crypto Tools API ==========

@app.route('/api/crypto/generate-key', methods=['POST'])
@rate_limit
def generate_key():
    """Generate encryption key"""
    data = request.get_json() or {}
    key_type = data.get('type', 'aes256')

    result = crypto_module.generate_key(key_type)
    return jsonify(result)


@app.route('/api/crypto/derive-key', methods=['POST'])
@rate_limit
def derive_key():
    """Derive key from password"""
    data = request.get_json()
    password = data.get('password', '')
    algorithm = data.get('algorithm', 'pbkdf2')

    if not password:
        return jsonify({"error": "Password is required"}), 400

    result = crypto_module.derive_key(password, algorithm=algorithm)
    return jsonify(result)


@app.route('/api/crypto/hash', methods=['POST'])
@rate_limit
def hash_data():
    """Hash data with multiple algorithms"""
    data = request.get_json()
    text = data.get('data', '')
    algorithms = data.get('algorithms', None)

    if not text:
        return jsonify({"error": "Data is required"}), 400

    result = crypto_module.hash_data(text, algorithms)
    return jsonify(result)


@app.route('/api/crypto/encode', methods=['POST'])
@rate_limit
def encode_data():
    """Encode data (base64, hex)"""
    data = request.get_json()
    text = data.get('data', '')
    encoding = data.get('encoding', 'base64')

    if not text:
        return jsonify({"error": "Data is required"}), 400

    if encoding == 'base64':
        result = crypto_module.encode_base64(text)
    elif encoding == 'hex':
        result = {"hex": crypto_module.encode_hex(text)}
    else:
        result = {"error": "Unknown encoding"}

    return jsonify(result)


@app.route('/api/crypto/decode', methods=['POST'])
@rate_limit
def decode_data():
    """Decode data (base64, hex)"""
    data = request.get_json()
    encoded = data.get('data', '')
    encoding = data.get('encoding', 'base64')

    if not encoded:
        return jsonify({"error": "Data is required"}), 400

    if encoding == 'base64':
        result = crypto_module.decode_base64(encoded)
    elif encoding == 'hex':
        result = crypto_module.decode_hex(encoded)
    else:
        result = {"error": "Unknown encoding"}

    return jsonify(result)


@app.route('/api/crypto/jwt-analyze', methods=['POST'])
@rate_limit
def analyze_jwt():
    """Analyze JWT token"""
    data = request.get_json()
    token = data.get('token', '')

    if not token:
        return jsonify({"error": "Token is required"}), 400

    result = crypto_module.analyze_jwt(token)
    return jsonify(result)


@app.route('/api/crypto/generate-token', methods=['POST'])
@rate_limit
def generate_token():
    """Generate secure random token"""
    data = request.get_json() or {}
    length = data.get('length', 32)
    format_type = data.get('format', 'hex')

    token = crypto_module.generate_secure_token(length, format_type)
    return jsonify({"token": token, "length": length, "format": format_type})


# ========== Network Security API ==========

@app.route('/api/network/scan', methods=['POST'])
@rate_limit
def port_scan():
    """Scan ports on target"""
    data = request.get_json()
    target = data.get('target', '')
    ports = data.get('ports', None)

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # Validate target is localhost or private IP for safety
    # In production, implement proper authorization
    logger.audit("port_scan", resource=target)

    result = network_module.scan_common_ports(target, ports)
    return jsonify(result)


@app.route('/api/network/dns', methods=['POST'])
@rate_limit
def dns_lookup():
    """DNS lookup"""
    data = request.get_json()
    domain = data.get('domain', '')

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    result = network_module.dns_lookup(domain)
    return jsonify(result)


@app.route('/api/network/ssl', methods=['POST'])
@rate_limit
def ssl_analyze():
    """Analyze SSL/TLS certificate"""
    data = request.get_json()
    host = data.get('host', '')
    port = data.get('port', 443)

    if not host:
        return jsonify({"error": "Host is required"}), 400

    result = network_module.analyze_ssl(host, port)
    return jsonify(result)


@app.route('/api/network/headers', methods=['POST'])
@rate_limit
def http_headers():
    """Analyze HTTP security headers"""
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = network_module.analyze_http_headers(url)
    return jsonify(result)


# ========== Code Scanner API ==========

@app.route('/api/scan/code', methods=['POST'])
@rate_limit
def scan_code():
    """Scan code for vulnerabilities"""
    data = request.get_json()
    code = data.get('code', '')
    language = data.get('language', 'python')

    if not code:
        return jsonify({"error": "Code is required"}), 400

    # Create temporary file for scanning
    import tempfile
    ext_map = {
        'python': '.py',
        'javascript': '.js',
        'php': '.php',
        'java': '.java'
    }

    ext = ext_map.get(language, '.txt')

    with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        result = code_scanner.scan_file(temp_path)
    finally:
        os.unlink(temp_path)

    return jsonify(result)


# ========== File Security API ==========

@app.route('/api/file/hash', methods=['POST'])
@rate_limit
def file_hash():
    """Calculate file hashes"""
    if 'file' not in request.files:
        return jsonify({"error": "File is required"}), 400

    file = request.files['file']

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        file.save(f.name)
        temp_path = f.name

    try:
        result = file_module.calculate_hashes(temp_path)
        result['filename'] = file.filename
    finally:
        os.unlink(temp_path)

    return jsonify(result)


@app.route('/api/file/analyze', methods=['POST'])
@rate_limit
def file_analyze():
    """Analyze file security"""
    if 'file' not in request.files:
        return jsonify({"error": "File is required"}), 400

    file = request.files['file']

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        file.save(f.name)
        temp_path = f.name

    try:
        result = file_module.analyze_file(temp_path)
        result['original_filename'] = file.filename
    finally:
        os.unlink(temp_path)

    return jsonify(result)


# ========== Error Handlers ==========

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return jsonify({"error": "Internal server error"}), 500


# ========== Main ==========

def create_app():
    """Application factory"""
    return app


if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           CyberSecurity Toolkit - Web Dashboard           ║
    ║                      Version 1.0.0                        ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Starting web server on http://127.0.0.1:5000             ║
    ║  Press Ctrl+C to stop                                     ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    app.run(debug=False, host='127.0.0.1', port=5000)
