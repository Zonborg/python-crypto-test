"""
Comprehensive demonstration of Flask's cryptographic and security features.
Covers session management, CSRF protection, secure cookies,
password utilities, and security-related extensions.
"""

import os
import hmac
import hashlib
from flask import Flask, session, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, URLSafeSerializer


def demo_secret_key_generation():
    """Flask secret key generation."""
    print("\n" + "=" * 60)
    print("FLASK SECRET KEY GENERATION")
    print("=" * 60)

    # Method 1: os.urandom
    secret_key_bytes = os.urandom(32)
    print(f"os.urandom(32): {secret_key_bytes.hex()}")

    # Method 2: secrets module
    import secrets
    secret_key_hex = secrets.token_hex(32)
    print(f"secrets.token_hex(32): {secret_key_hex}")

    secret_key_url = secrets.token_urlsafe(32)
    print(f"secrets.token_urlsafe(32): {secret_key_url}")

    print("\nRecommended minimum: 32 bytes of random data")
    print("Store in environment variable, not in code!")


def demo_session_signing():
    """Flask session cookie signing."""
    print("\n" + "=" * 60)
    print("FLASK SESSION COOKIE SIGNING")
    print("=" * 60)

    app = Flask(__name__)
    app.secret_key = os.urandom(32)

    with app.test_request_context():
        # Set session data
        session['user_id'] = 12345
        session['username'] = 'demo_user'
        session['role'] = 'admin'

        print(f"Session data: {dict(session)}")
        print(f"Session signed with: HMAC-SHA1 (itsdangerous)")
        print(f"Cookie name: 'session' (default)")
        print(f"Session type: SecureCookieSession")

    # Show session configuration
    print(f"\nSession config:")
    print(f"  SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE', False)}")
    print(f"  SESSION_COOKIE_HTTPONLY: {app.config.get('SESSION_COOKIE_HTTPONLY', True)}")
    print(f"  SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')}")
    print(f"  PERMANENT_SESSION_LIFETIME: {app.config.get('PERMANENT_SESSION_LIFETIME')}")


def demo_secure_cookie_config():
    """Secure cookie configuration."""
    print("\n" + "=" * 60)
    print("SECURE COOKIE CONFIGURATION")
    print("=" * 60)

    app = Flask(__name__)
    app.secret_key = os.urandom(32)

    # Secure configuration
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_NAME='__Host-session',
        PERMANENT_SESSION_LIFETIME=3600,
        SESSION_COOKIE_DOMAIN=None,  # Strict same-origin
    )

    print("Secure cookie settings:")
    secure_settings = {
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Strict',
        'SESSION_COOKIE_NAME': '__Host-session',
        'PERMANENT_SESSION_LIFETIME': 3600,
    }
    for key, value in secure_settings.items():
        print(f"  {key}: {value}")

    # Response with secure headers
    with app.test_request_context():
        response = make_response("OK")
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        response.headers['Content-Security-Policy'] = "default-src 'self'"

        print("\nSecurity response headers:")
        for key, value in response.headers:
            if key.startswith(('X-', 'Strict', 'Content-Security')):
                print(f"  {key}: {value}")


def demo_password_hashing():
    """Flask/Werkzeug password hashing."""
    print("\n" + "=" * 60)
    print("FLASK PASSWORD HASHING")
    print("=" * 60)

    passwords = [
        "simple-password",
        "C0mpl3x!P@55w0rd",
        "unicode-пароль",
    ]

    for password in passwords:
        hashed = generate_password_hash(password)
        verified = check_password_hash(hashed, password)
        wrong = check_password_hash(hashed, "wrong")
        print(f"  '{password[:20]}': hash={hashed[:40]}...")
        print(f"    Verify correct: {verified}, Verify wrong: {wrong}")


def demo_token_generation():
    """Secure token generation for various purposes."""
    print("\n" + "=" * 60)
    print("SECURE TOKEN GENERATION")
    print("=" * 60)

    secret_key = os.urandom(32)

    # URL-safe timed serializer (for email confirmation, password reset)
    timed_serializer = URLSafeTimedSerializer(secret_key)

    # Generate email confirmation token
    email = "user@example.com"
    confirm_token = timed_serializer.dumps(email, salt='email-confirm')
    print(f"Email confirm token: {confirm_token}")

    # Verify token (within time limit)
    confirmed_email = timed_serializer.loads(confirm_token, salt='email-confirm', max_age=3600)
    print(f"Confirmed email: {confirmed_email}")

    # Password reset token
    reset_data = {"user_id": 42, "action": "reset"}
    reset_token = timed_serializer.dumps(reset_data, salt='password-reset')
    print(f"Reset token: {reset_token}")

    # API key generation
    serializer = URLSafeSerializer(secret_key)
    api_key = serializer.dumps({"app_id": "myapp", "scope": "read"}, salt='api-key')
    print(f"API key: {api_key}")


def demo_csrf_protection():
    """CSRF token generation and validation."""
    print("\n" + "=" * 60)
    print("CSRF PROTECTION")
    print("=" * 60)

    app = Flask(__name__)
    app.secret_key = os.urandom(32)

    with app.test_request_context():
        # Generate CSRF token
        session['csrf_token'] = hashlib.sha256(os.urandom(32)).hexdigest()
        csrf_token = session['csrf_token']
        print(f"CSRF token: {csrf_token}")

        # Validate (constant-time comparison)
        submitted_token = csrf_token  # Simulating form submission
        is_valid = hmac.compare_digest(csrf_token, submitted_token)
        print(f"Token valid: {is_valid}")

        # Show HTML form pattern
        print(f"\nHTML form pattern:")
        print(f'  <input type="hidden" name="csrf_token" value="{csrf_token[:20]}...">')


def demo_safe_redirects():
    """Safe redirect validation."""
    print("\n" + "=" * 60)
    print("SAFE REDIRECT VALIDATION")
    print("=" * 60)

    from urllib.parse import urlparse, urljoin

    def is_safe_url(target, host):
        """Validate redirect URL to prevent open redirects."""
        ref_url = urlparse(f"https://{host}")
        test_url = urlparse(urljoin(f"https://{host}", target))
        return (
            test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc
        )

    host = "example.com"
    test_urls = [
        ("/dashboard", True),
        ("/user/profile", True),
        ("https://example.com/page", True),
        ("https://evil.com/phish", False),
        ("//evil.com/phish", False),
        ("javascript:alert(1)", False),
    ]

    print(f"Host: {host}")
    for url, expected_safe in test_urls:
        actual_safe = is_safe_url(url, host)
        status = "OK" if actual_safe == expected_safe else "MISMATCH"
        print(f"  {url:35s} safe={actual_safe:5} [{status}]")


def demo_rate_limiting_tokens():
    """Token bucket pattern for rate limiting."""
    print("\n" + "=" * 60)
    print("RATE LIMITING WITH SECURE TOKENS")
    print("=" * 60)

    import time

    class TokenBucket:
        def __init__(self, rate, capacity):
            self.rate = rate
            self.capacity = capacity
            self.tokens = capacity
            self.last_time = time.time()

        def consume(self, tokens=1):
            now = time.time()
            elapsed = now - self.last_time
            self.last_time = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    bucket = TokenBucket(rate=2, capacity=5)
    results = []
    for i in range(8):
        allowed = bucket.consume()
        results.append(("ALLOWED" if allowed else "DENIED"))

    print("Token bucket (rate=2/s, capacity=5):")
    for i, result in enumerate(results):
        print(f"  Request {i+1}: {result}")


def demo_content_security():
    """Content security headers and nonce generation."""
    print("\n" + "=" * 60)
    print("CONTENT SECURITY POLICY")
    print("=" * 60)

    import secrets

    # Generate CSP nonce
    nonce = secrets.token_urlsafe(16)

    csp_directives = {
        "default-src": "'self'",
        "script-src": f"'self' 'nonce-{nonce}'",
        "style-src": "'self' 'unsafe-inline'",
        "img-src": "'self' data: https:",
        "font-src": "'self'",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    }

    csp_header = "; ".join(f"{k} {v}" for k, v in csp_directives.items())

    print(f"CSP Nonce: {nonce}")
    print(f"\nContent-Security-Policy:")
    for directive, value in csp_directives.items():
        print(f"  {directive}: {value}")
    print(f"\nHTML usage: <script nonce=\"{nonce}\">...</script>")


def demo_secure_app_config():
    """Complete secure Flask application configuration."""
    print("\n" + "=" * 60)
    print("SECURE FLASK APP CONFIGURATION")
    print("=" * 60)

    app = Flask(__name__)

    # Security configuration
    app.config.update(
        SECRET_KEY=os.urandom(32),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
        JSON_SORT_KEYS=False,
        PREFERRED_URL_SCHEME='https',
    )

    print("Secure Flask configuration:")
    display_config = {
        'SECRET_KEY': '<32 random bytes>',
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'PERMANENT_SESSION_LIFETIME': 1800,
        'MAX_CONTENT_LENGTH': '16MB',
        'PREFERRED_URL_SCHEME': 'https',
    }
    for key, value in display_config.items():
        print(f"  {key}: {value}")


def main():
    """Run all Flask security demonstrations."""
    print("FLASK SECURITY FEATURES - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Secret Key
    demo_secret_key_generation()

    # Sessions
    demo_session_signing()
    demo_secure_cookie_config()

    # Authentication
    demo_password_hashing()
    demo_token_generation()

    # CSRF
    demo_csrf_protection()

    # Security
    demo_safe_redirects()
    demo_rate_limiting_tokens()
    demo_content_security()
    demo_secure_app_config()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
