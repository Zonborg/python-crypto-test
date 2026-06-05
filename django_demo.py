"""
Comprehensive demonstration of Django's cryptographic utilities.
Covers password hashing, signing, CSRF tokens, encryption utilities,
and the django.utils.crypto module.
"""

import os
import sys
import django
from django.conf import settings

# Minimal Django configuration for standalone usage
if not settings.configured:
    settings.configure(
        SECRET_KEY='demo-secret-key-for-testing-only-not-for-production-use-12345',
        INSTALLED_APPS=['django.contrib.auth', 'django.contrib.contenttypes'],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
        PASSWORD_HASHERS=[
            'django.contrib.auth.hashers.Argon2PasswordHasher',
            'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
            'django.contrib.auth.hashers.BCryptPasswordHasher',
            'django.contrib.auth.hashers.PBKDF2PasswordHasher',
            'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
            'django.contrib.auth.hashers.ScryptPasswordHasher',
        ],
    )
    django.setup()

from django.contrib.auth.hashers import (
    make_password, check_password, identify_hasher,
    PBKDF2PasswordHasher, PBKDF2SHA1PasswordHasher,
    Argon2PasswordHasher, BCryptSHA256PasswordHasher,
    ScryptPasswordHasher,
)
from django.core.signing import Signer, TimestampSigner, dumps, loads
from django.utils.crypto import (
    get_random_string, constant_time_compare, pbkdf2, salted_hmac
)
from django.middleware.csrf import _get_new_csrf_string, _mask_cipher_secret
import hashlib


def demo_pbkdf2_hasher():
    """Django PBKDF2 password hasher."""
    print("\n" + "=" * 60)
    print("DJANGO PBKDF2 PASSWORD HASHER")
    print("=" * 60)

    password = "my-secret-password"

    # Hash with PBKDF2-SHA256
    hashed = make_password(password, hasher='pbkdf2_sha256')
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")

    # Verify
    assert check_password(password, hashed)
    assert not check_password("wrong-password", hashed)
    print("Verify correct:   PASSED")
    print("Verify incorrect: REJECTED")

    # Identify hasher
    hasher = identify_hasher(hashed)
    print(f"Hasher: {hasher.algorithm}")
    print(f"Iterations: {hasher.iterations}")


def demo_pbkdf2_sha1_hasher():
    """Django PBKDF2-SHA1 password hasher."""
    print("\n" + "=" * 60)
    print("DJANGO PBKDF2-SHA1 PASSWORD HASHER")
    print("=" * 60)

    password = "my-secret-password"
    hashed = make_password(password, hasher='pbkdf2_sha1')

    assert check_password(password, hashed)
    print(f"Hash: {hashed}")
    print("Verification: PASSED")


def demo_argon2_hasher():
    """Django Argon2 password hasher."""
    print("\n" + "=" * 60)
    print("DJANGO ARGON2 PASSWORD HASHER")
    print("=" * 60)

    password = "my-secret-password"

    try:
        hashed = make_password(password, hasher='argon2')
        assert check_password(password, hashed)
        print(f"Password: {password}")
        print(f"Hash:     {hashed}")
        print("Verification: PASSED")
    except Exception as e:
        print(f"Argon2 not available: {e}")


def demo_bcrypt_hasher():
    """Django BCrypt password hasher."""
    print("\n" + "=" * 60)
    print("DJANGO BCRYPT-SHA256 PASSWORD HASHER")
    print("=" * 60)

    password = "my-secret-password"

    try:
        hashed = make_password(password, hasher='bcrypt_sha256')
        assert check_password(password, hashed)
        print(f"Password: {password}")
        print(f"Hash:     {hashed}")
        print("Verification: PASSED")
    except Exception as e:
        print(f"BCrypt not available: {e}")


def demo_scrypt_hasher():
    """Django Scrypt password hasher."""
    print("\n" + "=" * 60)
    print("DJANGO SCRYPT PASSWORD HASHER")
    print("=" * 60)

    password = "my-secret-password"

    try:
        hashed = make_password(password, hasher='scrypt')
        assert check_password(password, hashed)
        print(f"Password: {password}")
        print(f"Hash:     {hashed}")
        print("Verification: PASSED")
    except Exception as e:
        print(f"Scrypt not available: {e}")


def demo_custom_salt():
    """Password hashing with custom salt."""
    print("\n" + "=" * 60)
    print("PASSWORD HASHING WITH CUSTOM SALT")
    print("=" * 60)

    password = "my-secret-password"
    custom_salt = "custom_salt_value"

    hashed = make_password(password, salt=custom_salt, hasher='pbkdf2_sha256')
    assert check_password(password, hashed)

    print(f"Password:    {password}")
    print(f"Custom salt: {custom_salt}")
    print(f"Hash:        {hashed}")
    print("Verification: PASSED")


def demo_unusable_password():
    """Unusable password marker."""
    print("\n" + "=" * 60)
    print("UNUSABLE PASSWORD")
    print("=" * 60)

    unusable = make_password(None)
    print(f"Unusable hash: {unusable}")
    print(f"Check returns False: {not check_password('anything', unusable)}")


def demo_signer():
    """Django's Signer for data integrity."""
    print("\n" + "=" * 60)
    print("DJANGO SIGNER")
    print("=" * 60)

    signer = Signer()

    # Sign a value
    value = "my-important-data"
    signed = signer.sign(value)
    print(f"Value:  {value}")
    print(f"Signed: {signed}")

    # Unsign (verify and extract)
    unsigned = signer.unsign(signed)
    assert unsigned == value
    print(f"Unsigned: {unsigned}")

    # Custom separator and salt
    signer_custom = Signer(salt='custom-salt', sep=':')
    signed_custom = signer_custom.sign(value)
    print(f"Custom signed: {signed_custom}")

    # Tampered data detection
    try:
        signer.unsign(signed + "tampered")
        print("Tampered: NOT DETECTED (ERROR)")
    except django.core.signing.BadSignature:
        print("Tampered: Correctly detected")


def demo_timestamp_signer():
    """Django's TimestampSigner for time-limited signatures."""
    print("\n" + "=" * 60)
    print("DJANGO TIMESTAMP SIGNER")
    print("=" * 60)

    signer = TimestampSigner()

    value = "time-sensitive-data"
    signed = signer.sign(value)
    print(f"Value:  {value}")
    print(f"Signed: {signed}")

    # Unsign with max_age
    import time
    unsigned = signer.unsign(signed, max_age=60)  # Valid for 60 seconds
    print(f"Unsigned (within 60s): {unsigned}")

    # Test expiration
    try:
        signer.unsign(signed, max_age=0)
        print("Expired: NOT DETECTED (ERROR)")
    except django.core.signing.SignatureExpired:
        print("Expired (max_age=0): Correctly expired")


def demo_signing_objects():
    """Django's dumps/loads for signing complex objects."""
    print("\n" + "=" * 60)
    print("DJANGO OBJECT SIGNING (dumps/loads)")
    print("=" * 60)

    # Sign a dictionary
    data = {"user_id": 42, "role": "admin", "permissions": ["read", "write"]}
    signed = dumps(data)
    print(f"Data:   {data}")
    print(f"Signed: {signed[:50]}...")

    # Load and verify
    loaded = loads(signed)
    assert loaded == data
    print(f"Loaded: {loaded}")

    # With compression
    large_data = {"items": list(range(100))}
    signed_compressed = dumps(large_data, compress=True)
    loaded_compressed = loads(signed_compressed)
    assert loaded_compressed == large_data
    print(f"Compressed signing: OK ({len(signed_compressed)} chars)")

    # With salt
    signed_salted = dumps(data, salt='my-custom-salt')
    loaded_salted = loads(signed_salted, salt='my-custom-salt')
    assert loaded_salted == data
    print("Salted signing: OK")


def demo_random_string():
    """Django's get_random_string utility."""
    print("\n" + "=" * 60)
    print("DJANGO RANDOM STRING GENERATION")
    print("=" * 60)

    # Default (alphanumeric + special)
    random_default = get_random_string(32)
    print(f"Default (32):    {random_default}")

    # Custom allowed chars
    random_hex = get_random_string(32, allowed_chars='0123456789abcdef')
    print(f"Hex (32):        {random_hex}")

    random_alpha = get_random_string(16, allowed_chars='abcdefghijklmnopqrstuvwxyz')
    print(f"Alpha (16):      {random_alpha}")

    random_numeric = get_random_string(8, allowed_chars='0123456789')
    print(f"Numeric (8):     {random_numeric}")

    # Various lengths
    for length in [8, 16, 32, 64]:
        s = get_random_string(length)
        print(f"  Length {length:2d}: {s[:40]}{'...' if length > 40 else ''}")


def demo_constant_time_compare():
    """Django's constant-time string comparison."""
    print("\n" + "=" * 60)
    print("CONSTANT-TIME COMPARISON")
    print("=" * 60)

    value1 = "secret-token-12345"
    value2 = "secret-token-12345"
    value3 = "secret-token-99999"

    result_equal = constant_time_compare(value1, value2)
    result_different = constant_time_compare(value1, value3)

    print(f"Compare equal:     {result_equal}")
    print(f"Compare different: {result_different}")
    print("(Both comparisons take constant time)")


def demo_pbkdf2_utility():
    """Django's PBKDF2 utility function."""
    print("\n" + "=" * 60)
    print("DJANGO PBKDF2 UTILITY")
    print("=" * 60)

    password = "my-secret-password"
    salt = "random-salt-value"

    # SHA-256
    key_sha256 = pbkdf2(password, salt, iterations=600000, dklen=32, digest=hashlib.sha256)
    print(f"PBKDF2-SHA256: {key_sha256.hex()}")

    # SHA-1
    key_sha1 = pbkdf2(password, salt, iterations=600000, dklen=20, digest=hashlib.sha1)
    print(f"PBKDF2-SHA1:   {key_sha1.hex()}")

    # SHA-512
    key_sha512 = pbkdf2(password, salt, iterations=600000, dklen=64, digest=hashlib.sha512)
    print(f"PBKDF2-SHA512: {key_sha512.hex()[:50]}...")


def demo_salted_hmac():
    """Django's salted HMAC utility."""
    print("\n" + "=" * 60)
    print("DJANGO SALTED HMAC")
    print("=" * 60)

    key_salt = "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash"
    value = "session-data-to-authenticate"

    hmac_obj = salted_hmac(key_salt, value)
    digest = hmac_obj.hexdigest()

    print(f"Key salt: {key_salt[:50]}...")
    print(f"Value:    {value}")
    print(f"HMAC:     {digest}")

    # With custom secret
    hmac_custom = salted_hmac(key_salt, value, secret='custom-secret')
    digest_custom = hmac_custom.hexdigest()
    print(f"Custom:   {digest_custom}")

    # Different algorithm
    hmac_sha512 = salted_hmac(key_salt, value, algorithm='sha512')
    digest_512 = hmac_sha512.hexdigest()
    print(f"SHA-512:  {digest_512[:50]}...")


def demo_csrf_token():
    """Django CSRF token generation."""
    print("\n" + "=" * 60)
    print("DJANGO CSRF TOKEN")
    print("=" * 60)

    # Generate CSRF secret
    csrf_secret = _get_new_csrf_string()
    print(f"CSRF secret: {csrf_secret}")

    # Mask the secret (what's sent to the client)
    masked = _mask_cipher_secret(csrf_secret)
    print(f"Masked token: {masked}")
    print(f"Token length: {len(masked)}")


def demo_password_upgrade():
    """Demonstrate password hash upgrade detection."""
    print("\n" + "=" * 60)
    print("PASSWORD HASH UPGRADE DETECTION")
    print("=" * 60)

    password = "my-secret-password"

    # Create hash with lower iterations
    hasher = PBKDF2PasswordHasher()
    low_iter_hash = make_password(password, hasher='pbkdf2_sha256')

    # Check if upgrade is needed (based on current settings)
    needs_upgrade = identify_hasher(low_iter_hash).must_update(low_iter_hash)
    print(f"Hash: {low_iter_hash[:50]}...")
    print(f"Needs upgrade: {needs_upgrade}")


def main():
    """Run all Django crypto demonstrations."""
    print("DJANGO CRYPTO UTILITIES - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Password Hashing
    demo_pbkdf2_hasher()
    demo_pbkdf2_sha1_hasher()
    demo_argon2_hasher()
    demo_bcrypt_hasher()
    demo_scrypt_hasher()
    demo_custom_salt()
    demo_unusable_password()
    demo_password_upgrade()

    # Signing
    demo_signer()
    demo_timestamp_signer()
    demo_signing_objects()

    # Utilities
    demo_random_string()
    demo_constant_time_compare()
    demo_pbkdf2_utility()
    demo_salted_hmac()

    # CSRF
    demo_csrf_token()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
