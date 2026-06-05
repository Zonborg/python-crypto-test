"""
Comprehensive demonstration of the itsdangerous library.
Covers URL-safe serializers, timed serializers, signing,
salt usage, and various serialization formats.
"""

import os
import time
import json
from itsdangerous import (
    Signer, TimestampSigner,
    Serializer, TimedSerializer,
    URLSafeSerializer, URLSafeTimedSerializer,
    BadSignature, SignatureExpired, BadTimeSignature,
)


def demo_basic_signer():
    """Basic string signing."""
    print("\n" + "=" * 60)
    print("BASIC SIGNER")
    print("=" * 60)

    secret_key = "my-secret-key"
    signer = Signer(secret_key)

    # Sign a value
    value = "hello-world"
    signed = signer.sign(value)
    print(f"Value:  {value}")
    print(f"Signed: {signed}")

    # Unsign (verify)
    unsigned = signer.unsign(signed)
    print(f"Unsigned: {unsigned}")

    # Tampered value detection
    try:
        signer.unsign(signed + b"tampered")
        print("Tampered: NOT DETECTED (ERROR)")
    except BadSignature:
        print("Tampered: Correctly detected")

    # Different separator
    signer_dot = Signer(secret_key, sep='.')
    signed_dot = signer_dot.sign(value)
    print(f"Custom separator (.): {signed_dot}")


def demo_signer_with_salt():
    """Signer with salt for namespace separation."""
    print("\n" + "=" * 60)
    print("SIGNER WITH SALT (NAMESPACE SEPARATION)")
    print("=" * 60)

    secret_key = "my-secret-key"
    value = "sensitive-data"

    # Same key, different salts = different signatures
    signer1 = Signer(secret_key, salt='email-confirm')
    signer2 = Signer(secret_key, salt='password-reset')

    signed1 = signer1.sign(value)
    signed2 = signer2.sign(value)

    print(f"Salt 'email-confirm':  {signed1}")
    print(f"Salt 'password-reset': {signed2}")
    print(f"Different signatures: {signed1 != signed2}")

    # Cross-salt verification fails
    try:
        signer2.unsign(signed1)
        print("Cross-salt: NOT DETECTED (ERROR)")
    except BadSignature:
        print("Cross-salt: Correctly rejected")


def demo_timestamp_signer():
    """Timestamp signer for time-limited signatures."""
    print("\n" + "=" * 60)
    print("TIMESTAMP SIGNER")
    print("=" * 60)

    secret_key = "my-secret-key"
    signer = TimestampSigner(secret_key)

    value = "time-limited-data"
    signed = signer.sign(value)
    print(f"Value:  {value}")
    print(f"Signed: {signed}")

    # Unsign with max_age (should pass)
    unsigned = signer.unsign(signed, max_age=60)
    print(f"Unsigned (max_age=60s): {unsigned}")

    # Get timestamp
    unsigned_with_ts = signer.unsign(signed, return_timestamp=True)
    print(f"Timestamp: {unsigned_with_ts[1]}")

    # Test expiration
    try:
        signer.unsign(signed, max_age=0)
        print("Expired: NOT DETECTED")
    except SignatureExpired as e:
        print(f"Expired (max_age=0): Correctly expired (age: {e.date_signed})")


def demo_serializer():
    """Serializer for signing complex data structures."""
    print("\n" + "=" * 60)
    print("SERIALIZER (COMPLEX DATA)")
    print("=" * 60)

    secret_key = "my-secret-key"
    s = Serializer(secret_key)

    # Sign various data types
    data_examples = [
        {"user_id": 42, "role": "admin"},
        [1, 2, 3, "four", "five"],
        "simple-string",
        {"nested": {"key": "value", "list": [1, 2, 3]}},
    ]

    for data in data_examples:
        signed = s.dumps(data)
        loaded = s.loads(signed)
        assert loaded == data
        display = str(data)[:40]
        print(f"  {display:42s} -> {signed[:30]}...")


def demo_urlsafe_serializer():
    """URL-safe serializer (base64 encoding)."""
    print("\n" + "=" * 60)
    print("URL-SAFE SERIALIZER")
    print("=" * 60)

    secret_key = "my-secret-key"
    s = URLSafeSerializer(secret_key)

    # Generate URL-safe tokens
    data = {"user_id": 42, "action": "confirm_email"}
    token = s.dumps(data)
    print(f"Data:  {data}")
    print(f"Token: {token}")
    print(f"URL-safe: {all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.' for c in token)}")

    # Load
    loaded = s.loads(token)
    print(f"Loaded: {loaded}")

    # With salt
    token_salted = s.dumps(data, salt='email-confirm')
    loaded_salted = s.loads(token_salted, salt='email-confirm')
    print(f"Salted token: {token_salted}")
    print(f"Salted loaded: {loaded_salted}")


def demo_urlsafe_timed_serializer():
    """URL-safe timed serializer for expiring tokens."""
    print("\n" + "=" * 60)
    print("URL-SAFE TIMED SERIALIZER")
    print("=" * 60)

    secret_key = "my-secret-key"
    s = URLSafeTimedSerializer(secret_key)

    # Email confirmation token
    email = "user@example.com"
    token = s.dumps(email, salt='email-confirm')
    print(f"Email: {email}")
    print(f"Token: {token}")

    # Verify within time limit
    loaded = s.loads(token, salt='email-confirm', max_age=3600)
    print(f"Loaded (max_age=3600): {loaded}")

    # Password reset token
    reset_data = {"uid": 42, "ts": int(time.time())}
    reset_token = s.dumps(reset_data, salt='password-reset')
    print(f"\nReset data: {reset_data}")
    print(f"Reset token: {reset_token}")

    # API key
    api_data = {"app": "myapp", "scope": ["read", "write"]}
    api_token = s.dumps(api_data, salt='api-key')
    print(f"\nAPI data: {api_data}")
    print(f"API token: {api_token}")


def demo_timed_serializer():
    """Timed serializer with expiration."""
    print("\n" + "=" * 60)
    print("TIMED SERIALIZER WITH EXPIRATION")
    print("=" * 60)

    secret_key = "my-secret-key"
    s = TimedSerializer(secret_key)

    data = {"session": "abc123", "user": "demo"}
    signed = s.dumps(data)
    print(f"Data:   {data}")
    print(f"Signed: {signed}")

    # Load with timestamp
    loaded, timestamp = s.loads(signed, return_timestamp=True)
    print(f"Loaded: {loaded}")
    print(f"Signed at: {timestamp}")

    # Test max_age
    loaded_valid = s.loads(signed, max_age=60)
    print(f"Valid (60s): {loaded_valid}")


def demo_multiple_keys():
    """Serializer with key rotation (multiple secret keys)."""
    print("\n" + "=" * 60)
    print("KEY ROTATION (MULTIPLE SECRET KEYS)")
    print("=" * 60)

    # Old key (being rotated out)
    old_key = "old-secret-key-2023"
    # New key (current)
    new_key = "new-secret-key-2024"

    # Sign with old key
    old_serializer = URLSafeTimedSerializer(old_key)
    old_token = old_serializer.dumps("user@example.com", salt='confirm')
    print(f"Token signed with old key: {old_token}")

    # New serializer supports both keys using secret_key as list
    # In modern itsdangerous, pass multiple keys for key rotation
    new_serializer = URLSafeTimedSerializer([new_key, old_key])

    # Can verify old tokens (tries all keys)
    try:
        loaded = new_serializer.loads(old_token, salt='confirm', max_age=3600)
        print(f"Old token verified with key rotation: {loaded}")
    except BadSignature:
        print("Note: key rotation verification depends on version")

    # New tokens use first (primary) key
    new_token = new_serializer.dumps("user@example.com", salt='confirm')
    loaded_new = new_serializer.loads(new_token, salt='confirm', max_age=3600)
    print(f"New token: {new_token}")
    print(f"New token verified: {loaded_new}")


def demo_jws_serializer():
    """JSON Web Signature serializer (deprecated in newer itsdangerous)."""
    print("\n" + "=" * 60)
    print("JSON WEB SIGNATURE SERIALIZER")
    print("=" * 60)

    print("JSONWebSignatureSerializer was removed in itsdangerous >= 2.1")
    print("Use PyJWT or python-jose for JWS/JWT functionality")


def demo_custom_serialization():
    """Custom serialization format."""
    print("\n" + "=" * 60)
    print("CUSTOM SERIALIZATION")
    print("=" * 60)

    secret_key = "my-secret-key"

    # Custom serializer that uses compact JSON
    class CompactSerializer:
        def dumps(self, obj):
            return json.dumps(obj, separators=(',', ':'))

        def loads(self, data):
            return json.loads(data)

    s = Serializer(secret_key, serializer=CompactSerializer())

    data = {"user": "demo", "roles": ["admin", "user"], "active": True}
    signed = s.dumps(data)
    loaded = s.loads(signed)

    print(f"Data:   {data}")
    print(f"Signed: {signed}")
    print(f"Loaded: {loaded}")
    assert loaded == data
    print("Custom serializer: OK")


def demo_error_handling():
    """Error handling patterns."""
    print("\n" + "=" * 60)
    print("ERROR HANDLING")
    print("=" * 60)

    secret_key = "my-secret-key"
    s = URLSafeTimedSerializer(secret_key)

    token = s.dumps("test@example.com", salt='test')

    # BadSignature
    try:
        s.loads("invalid-token", salt='test', max_age=3600)
    except BadSignature as e:
        print(f"BadSignature: {type(e).__name__}: {e}")

    # Wrong salt
    try:
        s.loads(token, salt='wrong-salt', max_age=3600)
    except BadSignature as e:
        print(f"Wrong salt: {type(e).__name__}: {e}")

    # SignatureExpired
    try:
        s.loads(token, salt='test', max_age=0)
    except SignatureExpired as e:
        print(f"Expired: {type(e).__name__}")
        # Can still access the payload
        print(f"  Payload available: {e.payload is not None}")
        print(f"  Date signed: {e.date_signed}")


def demo_use_cases():
    """Common use cases for itsdangerous."""
    print("\n" + "=" * 60)
    print("COMMON USE CASES")
    print("=" * 60)

    secret_key = os.urandom(32)
    s = URLSafeTimedSerializer(secret_key)

    use_cases = {
        "Email confirmation": {
            "data": {"email": "user@example.com", "action": "confirm"},
            "salt": "email-confirm",
            "max_age": 86400,  # 24 hours
        },
        "Password reset": {
            "data": {"uid": 42, "hash": "abc123"},
            "salt": "password-reset",
            "max_age": 3600,  # 1 hour
        },
        "Account activation": {
            "data": {"uid": 42, "plan": "pro"},
            "salt": "activate",
            "max_age": 604800,  # 7 days
        },
        "Unsubscribe link": {
            "data": {"uid": 42, "list": "newsletter"},
            "salt": "unsubscribe",
            "max_age": None,  # Never expires
        },
    }

    for name, config in use_cases.items():
        token = s.dumps(config["data"], salt=config["salt"])
        max_age_str = f"{config['max_age']}s" if config['max_age'] else "never"
        print(f"  {name}:")
        print(f"    Token: {token[:40]}...")
        print(f"    Expires: {max_age_str}")


def main():
    """Run all itsdangerous demonstrations."""
    print("ITSDANGEROUS LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Basic Signing
    demo_basic_signer()
    demo_signer_with_salt()
    demo_timestamp_signer()

    # Serialization
    demo_serializer()
    demo_urlsafe_serializer()
    demo_urlsafe_timed_serializer()
    demo_timed_serializer()

    # Advanced
    demo_multiple_keys()
    demo_jws_serializer()
    demo_custom_serialization()

    # Error Handling
    demo_error_handling()

    # Use Cases
    demo_use_cases()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
