"""
Comprehensive demonstration of the PyJWT library.
Covers JWT encoding/decoding, algorithm support (HMAC, RSA, EC, EdDSA),
claims validation, custom headers, and advanced features.
"""

import datetime
import json
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization


def demo_hs256():
    """JWT with HMAC-SHA256."""
    print("\n" + "=" * 60)
    print("JWT WITH HS256 (HMAC-SHA256)")
    print("=" * 60)

    secret = "my-super-secret-key"
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    }

    token = jwt.encode(payload, secret, algorithm="HS256")
    decoded = jwt.decode(token, secret, algorithms=["HS256"])

    print(f"Payload: {json.dumps({k: str(v) for k, v in payload.items()}, indent=2)}")
    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_hs384():
    """JWT with HMAC-SHA384."""
    print("\n" + "=" * 60)
    print("JWT WITH HS384 (HMAC-SHA384)")
    print("=" * 60)

    secret = "my-super-secret-key-384"
    payload = {"sub": "user123", "role": "admin"}

    token = jwt.encode(payload, secret, algorithm="HS384")
    decoded = jwt.decode(token, secret, algorithms=["HS384"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_hs512():
    """JWT with HMAC-SHA512."""
    print("\n" + "=" * 60)
    print("JWT WITH HS512 (HMAC-SHA512)")
    print("=" * 60)

    secret = "my-super-secret-key-512"
    payload = {"sub": "user456", "permissions": ["read", "write"]}

    token = jwt.encode(payload, secret, algorithm="HS512")
    decoded = jwt.decode(token, secret, algorithms=["HS512"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_rs256():
    """JWT with RSA-SHA256."""
    print("\n" + "=" * 60)
    print("JWT WITH RS256 (RSA-SHA256)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {
        "sub": "1234567890",
        "name": "Jane Doe",
        "admin": True,
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }

    token = jwt.encode(payload, private_pem, algorithm="RS256")
    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_rs384():
    """JWT with RSA-SHA384."""
    print("\n" + "=" * 60)
    print("JWT WITH RS384 (RSA-SHA384)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "user789", "scope": "api:full"}
    token = jwt.encode(payload, private_pem, algorithm="RS384")
    decoded = jwt.decode(token, public_pem, algorithms=["RS384"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_rs512():
    """JWT with RSA-SHA512."""
    print("\n" + "=" * 60)
    print("JWT WITH RS512 (RSA-SHA512)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "highsec", "level": "top-secret"}
    token = jwt.encode(payload, private_pem, algorithm="RS512")
    decoded = jwt.decode(token, public_pem, algorithms=["RS512"])

    print(f"Key size: 4096 bits")
    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_ps256():
    """JWT with RSA-PSS-SHA256."""
    print("\n" + "=" * 60)
    print("JWT WITH PS256 (RSA-PSS-SHA256)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "pss-user", "method": "PSS"}
    token = jwt.encode(payload, private_pem, algorithm="PS256")
    decoded = jwt.decode(token, public_pem, algorithms=["PS256"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_es256():
    """JWT with ECDSA-SHA256 (P-256 curve)."""
    print("\n" + "=" * 60)
    print("JWT WITH ES256 (ECDSA P-256)")
    print("=" * 60)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "ec-user", "curve": "P-256"}
    token = jwt.encode(payload, private_pem, algorithm="ES256")
    decoded = jwt.decode(token, public_pem, algorithms=["ES256"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_es384():
    """JWT with ECDSA-SHA384 (P-384 curve)."""
    print("\n" + "=" * 60)
    print("JWT WITH ES384 (ECDSA P-384)")
    print("=" * 60)

    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "ec-user-384", "curve": "P-384"}
    token = jwt.encode(payload, private_pem, algorithm="ES384")
    decoded = jwt.decode(token, public_pem, algorithms=["ES384"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_es512():
    """JWT with ECDSA-SHA512 (P-521 curve)."""
    print("\n" + "=" * 60)
    print("JWT WITH ES512 (ECDSA P-521)")
    print("=" * 60)

    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "ec-user-521", "curve": "P-521"}
    token = jwt.encode(payload, private_pem, algorithm="ES512")
    decoded = jwt.decode(token, public_pem, algorithms=["ES512"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_eddsa():
    """JWT with EdDSA (Ed25519)."""
    print("\n" + "=" * 60)
    print("JWT WITH EdDSA (ED25519)")
    print("=" * 60)

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {"sub": "eddsa-user", "alg": "EdDSA"}
    token = jwt.encode(payload, private_pem, algorithm="EdDSA")
    decoded = jwt.decode(token, public_pem, algorithms=["EdDSA"])

    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_claims_validation():
    """JWT claims validation (exp, nbf, iss, aud)."""
    print("\n" + "=" * 60)
    print("JWT CLAIMS VALIDATION")
    print("=" * 60)

    secret = "claims-test-secret"
    now = datetime.datetime.now(datetime.timezone.utc)

    payload = {
        "sub": "user123",
        "iss": "my-app",
        "aud": "my-api",
        "exp": now + datetime.timedelta(hours=1),
        "nbf": now - datetime.timedelta(seconds=10),
        "iat": now,
    }

    token = jwt.encode(payload, secret, algorithm="HS256")

    # Decode with validation
    decoded = jwt.decode(
        token, secret,
        algorithms=["HS256"],
        issuer="my-app",
        audience="my-api",
        options={"require": ["exp", "iss", "aud"]}
    )

    print(f"Token:   {token[:50]}...")
    print(f"Issuer:  {decoded['iss']}")
    print(f"Audience: {decoded['aud']}")
    print("Claims validation: PASSED")

    # Test expired token
    expired_payload = {
        "sub": "user123",
        "exp": now - datetime.timedelta(hours=1),
    }
    expired_token = jwt.encode(expired_payload, secret, algorithm="HS256")
    try:
        jwt.decode(expired_token, secret, algorithms=["HS256"])
        print("Expired token: NOT REJECTED (ERROR)")
    except jwt.ExpiredSignatureError:
        print("Expired token: Correctly rejected")


def demo_custom_headers():
    """JWT with custom headers."""
    print("\n" + "=" * 60)
    print("JWT WITH CUSTOM HEADERS")
    print("=" * 60)

    secret = "header-test-secret"
    payload = {"sub": "user123", "data": "test"}

    headers = {
        "kid": "key-id-12345",
        "typ": "JWT",
        "cty": "application/json",
    }

    token = jwt.encode(payload, secret, algorithm="HS256", headers=headers)

    # Decode header without verification
    unverified_header = jwt.get_unverified_header(token)
    decoded = jwt.decode(token, secret, algorithms=["HS256"])

    print(f"Token:   {token[:50]}...")
    print(f"Headers: {unverified_header}")
    print(f"Decoded: {decoded}")


def demo_unverified_decode():
    """Decode JWT without verification (for inspection)."""
    print("\n" + "=" * 60)
    print("JWT UNVERIFIED DECODE (INSPECTION)")
    print("=" * 60)

    secret = "inspection-secret"
    payload = {"sub": "user123", "role": "admin", "data": "sensitive"}

    token = jwt.encode(payload, secret, algorithm="HS256")

    # Decode without verification (dangerous - only for inspection)
    decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    header = jwt.get_unverified_header(token)

    print(f"Token:           {token[:50]}...")
    print(f"Header:          {header}")
    print(f"Payload (unver): {decoded}")


def demo_leeway():
    """JWT with time leeway for clock skew."""
    print("\n" + "=" * 60)
    print("JWT WITH TIME LEEWAY")
    print("=" * 60)

    secret = "leeway-secret"
    now = datetime.datetime.now(datetime.timezone.utc)

    # Token that just expired (5 seconds ago)
    payload = {
        "sub": "user123",
        "exp": now - datetime.timedelta(seconds=5),
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    # Decode with 10-second leeway (should pass)
    decoded = jwt.decode(
        token, secret,
        algorithms=["HS256"],
        leeway=datetime.timedelta(seconds=10)
    )
    print(f"Token (5s expired): decoded with 10s leeway")
    print(f"Decoded: {decoded}")


def main():
    """Run all PyJWT demonstrations."""
    print("PYJWT LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # HMAC algorithms
    demo_hs256()
    demo_hs384()
    demo_hs512()

    # RSA algorithms
    demo_rs256()
    demo_rs384()
    demo_rs512()
    demo_ps256()

    # EC algorithms
    demo_es256()
    demo_es384()
    demo_es512()

    # EdDSA
    demo_eddsa()

    # Claims and validation
    demo_claims_validation()
    demo_custom_headers()
    demo_unverified_decode()
    demo_leeway()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
