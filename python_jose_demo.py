"""
Comprehensive demonstration of the python-jose library.
Covers JWS (JSON Web Signature), JWE (JSON Web Encryption),
JWK (JSON Web Key), JWT claims, and multiple algorithms.
"""

import json
import time
import datetime
import os
from jose import jwt, jws, jwk, jwe
from jose.constants import ALGORITHMS
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
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }

    token = jwt.encode(payload, secret, algorithm="HS256")
    decoded = jwt.decode(token, secret, algorithms=["HS256"])

    print(f"Payload: {json.dumps(payload, indent=2)}")
    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_hs384():
    """JWT with HMAC-SHA384."""
    print("\n" + "=" * 60)
    print("JWT WITH HS384 (HMAC-SHA384)")
    print("=" * 60)

    secret = "my-super-secret-key-384-bits-long"
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

    secret = "my-super-secret-key-512-bits-for-hmac"
    payload = {"sub": "user456", "permissions": ["read", "write", "admin"]}

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
        "iat": int(time.time()),
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

    payload = {"sub": "highsec", "level": "classified"}
    token = jwt.encode(payload, private_pem, algorithm="RS512")
    decoded = jwt.decode(token, public_pem, algorithms=["RS512"])

    print(f"Key size: 4096 bits")
    print(f"Token:   {token[:50]}...")
    print(f"Decoded: {decoded}")


def demo_ps256():
    """JWT with RSA-PSS-SHA256."""
    print("\n" + "=" * 60)
    print("JWT WITH PS256 (RSA-PSS)")
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

    payload = {"sub": "pss-user", "alg": "PS256"}

    try:
        token = jwt.encode(payload, private_pem, algorithm="PS256")
        decoded = jwt.decode(token, public_pem, algorithms=["PS256"])
        print(f"Token:   {token[:50]}...")
        print(f"Decoded: {decoded}")
    except Exception as e:
        print(f"PS256 not supported with current backend: {e}")
        print("Install python-jose[cryptography] for RSA-PSS support")
        # Fall back to RS256 to demonstrate RSA signing works
        token = jwt.encode(payload, private_pem, algorithm="RS256")
        decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
        print(f"Fallback RS256 Token:   {token[:50]}...")
        print(f"Fallback RS256 Decoded: {decoded}")


def demo_es256():
    """JWT with ECDSA P-256."""
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
    """JWT with ECDSA P-384."""
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
    """JWT with ECDSA P-521."""
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


def demo_claims_validation():
    """JWT claims validation."""
    print("\n" + "=" * 60)
    print("JWT CLAIMS VALIDATION")
    print("=" * 60)

    secret = "claims-test-secret"
    now = int(time.time())

    payload = {
        "sub": "user123",
        "iss": "my-app",
        "aud": "my-api",
        "exp": now + 3600,
        "nbf": now - 10,
        "iat": now,
        "custom_claim": "custom_value",
    }

    token = jwt.encode(payload, secret, algorithm="HS256")

    # Decode with validation
    decoded = jwt.decode(
        token, secret,
        algorithms=["HS256"],
        issuer="my-app",
        audience="my-api",
        options={"require_exp": True, "require_iat": True}
    )

    print(f"Token:   {token[:50]}...")
    print(f"Issuer:  {decoded['iss']}")
    print(f"Audience: {decoded['aud']}")
    print(f"Custom:  {decoded['custom_claim']}")
    print("Claims validation: PASSED")

    # Test expired token
    expired_payload = {
        "sub": "user123",
        "exp": now - 3600,  # 1 hour ago
    }
    expired_token = jwt.encode(expired_payload, secret, algorithm="HS256")
    try:
        jwt.decode(expired_token, secret, algorithms=["HS256"])
        print("Expired token: NOT REJECTED (ERROR)")
    except jwt.ExpiredSignatureError:
        print("Expired token: Correctly rejected")


def demo_jws_operations():
    """JWS (JSON Web Signature) operations."""
    print("\n" + "=" * 60)
    print("JWS OPERATIONS")
    print("=" * 60)

    secret = "jws-secret-key"
    payload = b"Raw payload to sign"

    # Sign
    signed = jws.sign(payload, secret, algorithm="HS256")
    print(f"Payload: {payload}")
    print(f"Signed:  {signed[:50]}...")

    # Verify
    verified_payload = jws.verify(signed, secret, algorithms=["HS256"])
    assert verified_payload == payload
    print(f"Verified: {verified_payload}")

    # Get unverified header
    header = jws.get_unverified_header(signed)
    print(f"Header:  {header}")

    # Get unverified claims (for JWT)
    token = jwt.encode({"sub": "test"}, secret, algorithm="HS256")
    unverified = jwt.get_unverified_claims(token)
    print(f"Unverified claims: {unverified}")


def demo_jwk_operations():
    """JWK (JSON Web Key) operations."""
    print("\n" + "=" * 60)
    print("JWK OPERATIONS")
    print("=" * 60)

    # RSA JWK
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Construct RSA JWK
    rsa_jwk = jwk.construct(private_pem, algorithm="RS256")
    print(f"RSA JWK constructed: {type(rsa_jwk).__name__}")

    # EC JWK
    ec_private = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    ec_jwk = jwk.construct(ec_pem, algorithm="ES256")
    print(f"EC JWK constructed: {type(ec_jwk).__name__}")

    # HMAC JWK
    hmac_key = os.urandom(32)
    hmac_jwk = jwk.construct(hmac_key, algorithm="HS256")
    print(f"HMAC JWK constructed: {type(hmac_jwk).__name__}")

    # Sign with JWK
    payload = {"sub": "jwk-test"}
    token = jwt.encode(payload, rsa_jwk.to_dict(), algorithm="RS256")
    print(f"Token signed with JWK: {token[:40]}...")


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
    }

    token = jwt.encode(payload, secret, algorithm="HS256", headers=headers)
    header = jws.get_unverified_header(token)
    decoded = jwt.decode(token, secret, algorithms=["HS256"])

    print(f"Token:   {token[:50]}...")
    print(f"Headers: {header}")
    print(f"Decoded: {decoded}")


def demo_unverified_decode():
    """Decode JWT without verification."""
    print("\n" + "=" * 60)
    print("UNVERIFIED JWT DECODE")
    print("=" * 60)

    secret = "decode-secret"
    payload = {"sub": "user123", "role": "admin", "data": "sensitive"}

    token = jwt.encode(payload, secret, algorithm="HS256")

    # Get claims without verification
    unverified_claims = jwt.get_unverified_claims(token)
    unverified_header = jwt.get_unverified_header(token)

    print(f"Token:    {token[:50]}...")
    print(f"Header:   {unverified_header}")
    print(f"Claims:   {unverified_claims}")
    print("WARNING: Do not trust unverified claims for authorization!")


def demo_available_algorithms():
    """List available algorithms."""
    print("\n" + "=" * 60)
    print("AVAILABLE ALGORITHMS")
    print("=" * 60)

    print("HMAC algorithms:")
    for alg in ALGORITHMS.HMAC:
        print(f"  - {alg}")

    print("RSA algorithms:")
    for alg in ALGORITHMS.RSA:
        print(f"  - {alg}")

    print("EC algorithms:")
    for alg in ALGORITHMS.EC:
        print(f"  - {alg}")

    print(f"\nAll supported: {ALGORITHMS.SUPPORTED}")


def demo_token_expiration_patterns():
    """Common token expiration patterns."""
    print("\n" + "=" * 60)
    print("TOKEN EXPIRATION PATTERNS")
    print("=" * 60)

    secret = "expiration-secret"
    now = int(time.time())

    patterns = {
        "Access token (15 min)": {"sub": "user", "exp": now + 900},
        "Refresh token (7 days)": {"sub": "user", "exp": now + 604800},
        "Email confirm (24 hrs)": {"sub": "user", "action": "confirm", "exp": now + 86400},
        "Password reset (1 hr)": {"sub": "user", "action": "reset", "exp": now + 3600},
    }

    for name, payload in patterns.items():
        token = jwt.encode(payload, secret, algorithm="HS256")
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        ttl = decoded["exp"] - now
        print(f"  {name:25s}: TTL={ttl}s, token={token[:30]}...")


def demo_nested_jwt():
    """Nested JWT (signed then encrypted concept)."""
    print("\n" + "=" * 60)
    print("NESTED JWT PATTERN")
    print("=" * 60)

    sign_secret = "signing-key"
    encrypt_secret = "encryption-key-32bytes!!"

    # First: create signed JWT
    payload = {"sub": "user123", "role": "admin", "iat": int(time.time())}
    signed_token = jwt.encode(payload, sign_secret, algorithm="HS256")
    print(f"Signed JWT: {signed_token[:40]}...")

    # In practice, you'd encrypt the signed JWT using JWE
    # python-jose supports JWE for encryption
    # Here we demonstrate the concept
    wrapper_payload = {"token": signed_token, "encrypted_at": int(time.time())}
    outer_token = jwt.encode(wrapper_payload, encrypt_secret, algorithm="HS256")
    print(f"Outer JWT:  {outer_token[:40]}...")

    # Decrypt outer, then verify inner
    outer_decoded = jwt.decode(outer_token, encrypt_secret, algorithms=["HS256"])
    inner_decoded = jwt.decode(outer_decoded["token"], sign_secret, algorithms=["HS256"])
    print(f"Inner payload: {inner_decoded}")


def main():
    """Run all python-jose demonstrations."""
    print("PYTHON-JOSE LIBRARY - COMPREHENSIVE DEMO")
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

    # Claims and validation
    demo_claims_validation()
    demo_custom_headers()
    demo_unverified_decode()

    # JWS/JWK
    demo_jws_operations()
    demo_jwk_operations()

    # Patterns
    demo_token_expiration_patterns()
    demo_nested_jwt()

    # Info
    demo_available_algorithms()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
