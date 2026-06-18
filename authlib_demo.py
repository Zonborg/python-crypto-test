"""
Comprehensive demonstration of the Authlib library.
Covers JWT (JSON Web Token), JWK (JSON Web Key), JWS (JSON Web Signature),
JWE (JSON Web Encryption), and core cryptographic algorithms.
"""

import json
import time
from authlib.jose import (
    jwt,
    JsonWebKey,
    JsonWebSignature,
    JsonWebEncryption,
    OctKey,
    RSAKey,
    ECKey,
    OKPKey,
)
from authlib.jose.errors import (
    ExpiredTokenError,
    InvalidClaimError,
    MissingClaimError,
    BadSignatureError,
)


# ---------------------------------------------------------------------------
# JWK – Key Generation and Management
# ---------------------------------------------------------------------------

def demo_jwk_oct():
    """Generate and export symmetric (oct) JWK keys."""
    print("\n" + "=" * 60)
    print("JWK - SYMMETRIC (oct) KEYS")
    print("=" * 60)

    for bits in (128, 192, 256):
        key = OctKey.generate_key(bits, is_private=True)
        exported = key.as_dict()
        print(f"Size: {bits}-bit  kty={exported['kty']}  k={exported['k'][:20]}...")

    # Import from raw bytes
    import os
    raw = os.urandom(32)
    key = OctKey.import_key(raw)
    print(f"Imported from raw bytes: kty={key.as_dict()['kty']}")


def demo_jwk_rsa():
    """Generate and export RSA JWK keys."""
    print("\n" + "=" * 60)
    print("JWK - RSA KEYS")
    print("=" * 60)

    key = RSAKey.generate_key(2048, is_private=True)
    private_dict = key.as_dict(is_private=True)
    public_dict = key.as_dict()

    print(f"Key type:         {private_dict['kty']}")
    print(f"Modulus n (first 30): {private_dict['n'][:30]}...")
    print(f"Public exponent e:    {private_dict['e']}")

    # Export PEM and re-import
    pem = key.as_pem(is_private=True)
    re_imported = RSAKey.import_key(pem)
    assert re_imported.as_dict()["n"] == private_dict["n"]
    print("PEM export/import round-trip: OK")


def demo_jwk_ec():
    """Generate EC JWK keys for supported curves."""
    print("\n" + "=" * 60)
    print("JWK - EC KEYS (P-256 / P-384 / P-521)")
    print("=" * 60)

    for curve in ("P-256", "P-384", "P-521"):
        key = ECKey.generate_key(curve, is_private=True)
        d = key.as_dict(is_private=True)
        print(f"Curve: {curve}  x={d['x'][:20]}...  y={d['y'][:20]}...")


def demo_jwk_okp():
    """Generate OKP (Ed25519 / Ed448) JWK keys."""
    print("\n" + "=" * 60)
    print("JWK - OKP KEYS (Ed25519 / Ed448)")
    print("=" * 60)

    for crv in ("Ed25519", "Ed448"):
        key = OKPKey.generate_key(crv, is_private=True)
        d = key.as_dict(is_private=True)
        print(f"Curve: {crv}  x={d['x'][:30]}...")


def demo_jwk_set():
    """Build a JWK Set from multiple keys."""
    print("\n" + "=" * 60)
    print("JWKS - JSON WEB KEY SET")
    print("=" * 60)

    keys = [
        RSAKey.generate_key(2048, is_private=True),
        ECKey.generate_key("P-256", is_private=True),
        ECKey.generate_key("P-384", is_private=True),
        OKPKey.generate_key("Ed25519", is_private=True),
    ]

    key_set = JsonWebKey.import_key_set({"keys": [k.as_dict(is_private=True) for k in keys]})
    print(f"Key set length: {len(key_set.keys)}")

    for k in key_set.keys:
        d = k.as_dict()
        print(f"  kty={d['kty']}  crv={d.get('crv', 'n/a')}")


# ---------------------------------------------------------------------------
# JWT – JSON Web Tokens
# ---------------------------------------------------------------------------

def demo_jwt_hs256():
    """JWT signed with HMAC-SHA256."""
    print("\n" + "=" * 60)
    print("JWT - HS256 (HMAC-SHA256)")
    print("=" * 60)

    key = OctKey.generate_key(256, is_private=True)
    now = int(time.time())

    payload = {
        "sub": "user-123",
        "name": "Alice",
        "iat": now,
        "exp": now + 3600,
        "iss": "authlib-demo",
        "aud": "myapp",
    }

    token = jwt.encode({"alg": "HS256"}, payload, key)
    print(f"Token (first 60): {token.decode()[:60]}...")

    claims = jwt.decode(token, key)
    claims.validate()
    print(f"Decoded sub:  {claims['sub']}")
    print(f"Decoded name: {claims['name']}")


def demo_jwt_hs384():
    """JWT signed with HMAC-SHA384."""
    print("\n" + "=" * 60)
    print("JWT - HS384 (HMAC-SHA384)")
    print("=" * 60)

    key = OctKey.generate_key(384, is_private=True)
    payload = {"sub": "hs384-user", "exp": int(time.time()) + 3600}

    token = jwt.encode({"alg": "HS384"}, payload, key)
    claims = jwt.decode(token, key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_hs512():
    """JWT signed with HMAC-SHA512."""
    print("\n" + "=" * 60)
    print("JWT - HS512 (HMAC-SHA512)")
    print("=" * 60)

    key = OctKey.generate_key(512, is_private=True)
    payload = {"sub": "hs512-user", "exp": int(time.time()) + 3600}

    token = jwt.encode({"alg": "HS512"}, payload, key)
    claims = jwt.decode(token, key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_rs256():
    """JWT signed with RSA-SHA256."""
    print("\n" + "=" * 60)
    print("JWT - RS256 (RSA-SHA256)")
    print("=" * 60)

    private_key = RSAKey.generate_key(2048, is_private=True)
    public_key = RSAKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "rs256-user", "role": "admin", "exp": int(time.time()) + 3600}

    token = jwt.encode({"alg": "RS256"}, payload, private_key)
    print(f"Token (first 60): {token.decode()[:60]}...")

    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Decoded sub:  {claims['sub']}")
    print(f"Decoded role: {claims['role']}")


def demo_jwt_rs384():
    """JWT signed with RSA-SHA384."""
    print("\n" + "=" * 60)
    print("JWT - RS384 (RSA-SHA384)")
    print("=" * 60)

    private_key = RSAKey.generate_key(2048, is_private=True)
    public_key = RSAKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "rs384-user", "exp": int(time.time()) + 3600}
    token = jwt.encode({"alg": "RS384"}, payload, private_key)
    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_rs512():
    """JWT signed with RSA-SHA512."""
    print("\n" + "=" * 60)
    print("JWT - RS512 (RSA-SHA512)")
    print("=" * 60)

    private_key = RSAKey.generate_key(2048, is_private=True)
    public_key = RSAKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "rs512-user", "exp": int(time.time()) + 3600}
    token = jwt.encode({"alg": "RS512"}, payload, private_key)
    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_ps256():
    """JWT signed with RSASSA-PSS SHA-256."""
    print("\n" + "=" * 60)
    print("JWT - PS256 (RSASSA-PSS SHA-256)")
    print("=" * 60)

    private_key = RSAKey.generate_key(2048, is_private=True)
    public_key = RSAKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "ps256-user", "exp": int(time.time()) + 3600}
    token = jwt.encode({"alg": "PS256"}, payload, private_key)
    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_es256():
    """JWT signed with ECDSA P-256."""
    print("\n" + "=" * 60)
    print("JWT - ES256 (ECDSA P-256)")
    print("=" * 60)

    private_key = ECKey.generate_key("P-256", is_private=True)
    public_key = ECKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "es256-user", "scope": "read write", "exp": int(time.time()) + 3600}

    token = jwt.encode({"alg": "ES256"}, payload, private_key)
    print(f"Token (first 60): {token.decode()[:60]}...")

    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Decoded sub:   {claims['sub']}")
    print(f"Decoded scope: {claims['scope']}")


def demo_jwt_es384():
    """JWT signed with ECDSA P-384."""
    print("\n" + "=" * 60)
    print("JWT - ES384 (ECDSA P-384)")
    print("=" * 60)

    private_key = ECKey.generate_key("P-384", is_private=True)
    public_key = ECKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "es384-user", "exp": int(time.time()) + 3600}
    token = jwt.encode({"alg": "ES384"}, payload, private_key)
    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_es512():
    """JWT signed with ECDSA P-521."""
    print("\n" + "=" * 60)
    print("JWT - ES512 (ECDSA P-521)")
    print("=" * 60)

    private_key = ECKey.generate_key("P-521", is_private=True)
    public_key = ECKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "es512-user", "exp": int(time.time()) + 3600}
    token = jwt.encode({"alg": "ES512"}, payload, private_key)
    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_eddsa():
    """JWT signed with EdDSA (Ed25519)."""
    print("\n" + "=" * 60)
    print("JWT - EdDSA (Ed25519)")
    print("=" * 60)

    private_key = OKPKey.generate_key("Ed25519", is_private=True)
    public_key = OKPKey.import_key(private_key.as_pem(is_private=False))

    payload = {"sub": "eddsa-user", "exp": int(time.time()) + 3600}
    token = jwt.encode({"alg": "EdDSA"}, payload, private_key)
    claims = jwt.decode(token, public_key)
    claims.validate()
    print(f"Token (first 60): {token.decode()[:60]}...")
    print(f"Decoded sub: {claims['sub']}")


def demo_jwt_claims_validation():
    """JWT claims validation (exp, iss, aud, nbf)."""
    print("\n" + "=" * 60)
    print("JWT - CLAIMS VALIDATION")
    print("=" * 60)

    key = OctKey.generate_key(256, is_private=True)
    now = int(time.time())

    # Valid token with full claims
    payload = {
        "sub": "validated-user",
        "iss": "https://auth.example.com",
        "aud": "https://api.example.com",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    token = jwt.encode({"alg": "HS256"}, payload, key)
    claims_options = {
        "iss": {"essential": True, "value": "https://auth.example.com"},
        "aud": {"essential": True, "values": ["https://api.example.com"]},
    }
    claims = jwt.decode(token, key, claims_options=claims_options)
    claims.validate(now=now, leeway=0)
    print(f"Full claims validation passed: sub={claims['sub']}")

    # Expired token
    expired_payload = {
        "sub": "expired-user",
        "exp": now - 60,
        "iss": "https://auth.example.com",
    }
    expired_token = jwt.encode({"alg": "HS256"}, expired_payload, key)
    try:
        c = jwt.decode(expired_token, key)
        c.validate()
        print("ERROR: expired token should have been rejected")
    except ExpiredTokenError:
        print("Expired token correctly rejected: ExpiredTokenError")

    # Missing claim
    no_exp_payload = {"sub": "no-exp-user"}
    no_exp_token = jwt.encode({"alg": "HS256"}, no_exp_payload, key)
    try:
        c = jwt.decode(no_exp_token, key)
        c.validate(leeway=0)
        # validate() does not enforce exp presence by default; just show decoded
        print(f"Token without exp decoded: sub={c['sub']}")
    except MissingClaimError as exc:
        print(f"Missing claim correctly rejected: {exc}")


# ---------------------------------------------------------------------------
# JWS – JSON Web Signature (low-level)
# ---------------------------------------------------------------------------

def demo_jws_compact():
    """Low-level JWS compact serialisation."""
    print("\n" + "=" * 60)
    print("JWS - COMPACT SERIALISATION")
    print("=" * 60)

    jws_obj = JsonWebSignature()

    # HS256
    key = OctKey.generate_key(256, is_private=True)
    payload = b"Authlib JWS compact payload"
    token = jws_obj.serialize_compact({"alg": "HS256"}, payload, key)
    print(f"HS256 token (first 60): {token.decode()[:60]}...")

    data = jws_obj.deserialize_compact(token, key)
    assert data["payload"] == payload
    print(f"Payload verified: {data['payload']}")


def demo_jws_json():
    """Low-level JWS JSON serialisation with multiple signatures."""
    print("\n" + "=" * 60)
    print("JWS - JSON SERIALISATION (MULTI-SIGNATURE)")
    print("=" * 60)

    jws_obj = JsonWebSignature()

    key_rsa = RSAKey.generate_key(2048, is_private=True)
    pub_rsa = RSAKey.import_key(key_rsa.as_pem(is_private=False))
    key_ec = ECKey.generate_key("P-256", is_private=True)
    pub_ec = ECKey.import_key(key_ec.as_pem(is_private=False))

    payload = b"Multi-signed JWS payload"

    # Callable selects the correct private key based on the protected header alg.
    # serialize_json captures `key` via closure so all _sign calls share one key;
    # a callable bypasses this by dispatching per-signature at call time.
    def sign_key(header, _payload):
        return key_rsa if header["alg"].startswith("RS") else key_ec

    token = jws_obj.serialize_json(
        [
            {"protected": {"alg": "RS256"}},
            {"protected": {"alg": "ES256"}},
        ],
        payload,
        sign_key,
    )
    print(f"Number of signatures: {len(token['signatures'])}")

    # Same callable pattern for verification: deserialize_json validates ALL
    # signatures and raises BadSignatureError if any fail, so each signature
    # must receive its matching public key.
    def verify_key(header, _payload):
        return pub_rsa if header["alg"].startswith("RS") else pub_ec

    data = jws_obj.deserialize_json(token, verify_key)
    assert data["payload"] == payload
    print(f"RS256 + ES256 multi-signature verified: OK")
    print(f"Payload: {data['payload']}")


# ---------------------------------------------------------------------------
# JWE – JSON Web Encryption (low-level)
# ---------------------------------------------------------------------------

def demo_jwe_rsa_oaep():
    """JWE with RSA-OAEP and AES-GCM."""
    print("\n" + "=" * 60)
    print("JWE - RSA-OAEP / A256GCM")
    print("=" * 60)

    jwe_obj = JsonWebEncryption()
    private_key = RSAKey.generate_key(2048, is_private=True)
    public_key = RSAKey.import_key(private_key.as_pem(is_private=False))

    plaintext = b"Secret message for RSA-OAEP JWE"
    token = jwe_obj.serialize_compact(
        {"alg": "RSA-OAEP", "enc": "A256GCM"}, plaintext, public_key
    )
    print(f"JWE token (first 60): {token.decode()[:60]}...")

    result = jwe_obj.deserialize_compact(token, private_key)
    assert result["payload"] == plaintext
    print(f"Decrypted: {result['payload']}")


def demo_jwe_aes_keywrap():
    """JWE with AES key-wrap (A256KW) and AES-CBC-HMAC."""
    print("\n" + "=" * 60)
    print("JWE - A256KW / A128CBC-HS256")
    print("=" * 60)

    jwe_obj = JsonWebEncryption()
    key = OctKey.generate_key(256, is_private=True)

    plaintext = b"AES key-wrap encrypted payload"
    token = jwe_obj.serialize_compact(
        {"alg": "A256KW", "enc": "A128CBC-HS256"}, plaintext, key
    )
    print(f"JWE token (first 60): {token.decode()[:60]}...")

    result = jwe_obj.deserialize_compact(token, key)
    assert result["payload"] == plaintext
    print(f"Decrypted: {result['payload']}")


def demo_jwe_ecdh_es():
    """JWE with ECDH-ES key agreement."""
    print("\n" + "=" * 60)
    print("JWE - ECDH-ES / A256GCM")
    print("=" * 60)

    jwe_obj = JsonWebEncryption()
    private_key = ECKey.generate_key("P-256", is_private=True)
    public_key = ECKey.import_key(private_key.as_pem(is_private=False))

    plaintext = b"ECDH-ES encrypted payload"
    token = jwe_obj.serialize_compact(
        {"alg": "ECDH-ES", "enc": "A256GCM"}, plaintext, public_key
    )
    print(f"JWE token (first 60): {token.decode()[:60]}...")

    result = jwe_obj.deserialize_compact(token, private_key)
    assert result["payload"] == plaintext
    print(f"Decrypted: {result['payload']}")


def demo_jwe_direct():
    """JWE with direct key agreement (dir)."""
    print("\n" + "=" * 60)
    print("JWE - DIRECT ENCRYPTION (dir) / A256GCM")
    print("=" * 60)

    jwe_obj = JsonWebEncryption()
    key = OctKey.generate_key(256, is_private=True)

    plaintext = b"Direct AES-GCM encrypted payload"
    token = jwe_obj.serialize_compact(
        {"alg": "dir", "enc": "A256GCM"}, plaintext, key
    )
    print(f"JWE token (first 60): {token.decode()[:60]}...")

    result = jwe_obj.deserialize_compact(token, key)
    assert result["payload"] == plaintext
    print(f"Decrypted: {result['payload']}")


def demo_jwe_aes_gcmkw():
    """JWE with AES-256-GCM key-wrap (A256GCMKW) and AES-GCM content encryption."""
    print("\n" + "=" * 60)
    print("JWE - A256GCMKW / A256GCM")
    print("=" * 60)

    jwe_obj = JsonWebEncryption()
    key = OctKey.generate_key(256, is_private=True)

    plaintext = b"AES-GCM key-wrap encrypted payload"
    token = jwe_obj.serialize_compact(
        {"alg": "A256GCMKW", "enc": "A256GCM"}, plaintext, key
    )
    print(f"JWE token (first 60): {token.decode()[:60]}...")

    result = jwe_obj.deserialize_compact(token, key)
    assert result["payload"] == plaintext
    print(f"Decrypted: {result['payload']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Run all Authlib demonstrations."""
    print("AUTHLIB LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # JWK key generation
    demo_jwk_oct()
    demo_jwk_rsa()
    demo_jwk_ec()
    demo_jwk_okp()
    demo_jwk_set()

    # JWT - HMAC algorithms
    demo_jwt_hs256()
    demo_jwt_hs384()
    demo_jwt_hs512()

    # JWT - RSA algorithms
    demo_jwt_rs256()
    demo_jwt_rs384()
    demo_jwt_rs512()
    demo_jwt_ps256()

    # JWT - EC algorithms
    demo_jwt_es256()
    demo_jwt_es384()
    demo_jwt_es512()

    # JWT - OKP
    demo_jwt_eddsa()

    # JWT claims validation
    demo_jwt_claims_validation()

    # JWS low-level
    demo_jws_compact()
    demo_jws_json()

    # JWE low-level
    demo_jwe_rsa_oaep()
    demo_jwe_aes_keywrap()
    demo_jwe_ecdh_es()
    demo_jwe_direct()
    demo_jwe_aes_gcmkw()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
