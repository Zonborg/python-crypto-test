"""
Comprehensive demonstration of the jwcrypto library.
Covers JWK (JSON Web Key) generation and management, JWS (JSON Web Signature),
JWE (JSON Web Encryption), JWT (JSON Web Token), and JWKS (key sets).
"""

import json
import time
from jwcrypto import jwk, jws, jwe, jwt
from jwcrypto.common import json_encode, json_decode


# ---------------------------------------------------------------------------
# JWK – Key Generation
# ---------------------------------------------------------------------------

def demo_jwk_rsa():
    """Generate and inspect an RSA JWK."""
    print("\n" + "=" * 60)
    print("JWK - RSA KEY GENERATION")
    print("=" * 60)

    key = jwk.JWK.generate(kty="RSA", size=2048)
    public_key = key.export_public(as_dict=True)

    print(f"Key type:  {key.get('kty')}")
    print(f"Key ID:    {key.get('kid')}")
    print(f"Public 'n' (first 40 chars): {public_key['n'][:40]}...")

    # Round-trip: export private, re-import
    exported = key.export(private_key=True)
    imported = jwk.JWK.from_json(exported)
    assert imported.export_public() == key.export_public()
    print("Private key export/import round-trip: OK")


def demo_jwk_ec():
    """Generate EC JWKs for P-256, P-384, and P-521."""
    print("\n" + "=" * 60)
    print("JWK - EC KEY GENERATION (P-256 / P-384 / P-521)")
    print("=" * 60)

    for curve in ("P-256", "P-384", "P-521"):
        key = jwk.JWK.generate(kty="EC", crv=curve)
        pub = key.export_public(as_dict=True)
        print(f"Curve: {curve}  x={pub['x'][:20]}...  y={pub['y'][:20]}...")


def demo_jwk_okp():
    """Generate OKP (Ed25519 / X25519) JWKs."""
    print("\n" + "=" * 60)
    print("JWK - OKP KEY GENERATION (Ed25519 / X25519)")
    print("=" * 60)

    for crv in ("Ed25519", "X25519"):
        key = jwk.JWK.generate(kty="OKP", crv=crv)
        pub = key.export_public(as_dict=True)
        print(f"Curve: {crv}  x={pub['x'][:30]}...")


def demo_jwk_symmetric():
    """Generate symmetric (oct) JWKs of various sizes."""
    print("\n" + "=" * 60)
    print("JWK - SYMMETRIC (oct) KEY GENERATION")
    print("=" * 60)

    for bits in (128, 192, 256, 384, 512):
        key = jwk.JWK.generate(kty="oct", size=bits)
        exported = json_decode(key.export())
        print(f"Size: {bits}-bit  k={exported['k'][:20]}...")


def demo_jwks():
    """Build and query a JWK Set."""
    print("\n" + "=" * 60)
    print("JWKS - JSON WEB KEY SET")
    print("=" * 60)

    keyset = jwk.JWKSet()

    for crv in ("P-256", "P-384"):
        k = jwk.JWK.generate(kty="EC", crv=crv)
        keyset.add(k)

    rsa_key = jwk.JWK.generate(kty="RSA", size=2048, kid="demo-rsa-key")
    keyset.add(rsa_key)

    exported = keyset.export(private_keys=False)
    parsed = json.loads(exported)
    print(f"Key set contains {len(parsed['keys'])} public keys")
    for entry in parsed["keys"]:
        print(f"  kty={entry['kty']}  crv={entry.get('crv', 'n/a')}  kid={entry.get('kid', 'n/a')[:12]}...")

    # Look up by key ID
    rsa_kid = rsa_key.get('kid')
    found = keyset.get_key(rsa_kid)
    assert found is not None
    print(f"Looked up RSA key by kid: {rsa_kid}  OK")


# ---------------------------------------------------------------------------
# JWS – JSON Web Signature
# ---------------------------------------------------------------------------

def demo_jws_hmac():
    """JWS compact serialisation with HS256."""
    print("\n" + "=" * 60)
    print("JWS - HMAC-SHA256 (HS256) COMPACT SERIALISATION")
    print("=" * 60)

    key = jwk.JWK.generate(kty="oct", size=256)
    payload = b"Hello, JWS with HMAC!"

    token = jws.JWS(payload)
    token.add_signature(key, alg="HS256", protected=json_encode({"alg": "HS256"}))
    compact = token.serialize(compact=True)
    print(f"Compact JWS (first 60): {compact[:60]}...")

    # Verify
    verified = jws.JWS()
    verified.deserialize(compact, key, "HS256")
    assert verified.payload == payload
    print(f"Payload verified: {verified.payload}")


def demo_jws_rsa():
    """JWS compact serialisation with RS256."""
    print("\n" + "=" * 60)
    print("JWS - RSA-SHA256 (RS256) COMPACT SERIALISATION")
    print("=" * 60)

    key = jwk.JWK.generate(kty="RSA", size=2048)
    public_key = jwk.JWK.from_json(key.export_public())

    payload = b"Signed with RSA-SHA256"

    token = jws.JWS(payload)
    token.add_signature(key, alg="RS256", protected=json_encode({"alg": "RS256"}))
    compact = token.serialize(compact=True)
    print(f"Compact JWS (first 60): {compact[:60]}...")

    verified = jws.JWS()
    verified.deserialize(compact, public_key, "RS256")
    assert verified.payload == payload
    print(f"Payload verified: {verified.payload}")


def demo_jws_ec():
    """JWS compact serialisation with ES256."""
    print("\n" + "=" * 60)
    print("JWS - ECDSA P-256 (ES256) COMPACT SERIALISATION")
    print("=" * 60)

    key = jwk.JWK.generate(kty="EC", crv="P-256")
    public_key = jwk.JWK.from_json(key.export_public())

    payload = b"Signed with ECDSA P-256"

    token = jws.JWS(payload)
    token.add_signature(key, alg="ES256", protected=json_encode({"alg": "ES256"}))
    compact = token.serialize(compact=True)
    print(f"Compact JWS (first 60): {compact[:60]}...")

    verified = jws.JWS()
    verified.deserialize(compact, public_key, "ES256")
    assert verified.payload == payload
    print(f"Payload verified: {verified.payload}")


def demo_jws_eddsa():
    """JWS compact serialisation with EdDSA (Ed25519)."""
    print("\n" + "=" * 60)
    print("JWS - EdDSA (Ed25519) COMPACT SERIALISATION")
    print("=" * 60)

    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    public_key = jwk.JWK.from_json(key.export_public())

    payload = b"Signed with EdDSA Ed25519"

    token = jws.JWS(payload)
    token.add_signature(key, alg="EdDSA", protected=json_encode({"alg": "EdDSA"}))
    compact = token.serialize(compact=True)
    print(f"Compact JWS (first 60): {compact[:60]}...")

    verified = jws.JWS()
    verified.deserialize(compact, public_key, "EdDSA")
    assert verified.payload == payload
    print(f"Payload verified: {verified.payload}")


def demo_jws_json_serialisation():
    """JWS full JSON serialisation (multiple signatures)."""
    print("\n" + "=" * 60)
    print("JWS - FULL JSON SERIALISATION (MULTI-SIGNATURE)")
    print("=" * 60)

    key_rsa = jwk.JWK.generate(kty="RSA", size=2048)
    key_ec = jwk.JWK.generate(kty="EC", crv="P-256")

    payload = b"Multi-signed payload"

    token = jws.JWS(payload)
    token.add_signature(key_rsa, alg="RS256", protected=json_encode({"alg": "RS256"}))
    token.add_signature(key_ec, alg="ES256", protected=json_encode({"alg": "ES256"}))

    serialized = token.serialize()
    parsed = json.loads(serialized)
    print(f"Number of signatures: {len(parsed['signatures'])}")
    for sig in parsed["signatures"]:
        hdr = json.loads(
            __import__("base64").urlsafe_b64decode(sig["protected"] + "==").decode()
        )
        print(f"  Algorithm: {hdr['alg']}")

    # Verify each signature independently
    for key, alg in [(key_rsa, "RS256"), (key_ec, "ES256")]:
        v = jws.JWS()
        v.deserialize(serialized, jwk.JWK.from_json(key.export_public()), alg)
        assert v.payload == payload
    print("Both signatures verified: OK")


# ---------------------------------------------------------------------------
# JWE – JSON Web Encryption
# ---------------------------------------------------------------------------

def demo_jwe_rsa_oaep():
    """JWE with RSA-OAEP key wrap and AES-GCM content encryption."""
    print("\n" + "=" * 60)
    print("JWE - RSA-OAEP / A256GCM")
    print("=" * 60)

    key = jwk.JWK.generate(kty="RSA", size=2048)
    public_key = jwk.JWK.from_json(key.export_public())

    plaintext = b"Secret message encrypted with RSA-OAEP and AES-256-GCM"

    protected_header = json_encode({
        "alg": "RSA-OAEP",
        "enc": "A256GCM",
    })

    token = jwe.JWE(plaintext, protected=protected_header)
    token.add_recipient(public_key)
    compact = token.serialize(compact=True)
    print(f"Compact JWE (first 60): {compact[:60]}...")

    decrypted = jwe.JWE()
    decrypted.deserialize(compact, key)
    assert decrypted.payload == plaintext
    print(f"Decrypted: {decrypted.payload}")


def demo_jwe_aes_keywrap():
    """JWE with AES key-wrap (A256KW) and AES-CBC-HMAC content encryption."""
    print("\n" + "=" * 60)
    print("JWE - A256KW / A256CBC-HS512")
    print("=" * 60)

    key = jwk.JWK.generate(kty="oct", size=256)

    plaintext = b"AES key-wrap with A256KW and A256CBC-HS512"

    protected_header = json_encode({
        "alg": "A256KW",
        "enc": "A256CBC-HS512",
    })

    token = jwe.JWE(plaintext, protected=protected_header)
    token.add_recipient(key)
    compact = token.serialize(compact=True)
    print(f"Compact JWE (first 60): {compact[:60]}...")

    decrypted = jwe.JWE()
    decrypted.deserialize(compact, key)
    assert decrypted.payload == plaintext
    print(f"Decrypted: {decrypted.payload}")


def demo_jwe_ecdh_es():
    """JWE with ECDH-ES key agreement and AES-GCM content encryption."""
    print("\n" + "=" * 60)
    print("JWE - ECDH-ES / A128GCM")
    print("=" * 60)

    key = jwk.JWK.generate(kty="EC", crv="P-256")
    public_key = jwk.JWK.from_json(key.export_public())

    plaintext = b"ECDH-ES key agreement message"

    protected_header = json_encode({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
    })

    token = jwe.JWE(plaintext, protected=protected_header)
    token.add_recipient(public_key)
    compact = token.serialize(compact=True)
    print(f"Compact JWE (first 60): {compact[:60]}...")

    decrypted = jwe.JWE()
    decrypted.deserialize(compact, key)
    assert decrypted.payload == plaintext
    print(f"Decrypted: {decrypted.payload}")


def demo_jwe_direct():
    """JWE with direct key agreement (dir) and AES-GCM."""
    print("\n" + "=" * 60)
    print("JWE - DIRECT KEY ENCRYPTION (dir) / A256GCM")
    print("=" * 60)

    key = jwk.JWK.generate(kty="oct", size=256)

    plaintext = b"Direct encryption with AES-256-GCM"

    protected_header = json_encode({
        "alg": "dir",
        "enc": "A256GCM",
    })

    token = jwe.JWE(plaintext, protected=protected_header)
    token.add_recipient(key)
    compact = token.serialize(compact=True)
    print(f"Compact JWE (first 60): {compact[:60]}...")

    decrypted = jwe.JWE()
    decrypted.deserialize(compact, key)
    assert decrypted.payload == plaintext
    print(f"Decrypted: {decrypted.payload}")


# ---------------------------------------------------------------------------
# JWT – JSON Web Token
# ---------------------------------------------------------------------------

def demo_jwt_hs256():
    """JWT signed with HS256."""
    print("\n" + "=" * 60)
    print("JWT - HS256 SIGNED TOKEN")
    print("=" * 60)

    key = jwk.JWK.generate(kty="oct", size=256)
    now = int(time.time())

    claims = {
        "sub": "user-42",
        "name": "Alice",
        "iat": now,
        "exp": now + 3600,
        "iss": "jwcrypto-demo",
    }

    token = jwt.JWT(header={"alg": "HS256"}, claims=claims)
    token.make_signed_token(key)
    compact = token.serialize()
    print(f"JWT (first 60): {compact[:60]}...")

    verified = jwt.JWT(key=key, jwt=compact)
    decoded = json.loads(verified.claims)
    print(f"Decoded sub:  {decoded['sub']}")
    print(f"Decoded name: {decoded['name']}")


def demo_jwt_rs256():
    """JWT signed with RS256."""
    print("\n" + "=" * 60)
    print("JWT - RS256 SIGNED TOKEN")
    print("=" * 60)

    key = jwk.JWK.generate(kty="RSA", size=2048)
    public_key = jwk.JWK.from_json(key.export_public())
    now = int(time.time())

    claims = {"sub": "rs256-user", "role": "admin", "exp": now + 3600}

    token = jwt.JWT(header={"alg": "RS256"}, claims=claims)
    token.make_signed_token(key)
    compact = token.serialize()
    print(f"JWT (first 60): {compact[:60]}...")

    verified = jwt.JWT(key=public_key, jwt=compact)
    decoded = json.loads(verified.claims)
    print(f"Decoded sub:  {decoded['sub']}")
    print(f"Decoded role: {decoded['role']}")


def demo_jwt_es256():
    """JWT signed with ES256."""
    print("\n" + "=" * 60)
    print("JWT - ES256 SIGNED TOKEN")
    print("=" * 60)

    key = jwk.JWK.generate(kty="EC", crv="P-256")
    public_key = jwk.JWK.from_json(key.export_public())
    now = int(time.time())

    claims = {"sub": "es256-user", "scope": "read write", "exp": now + 3600}

    token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
    token.make_signed_token(key)
    compact = token.serialize()
    print(f"JWT (first 60): {compact[:60]}...")

    verified = jwt.JWT(key=public_key, jwt=compact)
    decoded = json.loads(verified.claims)
    print(f"Decoded sub:   {decoded['sub']}")
    print(f"Decoded scope: {decoded['scope']}")


def demo_jwt_encrypted():
    """Nested JWT: signed with ES256 then encrypted with RSA-OAEP."""
    print("\n" + "=" * 60)
    print("JWT - NESTED (SIGNED + ENCRYPTED)")
    print("=" * 60)

    sign_key = jwk.JWK.generate(kty="EC", crv="P-256", use="sig")
    enc_key = jwk.JWK.generate(kty="RSA", size=2048, use="enc")
    enc_pub = jwk.JWK.from_json(enc_key.export_public())
    now = int(time.time())

    claims = {"sub": "nested-jwt-user", "exp": now + 3600}

    # Sign
    inner = jwt.JWT(header={"alg": "ES256"}, claims=claims)
    inner.make_signed_token(sign_key)

    # Encrypt the signed token
    outer = jwt.JWT(
        header={"alg": "RSA-OAEP", "enc": "A256GCM", "cty": "JWT"},
        claims=inner.serialize(),
    )
    outer.make_encrypted_token(enc_pub)
    compact = outer.serialize()
    print(f"Nested JWT (first 60): {compact[:60]}...")

    # Decrypt then verify
    decrypted_outer = jwt.JWT(key=enc_key, jwt=compact)
    inner_jwt_str = decrypted_outer.claims  # this is the signed inner JWT string
    verified_inner = jwt.JWT(
        key=jwk.JWK.from_json(sign_key.export_public()),
        jwt=json.loads(inner_jwt_str) if inner_jwt_str.startswith("{") else inner_jwt_str,
    )
    decoded = json.loads(verified_inner.claims)
    print(f"Decoded sub: {decoded['sub']}")
    print("Nested JWT decrypt + verify: OK")


def demo_jwt_claims_check():
    """JWT with expiry and issuer claims validation."""
    print("\n" + "=" * 60)
    print("JWT - CLAIMS VALIDATION (exp / iss)")
    print("=" * 60)

    key = jwk.JWK.generate(kty="oct", size=256)
    now = int(time.time())

    # Valid token
    claims = {
        "sub": "claims-user",
        "iss": "trusted-issuer",
        "exp": now + 3600,
        "iat": now,
    }
    token = jwt.JWT(header={"alg": "HS256"}, claims=claims)
    token.make_signed_token(key)
    compact = token.serialize()

    check_claims = {"iss": "trusted-issuer", "exp": None}
    verified = jwt.JWT(key=key, jwt=compact, check_claims=check_claims)
    decoded = json.loads(verified.claims)
    print(f"Claims validation passed: sub={decoded['sub']}, iss={decoded['iss']}")

    # Expired token — must be > 60 s in the past to exceed jwcrypto's default leeway
    expired_claims = {"sub": "expired-user", "exp": now - 120, "iss": "trusted-issuer"}
    expired_token = jwt.JWT(header={"alg": "HS256"}, claims=expired_claims)
    expired_token.make_signed_token(key)
    try:
        jwt.JWT(key=key, jwt=expired_token.serialize(), check_claims={"exp": None})
        print("ERROR: expired token should have been rejected")
    except Exception as exc:
        print(f"Expired token correctly rejected: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Run all jwcrypto demonstrations."""
    print("JWCRYPTO LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # JWK key generation
    demo_jwk_rsa()
    demo_jwk_ec()
    demo_jwk_okp()
    demo_jwk_symmetric()
    demo_jwks()

    # JWS
    demo_jws_hmac()
    demo_jws_rsa()
    demo_jws_ec()
    demo_jws_eddsa()
    demo_jws_json_serialisation()

    # JWE
    demo_jwe_rsa_oaep()
    demo_jwe_aes_keywrap()
    demo_jwe_ecdh_es()
    demo_jwe_direct()

    # JWT
    demo_jwt_hs256()
    demo_jwt_rs256()
    demo_jwt_es256()
    demo_jwt_encrypted()
    demo_jwt_claims_check()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
