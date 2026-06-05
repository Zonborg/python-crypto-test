"""
Comprehensive demonstration of the PassLib library.
Covers password hashing schemes including bcrypt, argon2, scrypt, pbkdf2,
sha256/512_crypt, des_crypt, and CryptContext management.
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="passlib")

from passlib.hash import (
    bcrypt, bcrypt_sha256, argon2, scrypt as passlib_scrypt,
    pbkdf2_sha256, pbkdf2_sha512, pbkdf2_sha1,
    sha256_crypt, sha512_crypt, des_crypt, md5_crypt,
    ldap_salted_sha256, ldap_salted_sha512,
    apr_md5_crypt, django_pbkdf2_sha256,
    hex_sha256, hex_sha512
)
from passlib.context import CryptContext
from passlib.totp import TOTP


def demo_bcrypt():
    """Bcrypt password hashing via passlib."""
    print("\n" + "=" * 60)
    print("BCRYPT PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"

    try:
        # Hash with default rounds (12)
        hashed = bcrypt.hash(password)
        print(f"Password:  {password}")
        print(f"Hash:      {hashed}")
        print(f"Rounds:    {bcrypt.default_rounds}")

        # Verify
        assert bcrypt.verify(password, hashed)
        assert not bcrypt.verify("wrong-password", hashed)
        print("Verify correct:   PASSED")
        print("Verify incorrect: PASSED (rejected)")

        # Custom rounds
        hashed_custom = bcrypt.using(rounds=14).hash(password)
        print(f"Hash (14 rounds): {hashed_custom}")
    except (ValueError, AttributeError) as e:
        # passlib has known incompatibility with bcrypt >= 4.1
        print(f"passlib/bcrypt version incompatibility: {e}")
        print("Using direct bcrypt library as fallback:")
        import bcrypt as _bcrypt
        salt = _bcrypt.gensalt(rounds=12)
        hashed = _bcrypt.hashpw(password.encode(), salt)
        print(f"Password:  {password}")
        print(f"Hash:      {hashed.decode()}")
        assert _bcrypt.checkpw(password.encode(), hashed)
        print("Verify correct:   PASSED")


def demo_bcrypt_sha256():
    """Bcrypt-SHA256 password hashing (handles passwords > 72 bytes)."""
    print("\n" + "=" * 60)
    print("BCRYPT-SHA256 PASSWORD HASHING")
    print("=" * 60)

    password = "a" * 60  # Safe length for bcrypt

    try:
        hashed = bcrypt_sha256.hash(password)
        assert bcrypt_sha256.verify(password, hashed)
        print(f"Password length: {len(password)}")
        print(f"Hash:           {hashed}")
        print("Verification:   PASSED")
    except (ValueError, AttributeError) as e:
        # passlib has known incompatibility with bcrypt >= 4.1
        print(f"passlib/bcrypt version incompatibility: {e}")
        print("bcrypt_sha256 demo skipped (passlib bug with bcrypt >= 4.1)")
        print("The bcrypt_sha256 scheme pre-hashes with SHA-256 to handle long passwords")


def demo_argon2():
    """Argon2 password hashing."""
    print("\n" + "=" * 60)
    print("ARGON2 PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"

    # Default Argon2id
    hashed = argon2.hash(password)
    assert argon2.verify(password, hashed)
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")
    print("Verification: PASSED")

    # Custom parameters
    hashed_custom = argon2.using(
        rounds=4,
        memory_cost=65536,
        parallelism=2
    ).hash(password)
    print(f"Custom hash: {hashed_custom}")


def demo_scrypt():
    """Scrypt password hashing."""
    print("\n" + "=" * 60)
    print("SCRYPT PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"
    hashed = passlib_scrypt.hash(password)

    assert passlib_scrypt.verify(password, hashed)
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")
    print("Verification: PASSED")


def demo_pbkdf2():
    """PBKDF2 password hashing variants."""
    print("\n" + "=" * 60)
    print("PBKDF2 PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"

    # PBKDF2-SHA256
    hashed_256 = pbkdf2_sha256.hash(password)
    assert pbkdf2_sha256.verify(password, hashed_256)
    print(f"PBKDF2-SHA256: {hashed_256}")

    # PBKDF2-SHA512
    hashed_512 = pbkdf2_sha512.hash(password)
    assert pbkdf2_sha512.verify(password, hashed_512)
    print(f"PBKDF2-SHA512: {hashed_512}")

    # Custom rounds
    hashed_custom = pbkdf2_sha256.using(rounds=600000).hash(password)
    print(f"PBKDF2 (600k): {hashed_custom}")
    print("Verification: PASSED")


def demo_sha_crypt():
    """SHA-256/512 crypt hashing (Unix)."""
    print("\n" + "=" * 60)
    print("SHA-CRYPT PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"

    # SHA-256 crypt
    hashed_256 = sha256_crypt.hash(password)
    assert sha256_crypt.verify(password, hashed_256)
    print(f"SHA256-crypt: {hashed_256}")

    # SHA-512 crypt
    hashed_512 = sha512_crypt.hash(password)
    assert sha512_crypt.verify(password, hashed_512)
    print(f"SHA512-crypt: {hashed_512}")
    print("Verification: PASSED")


def demo_legacy_hashes():
    """Legacy/insecure hash schemes (for migration testing)."""
    print("\n" + "=" * 60)
    print("LEGACY HASH SCHEMES (INSECURE)")
    print("=" * 60)

    password = "my-secret-password"

    # DES crypt
    hashed_des = des_crypt.hash(password)
    assert des_crypt.verify(password, hashed_des)
    print(f"DES-crypt:  {hashed_des}")

    # MD5 crypt
    hashed_md5 = md5_crypt.hash(password)
    assert md5_crypt.verify(password, hashed_md5)
    print(f"MD5-crypt:  {hashed_md5}")

    # APR MD5 (Apache)
    hashed_apr = apr_md5_crypt.hash(password)
    assert apr_md5_crypt.verify(password, hashed_apr)
    print(f"APR-MD5:    {hashed_apr}")
    print("Verification: PASSED (all legacy schemes)")


def demo_ldap_hashes():
    """LDAP-style password hashes."""
    print("\n" + "=" * 60)
    print("LDAP PASSWORD HASHES")
    print("=" * 60)

    password = "my-secret-password"

    hashed_256 = ldap_salted_sha256.hash(password)
    assert ldap_salted_sha256.verify(password, hashed_256)
    print(f"LDAP SSHA256: {hashed_256}")

    hashed_512 = ldap_salted_sha512.hash(password)
    assert ldap_salted_sha512.verify(password, hashed_512)
    print(f"LDAP SSHA512: {hashed_512}")
    print("Verification: PASSED")


def demo_django_hashes():
    """Django-compatible password hashes."""
    print("\n" + "=" * 60)
    print("DJANGO PASSWORD HASHES")
    print("=" * 60)

    password = "my-secret-password"

    hashed = django_pbkdf2_sha256.hash(password)
    assert django_pbkdf2_sha256.verify(password, hashed)
    print(f"Django PBKDF2: {hashed}")
    print("Verification:  PASSED")


def demo_crypt_context():
    """CryptContext for managing multiple hash schemes."""
    print("\n" + "=" * 60)
    print("CRYPTCONTEXT MANAGEMENT")
    print("=" * 60)

    # Create a context with scheme migration support
    ctx = CryptContext(
        schemes=["argon2", "pbkdf2_sha256", "sha256_crypt"],
        default="argon2",
        pbkdf2_sha256__rounds=300000,
        deprecated=["pbkdf2_sha256"],
    )

    password = "my-secret-password"

    # Hash with default scheme (argon2)
    hashed = ctx.hash(password)
    print(f"Default hash (argon2): {hashed[:50]}...")

    # Verify
    assert ctx.verify(password, hashed)
    print("Verify: PASSED")

    # Check if hash needs update (deprecated scheme)
    old_hash = pbkdf2_sha256.hash(password)
    needs_update = ctx.needs_update(old_hash)
    print(f"Old PBKDF2 hash needs update: {needs_update}")

    # Verify and update in one step
    valid, new_hash = ctx.verify_and_update(password, old_hash)
    print(f"Verify old hash: {valid}")
    print(f"New hash provided: {new_hash is not None}")


def demo_crypt_context_policy():
    """CryptContext with policy configuration."""
    print("\n" + "=" * 60)
    print("CRYPTCONTEXT POLICY CONFIGURATION")
    print("=" * 60)

    # Admin context with stricter requirements
    admin_ctx = CryptContext(
        schemes=["argon2", "pbkdf2_sha256"],
        default="argon2",
        argon2__rounds=8,
        argon2__memory_cost=102400,
        pbkdf2_sha256__rounds=600000,
    )

    # User context with standard requirements
    user_ctx = CryptContext(
        schemes=["argon2", "pbkdf2_sha256"],
        default="argon2",
        argon2__rounds=3,
        argon2__memory_cost=65536,
        pbkdf2_sha256__rounds=300000,
    )

    password = "my-secret-password"
    admin_hash = admin_ctx.hash(password)
    user_hash = user_ctx.hash(password)

    print(f"Admin hash: {admin_hash[:50]}...")
    print(f"User hash:  {user_hash[:50]}...")
    print(f"Admin verify: {admin_ctx.verify(password, admin_hash)}")
    print(f"User verify:  {user_ctx.verify(password, user_hash)}")


def demo_totp():
    """TOTP (Time-based One-Time Password)."""
    print("\n" + "=" * 60)
    print("TOTP (TIME-BASED ONE-TIME PASSWORD)")
    print("=" * 60)

    # Generate a new TOTP key
    totp_instance = TOTP(new=True, digits=6, alg="sha1", period=30)

    # Generate token
    token = totp_instance.generate()

    # Verify
    match = totp_instance.match(token.token)
    print(f"TOTP token: {token.token}")
    print(f"Match: {match is not None}")

    # Generate provisioning URI
    uri = totp_instance.to_uri(issuer="DemoApp", label="user@example.com")
    print(f"Provisioning URI: {uri[:60]}...")


def demo_hash_identification():
    """Identify hash format from hash string."""
    print("\n" + "=" * 60)
    print("HASH IDENTIFICATION")
    print("=" * 60)

    password = "test-password"

    hashes_to_identify = {
        "sha256_crypt": sha256_crypt.hash(password),
        "sha512_crypt": sha512_crypt.hash(password),
        "pbkdf2_sha256": pbkdf2_sha256.hash(password),
    }

    ctx = CryptContext(schemes=["sha256_crypt", "sha512_crypt", "pbkdf2_sha256"])

    for name, h in hashes_to_identify.items():
        identified = ctx.identify(h)
        print(f"  {name:15s} -> identified as: {identified}")


def main():
    """Run all PassLib demonstrations."""
    print("PASSLIB LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Modern password hashing
    demo_bcrypt()
    demo_bcrypt_sha256()
    demo_argon2()
    demo_scrypt()
    demo_pbkdf2()
    demo_sha_crypt()

    # Legacy schemes
    demo_legacy_hashes()
    demo_ldap_hashes()
    demo_django_hashes()

    # CryptContext management
    demo_crypt_context()
    demo_crypt_context_policy()

    # TOTP
    demo_totp()

    # Hash identification
    demo_hash_identification()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
