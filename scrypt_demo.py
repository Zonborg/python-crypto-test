"""
Comprehensive demonstration of the scrypt key derivation function.
Covers the hashlib.scrypt interface, passlib scrypt, and
direct usage patterns for password hashing and key derivation.
"""

import hashlib
import os
import time
import binascii


def demo_basic_scrypt():
    """Basic scrypt key derivation."""
    print("\n" + "=" * 60)
    print("BASIC SCRYPT KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = os.urandom(16)

    # Standard parameters: N=2^14, r=8, p=1
    derived_key = hashlib.scrypt(
        password,
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )

    print(f"Password:    {password}")
    print(f"Salt:        {salt.hex()}")
    print(f"Parameters:  N=16384, r=8, p=1")
    print(f"Key length:  32 bytes")
    print(f"Derived key: {derived_key.hex()}")


def demo_scrypt_parameter_variations():
    """Scrypt with various parameter combinations."""
    print("\n" + "=" * 60)
    print("SCRYPT PARAMETER VARIATIONS")
    print("=" * 60)

    password = b"test-password"
    salt = os.urandom(16)

    params = [
        {"n": 2**14, "r": 8, "p": 1, "desc": "Standard (N=16384, r=8, p=1)"},
        {"n": 2**15, "r": 8, "p": 1, "desc": "Higher N (N=32768, r=8, p=1)"},
        {"n": 2**14, "r": 8, "p": 2, "desc": "Higher p (N=16384, r=8, p=2)"},
        {"n": 2**14, "r": 16, "p": 1, "desc": "Higher r (N=16384, r=16, p=1)"},
        {"n": 2**20, "r": 8, "p": 1, "desc": "Very high N (N=1048576, r=8, p=1)"},
    ]

    for param in params:
        start = time.time()
        try:
            key = hashlib.scrypt(
                password, salt=salt,
                n=param["n"], r=param["r"], p=param["p"],
                dklen=32
            )
            elapsed = time.time() - start
            print(f"  {param['desc']:45s}: {key.hex()[:20]}... ({elapsed:.3f}s)")
        except (ValueError, MemoryError) as e:
            print(f"  {param['desc']:45s}: SKIPPED ({e})")


def demo_scrypt_key_lengths():
    """Scrypt with different output key lengths."""
    print("\n" + "=" * 60)
    print("SCRYPT OUTPUT KEY LENGTHS")
    print("=" * 60)

    password = b"test-password"
    salt = os.urandom(16)

    key_lengths = [16, 32, 48, 64, 128]

    for dklen in key_lengths:
        key = hashlib.scrypt(
            password, salt=salt,
            n=2**14, r=8, p=1,
            dklen=dklen
        )
        print(f"  dklen={dklen:3d}: {key.hex()[:50]}{'...' if dklen > 25 else ''}")


def demo_scrypt_password_hashing():
    """Using scrypt for password hashing and verification."""
    print("\n" + "=" * 60)
    print("SCRYPT PASSWORD HASHING")
    print("=" * 60)

    password = b"user-password-123"
    salt = os.urandom(32)

    # Derive key
    n, r, p = 2**14, 8, 1
    key = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=32)

    # Store as: salt$n$r$p$key (simplified format)
    stored_hash = f"{salt.hex()}${n}${r}${p}${key.hex()}"
    print(f"Password:    {password}")
    print(f"Stored hash: {stored_hash[:60]}...")

    # Verification
    parts = stored_hash.split("$")
    v_salt = bytes.fromhex(parts[0])
    v_n, v_r, v_p = int(parts[1]), int(parts[2]), int(parts[3])
    v_expected_key = bytes.fromhex(parts[4])

    v_derived = hashlib.scrypt(password, salt=v_salt, n=v_n, r=v_r, p=v_p, dklen=32)

    # Constant-time comparison
    import hmac
    is_valid = hmac.compare_digest(v_derived, v_expected_key)
    print(f"Verification: {'PASSED' if is_valid else 'FAILED'}")

    # Wrong password
    wrong_derived = hashlib.scrypt(b"wrong-pass", salt=v_salt, n=v_n, r=v_r, p=v_p, dklen=32)
    is_invalid = hmac.compare_digest(wrong_derived, v_expected_key)
    print(f"Wrong password: {'REJECTED' if not is_invalid else 'ACCEPTED (ERROR)'}")


def demo_scrypt_for_encryption_key():
    """Deriving encryption keys from passwords using scrypt."""
    print("\n" + "=" * 60)
    print("SCRYPT FOR ENCRYPTION KEY DERIVATION")
    print("=" * 60)

    password = b"encryption-password"
    salt = os.urandom(16)

    # Derive a 256-bit key for AES-256
    aes_key = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    print(f"AES-256 key: {aes_key.hex()}")

    # Derive a 512-bit key (split into encryption key + HMAC key)
    combined_key = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=64)
    enc_key = combined_key[:32]
    mac_key = combined_key[32:]
    print(f"Encryption key: {enc_key.hex()}")
    print(f"HMAC key:       {mac_key.hex()}")

    # Derive key for ChaCha20
    chacha_key = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    print(f"ChaCha20 key:   {chacha_key.hex()}")


def demo_scrypt_salt_importance():
    """Demonstrate importance of unique salts."""
    print("\n" + "=" * 60)
    print("SALT UNIQUENESS DEMONSTRATION")
    print("=" * 60)

    password = b"same-password"

    # Same password, different salts = different keys
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)

    key1 = hashlib.scrypt(password, salt=salt1, n=2**14, r=8, p=1, dklen=32)
    key2 = hashlib.scrypt(password, salt=salt2, n=2**14, r=8, p=1, dklen=32)

    print(f"Salt 1: {salt1.hex()}")
    print(f"Key 1:  {key1.hex()}")
    print(f"Salt 2: {salt2.hex()}")
    print(f"Key 2:  {key2.hex()}")
    print(f"Keys differ: {key1 != key2}")

    # Same password, same salt = same key (deterministic)
    key1_repeat = hashlib.scrypt(password, salt=salt1, n=2**14, r=8, p=1, dklen=32)
    print(f"Same salt reproduces key: {key1 == key1_repeat}")


def demo_scrypt_timing():
    """Measure scrypt computation time with different parameters."""
    print("\n" + "=" * 60)
    print("SCRYPT TIMING BENCHMARKS")
    print("=" * 60)

    password = b"benchmark-password"
    salt = os.urandom(16)

    benchmarks = [
        (2**10, 8, 1, "Light (N=1024)"),
        (2**12, 8, 1, "Medium-light (N=4096)"),
        (2**14, 8, 1, "Standard (N=16384)"),
    ]

    for n, r, p, desc in benchmarks:
        start = time.time()
        hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=32)
        elapsed = time.time() - start
        mem_estimate = 128 * r * n / (1024 * 1024)
        print(f"  {desc:25s}: {elapsed:.4f}s (est. {mem_estimate:.1f} MB memory)")


def demo_scrypt_multiple_keys():
    """Derive multiple independent keys from one password."""
    print("\n" + "=" * 60)
    print("MULTIPLE KEY DERIVATION")
    print("=" * 60)

    password = b"master-password"

    # Use different salts/info for different purposes
    purposes = ["encryption", "authentication", "signing", "storage"]

    for purpose in purposes:
        # Use purpose as part of salt for domain separation
        salt = hashlib.sha256(purpose.encode() + b"-salt-v1").digest()[:16]
        key = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
        print(f"  {purpose:15s}: {key.hex()}")


def demo_scrypt_passlib():
    """Scrypt via passlib (if available)."""
    print("\n" + "=" * 60)
    print("SCRYPT VIA PASSLIB")
    print("=" * 60)

    try:
        from passlib.hash import scrypt as passlib_scrypt

        password = "my-secret-password"
        hashed = passlib_scrypt.hash(password)

        assert passlib_scrypt.verify(password, hashed)
        assert not passlib_scrypt.verify("wrong-password", hashed)

        print(f"Password: {password}")
        print(f"Hash:     {hashed}")
        print("Verify correct:   PASSED")
        print("Verify incorrect: REJECTED")
    except ImportError:
        print("passlib not installed - skipping")


def demo_scrypt_vs_pbkdf2():
    """Compare scrypt with PBKDF2."""
    print("\n" + "=" * 60)
    print("SCRYPT VS PBKDF2 COMPARISON")
    print("=" * 60)

    password = b"comparison-password"
    salt = os.urandom(16)

    # PBKDF2-SHA256
    start = time.time()
    pbkdf2_key = hashlib.pbkdf2_hmac('sha256', password, salt, 600000, dklen=32)
    pbkdf2_time = time.time() - start

    # Scrypt
    start = time.time()
    scrypt_key = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    scrypt_time = time.time() - start

    print(f"  PBKDF2-SHA256 (600k iterations):")
    print(f"    Key:  {pbkdf2_key.hex()}")
    print(f"    Time: {pbkdf2_time:.4f}s")
    print(f"  Scrypt (N=16384, r=8, p=1):")
    print(f"    Key:  {scrypt_key.hex()}")
    print(f"    Time: {scrypt_time:.4f}s")
    print(f"  Note: Scrypt is memory-hard, PBKDF2 is not")


def main():
    """Run all scrypt demonstrations."""
    print("SCRYPT KEY DERIVATION - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Basic usage
    demo_basic_scrypt()
    demo_scrypt_parameter_variations()
    demo_scrypt_key_lengths()

    # Password hashing
    demo_scrypt_password_hashing()
    demo_scrypt_salt_importance()

    # Key derivation
    demo_scrypt_for_encryption_key()
    demo_scrypt_multiple_keys()

    # Benchmarks
    demo_scrypt_timing()
    demo_scrypt_vs_pbkdf2()

    # Passlib integration
    demo_scrypt_passlib()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
