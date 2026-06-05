"""
Comprehensive demonstration of the argon2-cffi library.
Covers password hashing with Argon2id, Argon2i, Argon2d,
parameter tuning, verification, and best practices.
"""

import time
import argon2
from argon2 import PasswordHasher, Type, Parameters
from argon2.exceptions import (
    VerifyMismatchError, VerificationError,
    InvalidHashError, HashingError
)
from argon2.low_level import hash_secret, hash_secret_raw, verify_secret, Type as LLType


def demo_basic_hashing():
    """Basic Argon2 password hashing."""
    print("\n" + "=" * 60)
    print("BASIC ARGON2 PASSWORD HASHING")
    print("=" * 60)

    ph = PasswordHasher()
    password = "my-secret-password"

    # Hash
    hashed = ph.hash(password)
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")
    print(f"Hash len: {len(hashed)} chars")

    # Verify
    assert ph.verify(hashed, password)
    print("Verify correct: PASSED")

    # Wrong password
    try:
        ph.verify(hashed, "wrong-password")
        print("Verify wrong: NOT REJECTED (ERROR)")
    except VerifyMismatchError:
        print("Verify wrong: REJECTED")


def demo_argon2id():
    """Argon2id (recommended default)."""
    print("\n" + "=" * 60)
    print("ARGON2ID (RECOMMENDED)")
    print("=" * 60)

    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )

    password = "argon2id-password"
    hashed = ph.hash(password)

    print(f"Type:        Argon2id")
    print(f"Time cost:   3 iterations")
    print(f"Memory cost: 64 MB")
    print(f"Parallelism: 4 threads")
    print(f"Hash length: 32 bytes")
    print(f"Salt length: 16 bytes")
    print(f"Hash: {hashed}")

    assert ph.verify(hashed, password)
    print("Verification: PASSED")


def demo_argon2i():
    """Argon2i (data-independent, side-channel resistant)."""
    print("\n" + "=" * 60)
    print("ARGON2I (SIDE-CHANNEL RESISTANT)")
    print("=" * 60)

    ph = PasswordHasher(
        time_cost=4,
        memory_cost=65536,
        parallelism=2,
        type=Type.I,
    )

    password = "argon2i-password"
    hashed = ph.hash(password)

    print(f"Type:        Argon2i")
    print(f"Time cost:   4 iterations")
    print(f"Hash: {hashed}")

    assert ph.verify(hashed, password)
    print("Verification: PASSED")


def demo_argon2d():
    """Argon2d (data-dependent, faster but vulnerable to side-channels)."""
    print("\n" + "=" * 60)
    print("ARGON2D (DATA-DEPENDENT)")
    print("=" * 60)

    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        type=Type.D,
    )

    password = "argon2d-password"
    hashed = ph.hash(password)

    print(f"Type:        Argon2d")
    print(f"Time cost:   3 iterations")
    print(f"Hash: {hashed}")

    assert ph.verify(hashed, password)
    print("Verification: PASSED")
    print("NOTE: Not recommended for password hashing (side-channel vulnerable)")


def demo_parameter_tuning():
    """Parameter tuning for different security levels."""
    print("\n" + "=" * 60)
    print("PARAMETER TUNING")
    print("=" * 60)

    password = "tuning-password"

    configs = [
        {"name": "Interactive (fast)", "time_cost": 1, "memory_cost": 65536, "parallelism": 4},
        {"name": "Standard", "time_cost": 3, "memory_cost": 65536, "parallelism": 4},
        {"name": "Sensitive", "time_cost": 4, "memory_cost": 131072, "parallelism": 4},
        {"name": "High security", "time_cost": 6, "memory_cost": 262144, "parallelism": 8},
    ]

    for config in configs:
        ph = PasswordHasher(
            time_cost=config["time_cost"],
            memory_cost=config["memory_cost"],
            parallelism=config["parallelism"],
            type=Type.ID,
        )

        start = time.time()
        hashed = ph.hash(password)
        elapsed = time.time() - start

        start_v = time.time()
        ph.verify(hashed, password)
        verify_time = time.time() - start_v

        mem_mb = config["memory_cost"] / 1024
        print(f"  {config['name']:20s}: t={config['time_cost']}, "
              f"m={mem_mb:.0f}MB, p={config['parallelism']}, "
              f"hash={elapsed:.3f}s, verify={verify_time:.3f}s")


def demo_hash_needs_update():
    """Check if hash needs rehashing (parameter upgrade)."""
    print("\n" + "=" * 60)
    print("HASH NEEDS UPDATE (PARAMETER UPGRADE)")
    print("=" * 60)

    # Old hasher (weaker parameters)
    old_ph = PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    password = "upgrade-password"
    old_hash = old_ph.hash(password)

    # New hasher (stronger parameters)
    new_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    # Check if old hash needs update
    needs_update = new_ph.check_needs_rehash(old_hash)
    print(f"Old hash: {old_hash}")
    print(f"Needs update: {needs_update}")

    # If it needs update, verify and rehash
    if needs_update:
        # Verify with old hash still works
        assert new_ph.verify(old_hash, password)
        # Generate new hash with stronger params
        new_hash = new_ph.hash(password)
        needs_update_new = new_ph.check_needs_rehash(new_hash)
        print(f"New hash: {new_hash}")
        print(f"New hash needs update: {needs_update_new}")


def demo_hash_format():
    """Argon2 hash format analysis."""
    print("\n" + "=" * 60)
    print("ARGON2 HASH FORMAT ANALYSIS")
    print("=" * 60)

    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )

    hashed = ph.hash("format-analysis")
    print(f"Full hash: {hashed}")
    print(f"\nFormat: $argon2id$v=<version>$m=<memory>,t=<time>,p=<parallel>$<salt>$<hash>")

    # Parse
    parts = hashed.split('$')
    print(f"\nParsed components:")
    print(f"  Algorithm: {parts[1]}")
    print(f"  Version:   {parts[2]}")
    print(f"  Params:    {parts[3]}")
    print(f"  Salt (b64): {parts[4]}")
    print(f"  Hash (b64): {parts[5]}")

    # Extract parameters from params string
    params = dict(p.split('=') for p in parts[3].split(','))
    print(f"\nExtracted parameters:")
    print(f"  Memory (KB): {params['m']}")
    print(f"  Time cost:   {params['t']}")
    print(f"  Parallelism: {params['p']}")


def demo_low_level_api():
    """Low-level argon2 API for key derivation."""
    print("\n" + "=" * 60)
    print("LOW-LEVEL API (KEY DERIVATION)")
    print("=" * 60)

    import os

    password = b"low-level-password"
    salt = os.urandom(16)

    # Hash to raw bytes (for key derivation)
    raw_hash = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=LLType.ID,
    )

    print(f"Password:  {password}")
    print(f"Salt:      {salt.hex()}")
    print(f"Raw hash:  {raw_hash.hex()}")
    print(f"Hash len:  {len(raw_hash)} bytes")

    # Hash to encoded string
    encoded_hash = hash_secret(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=LLType.ID,
    )
    print(f"Encoded:   {encoded_hash.decode()}")

    # Verify at low level
    is_valid = verify_secret(encoded_hash, password, type=LLType.ID)
    print(f"Verified:  {is_valid}")


def demo_different_hash_lengths():
    """Argon2 with different output lengths."""
    print("\n" + "=" * 60)
    print("DIFFERENT HASH LENGTHS")
    print("=" * 60)

    password = "hash-length-test"

    for hash_len in [16, 32, 48, 64, 128]:
        ph = PasswordHasher(
            time_cost=1,
            memory_cost=16384,
            parallelism=1,
            hash_len=hash_len,
        )
        hashed = ph.hash(password)
        assert ph.verify(hashed, password)
        # Extract the base64 hash part
        hash_part = hashed.split('$')[-1]
        print(f"  hash_len={hash_len:3d}: base64_len={len(hash_part):3d}, hash={hash_part[:30]}...")


def demo_unicode_passwords():
    """Argon2 with various unicode passwords."""
    print("\n" + "=" * 60)
    print("UNICODE PASSWORDS")
    print("=" * 60)

    ph = PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)

    passwords = [
        ("ASCII", "simple-password"),
        ("Extended", "café-résumé-naïve"),
        ("Cyrillic", "пароль-секрет"),
        ("Chinese", "密码测试安全"),
        ("Japanese", "パスワード"),
        ("Emoji", "🔐🔑🛡️"),
        ("Mixed", "p@ss-пароль-密码-🔒"),
    ]

    for name, pwd in passwords:
        hashed = ph.hash(pwd)
        verified = ph.verify(hashed, pwd)
        print(f"  {name:10s}: '{pwd[:15]}' -> verified={verified}")


def demo_error_handling():
    """Error handling patterns."""
    print("\n" + "=" * 60)
    print("ERROR HANDLING")
    print("=" * 60)

    ph = PasswordHasher()
    password = "error-test"
    hashed = ph.hash(password)

    # VerifyMismatchError (wrong password)
    try:
        ph.verify(hashed, "wrong")
    except VerifyMismatchError:
        print("VerifyMismatchError: Wrong password correctly caught")

    # InvalidHashError (malformed hash)
    try:
        ph.verify("not-a-valid-hash", password)
    except (VerificationError, InvalidHashError) as e:
        print(f"InvalidHashError: {type(e).__name__} correctly caught")

    # Empty password (should still work)
    empty_hash = ph.hash("")
    assert ph.verify(empty_hash, "")
    print("Empty password: hashes and verifies correctly")


def demo_parameters_object():
    """Using Parameters object for configuration."""
    print("\n" + "=" * 60)
    print("PARAMETERS OBJECT")
    print("=" * 60)

    # Get parameters from existing hash
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    hashed = ph.hash("test")

    # Access parameters directly from the hasher
    print(f"Parameters from PasswordHasher:")
    print(f"  time_cost:   {ph.time_cost}")
    print(f"  memory_cost: {ph.memory_cost}")
    print(f"  parallelism: {ph.parallelism}")
    print(f"  hash_len:    {ph.hash_len}")
    print(f"  salt_len:    {ph.salt_len}")
    print(f"  type:        {ph.type}")


def demo_comparison_with_other_kdf():
    """Compare Argon2 with other password hashing functions."""
    print("\n" + "=" * 60)
    print("COMPARISON WITH OTHER ALGORITHMS")
    print("=" * 60)

    password = "comparison-password"

    # Argon2id
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    start = time.time()
    argon2_hash = ph.hash(password)
    argon2_time = time.time() - start

    print(f"Argon2id (t=3, m=64MB, p=4):")
    print(f"  Time: {argon2_time:.4f}s")
    print(f"  Hash: {argon2_hash[:50]}...")
    print(f"  Memory-hard: YES")
    print(f"  GPU-resistant: YES")
    print(f"  Side-channel resistant: YES (id variant)")
    print(f"\nRecommended for:")
    print(f"  - Password storage (web apps, services)")
    print(f"  - Key derivation from passwords")
    print(f"  - Winner of Password Hashing Competition (2015)")


def main():
    """Run all argon2-cffi demonstrations."""
    print("ARGON2-CFFI LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Basic usage
    demo_basic_hashing()
    demo_argon2id()
    demo_argon2i()
    demo_argon2d()

    # Configuration
    demo_parameter_tuning()
    demo_hash_needs_update()
    demo_hash_format()
    demo_different_hash_lengths()
    demo_parameters_object()

    # Low-level
    demo_low_level_api()

    # Passwords
    demo_unicode_passwords()

    # Error handling
    demo_error_handling()

    # Comparison
    demo_comparison_with_other_kdf()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
