"""
Comprehensive demonstration of the bcrypt library.
Covers password hashing, salt generation, cost factor tuning,
verification, and best practices.
"""

import bcrypt
import time
import os


def demo_basic_hashing():
    """Basic bcrypt password hashing."""
    print("\n" + "=" * 60)
    print("BASIC BCRYPT PASSWORD HASHING")
    print("=" * 60)

    password = b"my-secret-password"

    # Generate salt and hash
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)

    print(f"Password:  {password}")
    print(f"Salt:      {salt}")
    print(f"Hash:      {hashed}")
    print(f"Hash len:  {len(hashed)} bytes")

    # Verify
    assert bcrypt.checkpw(password, hashed)
    assert not bcrypt.checkpw(b"wrong-password", hashed)
    print("Verify correct:   PASSED")
    print("Verify incorrect: REJECTED")


def demo_cost_factors():
    """Bcrypt with different cost factors (work factors)."""
    print("\n" + "=" * 60)
    print("BCRYPT COST FACTORS")
    print("=" * 60)

    password = b"benchmark-password"

    for rounds in [4, 8, 10, 12, 14]:
        start = time.time()
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password, salt)
        elapsed = time.time() - start

        # Verify timing
        start_v = time.time()
        bcrypt.checkpw(password, hashed)
        verify_time = time.time() - start_v

        print(f"  Rounds={rounds:2d}: hash={elapsed:.4f}s, verify={verify_time:.4f}s, "
              f"hash={hashed[:30]}...")


def demo_salt_generation():
    """Bcrypt salt generation."""
    print("\n" + "=" * 60)
    print("BCRYPT SALT GENERATION")
    print("=" * 60)

    # Default rounds (12)
    salt_default = bcrypt.gensalt()
    print(f"Default salt (rounds=12): {salt_default}")

    # Custom rounds
    salt_10 = bcrypt.gensalt(rounds=10)
    salt_14 = bcrypt.gensalt(rounds=14)
    print(f"Salt (rounds=10): {salt_10}")
    print(f"Salt (rounds=14): {salt_14}")

    # Demonstrate salt uniqueness
    salts = [bcrypt.gensalt() for _ in range(5)]
    all_different = len(set(salts)) == len(salts)
    print(f"\nSalt uniqueness (5 generated):")
    for i, s in enumerate(salts):
        print(f"  Salt {i+1}: {s}")
    print(f"All different: {all_different}")


def demo_salt_prefix():
    """Bcrypt salt/hash prefix analysis."""
    print("\n" + "=" * 60)
    print("BCRYPT HASH FORMAT ANALYSIS")
    print("=" * 60)

    password = b"analysis-password"

    # Generate with different prefixes
    salt_2b = bcrypt.gensalt(prefix=b"2b")
    hash_2b = bcrypt.hashpw(password, salt_2b)

    print(f"Hash ($2b$ prefix): {hash_2b}")
    print(f"\nHash format breakdown:")
    print(f"  $2b$       = bcrypt version identifier")
    print(f"  12$        = cost factor (2^12 = 4096 iterations)")
    print(f"  <22 chars> = 128-bit salt (base64)")
    print(f"  <31 chars> = 184-bit hash (base64)")

    # Demonstrate format
    hash_str = hash_2b.decode()
    parts = hash_str.split('$')
    print(f"\n  Version: ${parts[1]}$")
    print(f"  Cost:    {parts[2]}")
    print(f"  Salt+Hash: {parts[3]}")
    print(f"  Salt (first 22): {parts[3][:22]}")
    print(f"  Hash (last 31):  {parts[3][22:]}")


def demo_unicode_passwords():
    """Bcrypt with unicode passwords."""
    print("\n" + "=" * 60)
    print("BCRYPT UNICODE PASSWORDS")
    print("=" * 60)

    passwords = [
        ("ASCII", "simple-password"),
        ("Extended ASCII", "café-résumé"),
        ("Cyrillic", "пароль-секрет"),
        ("Chinese", "密码测试"),
        ("Mixed", "p@$$wörd-密码"),
        ("Emoji", "🔒secret🔑"),
    ]

    for name, pwd in passwords:
        pwd_bytes = pwd.encode('utf-8')
        salt = bcrypt.gensalt(rounds=4)  # Low rounds for speed
        hashed = bcrypt.hashpw(pwd_bytes, salt)
        verified = bcrypt.checkpw(pwd_bytes, hashed)
        print(f"  {name:15s}: '{pwd[:15]}...' -> verified={verified}")


def demo_password_length():
    """Bcrypt password length behavior (72-byte limit)."""
    print("\n" + "=" * 60)
    print("BCRYPT PASSWORD LENGTH (72-BYTE LIMIT)")
    print("=" * 60)

    # Bcrypt only uses first 72 bytes
    base_password = b"a" * 72
    extended_password = b"a" * 73  # Extra byte is ignored

    salt = bcrypt.gensalt(rounds=4)
    hash_72 = bcrypt.hashpw(base_password, salt)
    hash_73 = bcrypt.hashpw(extended_password, salt)

    # These will produce the same hash!
    same_hash = (hash_72 == hash_73)
    print(f"72-byte password hash: {hash_72[:40]}...")
    print(f"73-byte password hash: {hash_73[:40]}...")
    print(f"Same hash (truncated): {same_hash}")
    print("\nWARNING: Bcrypt silently truncates passwords at 72 bytes!")
    print("Mitigation: Pre-hash with SHA-256 for long passwords")

    # Mitigation: pre-hash
    import hashlib
    long_password = b"very-long-password-" * 20
    prehashed = hashlib.sha256(long_password).digest()
    import base64
    prehashed_b64 = base64.b64encode(prehashed)  # Keep under 72 bytes
    hashed = bcrypt.hashpw(prehashed_b64, bcrypt.gensalt(rounds=4))
    verified = bcrypt.checkpw(prehashed_b64, hashed)
    print(f"\nPre-hashed long password ({len(long_password)} bytes):")
    print(f"  SHA-256 + base64: {prehashed_b64[:40]}...")
    print(f"  Verified: {verified}")


def demo_hash_verification_patterns():
    """Common verification patterns."""
    print("\n" + "=" * 60)
    print("VERIFICATION PATTERNS")
    print("=" * 60)

    password = b"user-password"
    salt = bcrypt.gensalt()
    stored_hash = bcrypt.hashpw(password, salt)

    # Pattern 1: Direct verification
    is_valid = bcrypt.checkpw(password, stored_hash)
    print(f"Direct verification: {is_valid}")

    # Pattern 2: Timing-safe (bcrypt.checkpw is already constant-time)
    import hmac
    recomputed = bcrypt.hashpw(password, stored_hash)
    is_valid_ct = hmac.compare_digest(recomputed, stored_hash)
    print(f"Constant-time check: {is_valid_ct}")

    # Pattern 3: Verify against wrong passwords
    wrong_passwords = [b"", b" ", b"wrong", b"USER-PASSWORD", password + b"x"]
    print("Wrong password tests:")
    for wp in wrong_passwords:
        result = bcrypt.checkpw(wp, stored_hash)
        display = wp.decode('utf-8', errors='replace')[:20]
        print(f"  '{display}': {result}")


def demo_hash_storage():
    """Hash storage and retrieval patterns."""
    print("\n" + "=" * 60)
    print("HASH STORAGE PATTERNS")
    print("=" * 60)

    password = b"storage-demo-password"
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    # Store as string (for database)
    stored_string = hashed.decode('utf-8')
    print(f"Store as string: {stored_string}")

    # Retrieve and verify
    retrieved_bytes = stored_string.encode('utf-8')
    verified = bcrypt.checkpw(password, retrieved_bytes)
    print(f"Retrieved and verified: {verified}")

    # Store as bytes (for binary storage)
    stored_bytes = hashed
    print(f"Store as bytes: {len(stored_bytes)} bytes")
    print(f"Verify from bytes: {bcrypt.checkpw(password, stored_bytes)}")


def demo_kdf():
    """Bcrypt as a key derivation function."""
    print("\n" + "=" * 60)
    print("BCRYPT KEY DERIVATION")
    print("=" * 60)

    password = b"kdf-password"
    salt = bcrypt.gensalt(rounds=12)

    # Use bcrypt output as derived key
    derived = bcrypt.hashpw(password, salt)

    # Extract the hash portion (last 31 chars of base64)
    hash_portion = derived.decode().split('$')[3][22:]
    print(f"Password: {password}")
    print(f"Full hash: {derived}")
    print(f"Derived key material: {hash_portion}")
    print(f"Key length: {len(hash_portion)} chars")

    # For actual KDF use, better to use bcrypt.kdf if available
    try:
        key = bcrypt.kdf(
            password=password,
            salt=b"salt-value-here!",
            desired_key_bytes=32,
            rounds=100,
        )
        print(f"bcrypt.kdf output: {key.hex()}")
        print(f"KDF key length: {len(key)} bytes")
    except AttributeError:
        print("bcrypt.kdf not available in this version")


def demo_concurrent_hashing():
    """Demonstrate bcrypt thread safety."""
    print("\n" + "=" * 60)
    print("CONCURRENT HASHING")
    print("=" * 60)

    import threading

    passwords = [f"password-{i}".encode() for i in range(5)]
    results = {}
    errors = []

    def hash_password(pwd, index):
        try:
            hashed = bcrypt.hashpw(pwd, bcrypt.gensalt(rounds=4))
            verified = bcrypt.checkpw(pwd, hashed)
            results[index] = (hashed, verified)
        except Exception as e:
            errors.append((index, e))

    threads = []
    for i, pwd in enumerate(passwords):
        t = threading.Thread(target=hash_password, args=(pwd, i))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"Threads: {len(threads)}")
    print(f"Successful: {len(results)}")
    print(f"Errors: {len(errors)}")
    for idx, (hashed, verified) in sorted(results.items()):
        print(f"  Thread {idx}: verified={verified}")


def main():
    """Run all bcrypt demonstrations."""
    print("BCRYPT LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Basic hashing
    demo_basic_hashing()
    demo_cost_factors()
    demo_salt_generation()
    demo_salt_prefix()

    # Password handling
    demo_unicode_passwords()
    demo_password_length()
    demo_hash_verification_patterns()

    # Storage
    demo_hash_storage()

    # KDF
    demo_kdf()

    # Concurrency
    demo_concurrent_hashing()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
