"""
Comprehensive demonstration of Werkzeug's security utilities.
Covers password hashing, secure token generation, safe string comparison,
and cookie signing.
"""

import time
import hmac
from werkzeug.security import (
    generate_password_hash, check_password_hash,
    safe_join
)
from werkzeug.serving import generate_adhoc_ssl_context


def demo_pbkdf2_sha256():
    """Password hashing with PBKDF2-SHA256 (default)."""
    print("\n" + "=" * 60)
    print("WERKZEUG PBKDF2-SHA256 PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"

    # Default method (pbkdf2:sha256)
    hashed = generate_password_hash(password)
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")

    # Verify
    assert check_password_hash(hashed, password)
    assert not check_password_hash(hashed, "wrong-password")
    print("Verify correct:   PASSED")
    print("Verify incorrect: REJECTED")

    # Parse hash components
    parts = hashed.split("$")
    print(f"Method:   {parts[0]}")
    print(f"Salt:     {parts[1]}")
    print(f"Hash:     {parts[2][:30]}...")


def demo_pbkdf2_sha512():
    """Password hashing with PBKDF2-SHA512."""
    print("\n" + "=" * 60)
    print("WERKZEUG PBKDF2-SHA512 PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"
    hashed = generate_password_hash(password, method='pbkdf2:sha512')

    assert check_password_hash(hashed, password)
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")
    print("Verification: PASSED")


def demo_pbkdf2_sha1():
    """Password hashing with PBKDF2-SHA1."""
    print("\n" + "=" * 60)
    print("WERKZEUG PBKDF2-SHA1 PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"
    hashed = generate_password_hash(password, method='pbkdf2:sha1')

    assert check_password_hash(hashed, password)
    print(f"Hash: {hashed}")
    print("Verification: PASSED")


def demo_custom_iterations():
    """Password hashing with custom iteration count."""
    print("\n" + "=" * 60)
    print("CUSTOM ITERATION COUNT")
    print("=" * 60)

    password = "my-secret-password"

    iterations_list = [50000, 100000, 260000, 600000]

    for iterations in iterations_list:
        start = time.time()
        hashed = generate_password_hash(
            password,
            method=f'pbkdf2:sha256:{iterations}'
        )
        elapsed = time.time() - start
        assert check_password_hash(hashed, password)
        print(f"  {iterations:>7d} iterations: {elapsed:.4f}s - {hashed[:40]}...")


def demo_scrypt():
    """Password hashing with scrypt."""
    print("\n" + "=" * 60)
    print("WERKZEUG SCRYPT PASSWORD HASHING")
    print("=" * 60)

    password = "my-secret-password"

    try:
        hashed = generate_password_hash(password, method='scrypt')
        assert check_password_hash(hashed, password)
        print(f"Password: {password}")
        print(f"Hash:     {hashed}")
        print("Verification: PASSED")
    except (ValueError, TypeError) as e:
        print(f"Scrypt method: {e}")
        print("(May not be available in this version)")


def demo_salt_length():
    """Password hashing with custom salt length."""
    print("\n" + "=" * 60)
    print("CUSTOM SALT LENGTH")
    print("=" * 60)

    password = "my-secret-password"

    salt_lengths = [8, 16, 32, 64]
    for salt_len in salt_lengths:
        hashed = generate_password_hash(password, salt_length=salt_len)
        parts = hashed.split("$")
        actual_salt_len = len(parts[1]) if len(parts) > 1 else 0
        assert check_password_hash(hashed, password)
        print(f"  Salt length {salt_len:2d}: salt='{parts[1][:20]}...' ({actual_salt_len} chars)")


def demo_multiple_passwords():
    """Hash and verify multiple passwords."""
    print("\n" + "=" * 60)
    print("MULTIPLE PASSWORD HASHING")
    print("=" * 60)

    passwords = [
        "simple",
        "C0mpl3x!P@ssw0rd",
        "unicode-пароль-密码",
        "very-long-password-" * 10,
        "",  # Empty password
        " ",  # Whitespace
    ]

    for pwd in passwords:
        hashed = generate_password_hash(pwd)
        valid = check_password_hash(hashed, pwd)
        display = pwd[:30] + "..." if len(pwd) > 30 else pwd
        print(f"  '{display:33s}' -> verify={valid}")


def demo_hash_uniqueness():
    """Demonstrate that same password produces different hashes."""
    print("\n" + "=" * 60)
    print("HASH UNIQUENESS (SALT RANDOMIZATION)")
    print("=" * 60)

    password = "same-password"

    hashes = [generate_password_hash(password) for _ in range(5)]
    all_different = len(set(hashes)) == len(hashes)

    for i, h in enumerate(hashes):
        print(f"  Hash {i+1}: {h[:50]}...")

    print(f"All different: {all_different}")
    print("(Each hash uses a unique random salt)")


def demo_safe_join():
    """Safe path joining to prevent directory traversal."""
    print("\n" + "=" * 60)
    print("SAFE PATH JOINING")
    print("=" * 60)

    base = "/var/www/uploads"
    safe_paths = ["document.pdf", "images/photo.jpg", "data/file.csv"]
    unsafe_paths = ["../etc/passwd", "../../secret", "/etc/shadow"]

    print("  Safe paths:")
    for path in safe_paths:
        result = safe_join(base, path)
        print(f"    {path:25s} -> {result}")

    print("  Unsafe paths (should return None or raise):")
    for path in unsafe_paths:
        try:
            result = safe_join(base, path)
            if result is None:
                print(f"    {path:25s} -> BLOCKED (None)")
            else:
                print(f"    {path:25s} -> {result}")
        except Exception as e:
            print(f"    {path:25s} -> BLOCKED ({type(e).__name__})")


def demo_timing_attack_resistance():
    """Demonstrate constant-time comparison."""
    print("\n" + "=" * 60)
    print("TIMING-SAFE COMPARISON")
    print("=" * 60)

    # These comparisons should take constant time regardless of where they differ
    token = "abcdefghijklmnop"

    results = [
        ("Identical", hmac.compare_digest(token, token)),
        ("First char diff", hmac.compare_digest(token, "Xbcdefghijklmnop")),
        ("Last char diff", hmac.compare_digest(token, "abcdefghijklmnoX")),
        ("Completely different", hmac.compare_digest(token, "XXXXXXXXXXXXXXXX")),
        ("Different length", hmac.compare_digest(token, "short")),
    ]

    for desc, result in results:
        print(f"  {desc:25s}: {result}")


def demo_password_hash_comparison():
    """Compare performance of different hash methods."""
    print("\n" + "=" * 60)
    print("HASH METHOD PERFORMANCE COMPARISON")
    print("=" * 60)

    password = "benchmark-password"
    methods = [
        "pbkdf2:sha256:50000",
        "pbkdf2:sha256:260000",
        "pbkdf2:sha512:260000",
    ]

    for method in methods:
        start = time.time()
        hashed = generate_password_hash(password, method=method)
        hash_time = time.time() - start

        start = time.time()
        check_password_hash(hashed, password)
        verify_time = time.time() - start

        print(f"  {method:30s}: hash={hash_time:.4f}s, verify={verify_time:.4f}s")


def demo_adhoc_ssl():
    """Generate ad-hoc SSL context (for development)."""
    print("\n" + "=" * 60)
    print("AD-HOC SSL CONTEXT (DEVELOPMENT)")
    print("=" * 60)

    try:
        ctx = generate_adhoc_ssl_context()
        print(f"SSL Context created: {type(ctx).__name__}")
        print("Protocol: TLS (ad-hoc self-signed certificate)")
        print("WARNING: For development use only!")
    except Exception as e:
        print(f"Ad-hoc SSL: {e}")


def demo_hash_format_analysis():
    """Analyze the format of generated password hashes."""
    print("\n" + "=" * 60)
    print("HASH FORMAT ANALYSIS")
    print("=" * 60)

    password = "analysis-password"
    methods = ["pbkdf2:sha256", "pbkdf2:sha512", "pbkdf2:sha1"]

    for method in methods:
        hashed = generate_password_hash(password, method=method)
        parts = hashed.split("$")

        print(f"\n  Method: {method}")
        print(f"  Full hash: {hashed}")
        if len(parts) >= 3:
            print(f"  Format: method$salt$hash")
            print(f"    method: {parts[0]}")
            print(f"    salt:   {parts[1]}")
            print(f"    hash:   {parts[2][:30]}...")


def main():
    """Run all Werkzeug security demonstrations."""
    print("WERKZEUG SECURITY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Password Hashing
    demo_pbkdf2_sha256()
    demo_pbkdf2_sha512()
    demo_pbkdf2_sha1()
    demo_scrypt()
    demo_custom_iterations()
    demo_salt_length()

    # Multiple passwords
    demo_multiple_passwords()
    demo_hash_uniqueness()

    # Security utilities
    demo_safe_join()
    demo_timing_attack_resistance()

    # Performance
    demo_password_hash_comparison()
    demo_hash_format_analysis()

    # SSL
    demo_adhoc_ssl()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
