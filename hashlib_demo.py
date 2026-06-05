"""
Comprehensive demonstration of Python's built-in hashlib library.
Covers all standard hash algorithms, SHAKE XOFs, HMAC, PBKDF2,
file hashing, and hash comparison utilities.
"""

import hashlib
import hmac
import os
import secrets


def demo_sha2_family():
    """SHA-2 family hash functions."""
    print("\n" + "=" * 60)
    print("SHA-2 FAMILY HASH FUNCTIONS")
    print("=" * 60)

    data = b"Data to hash with SHA-2 family"

    algorithms = [
        ("SHA-224", hashlib.sha224),
        ("SHA-256", hashlib.sha256),
        ("SHA-384", hashlib.sha384),
        ("SHA-512", hashlib.sha512),
    ]

    for name, func in algorithms:
        digest = func(data).hexdigest()
        print(f"  {name:10s}: {digest[:50]}...")


def demo_sha3_family():
    """SHA-3 family hash functions."""
    print("\n" + "=" * 60)
    print("SHA-3 FAMILY HASH FUNCTIONS")
    print("=" * 60)

    data = b"Data to hash with SHA-3 family"

    algorithms = [
        ("SHA3-224", hashlib.sha3_224),
        ("SHA3-256", hashlib.sha3_256),
        ("SHA3-384", hashlib.sha3_384),
        ("SHA3-512", hashlib.sha3_512),
    ]

    for name, func in algorithms:
        digest = func(data).hexdigest()
        print(f"  {name:10s}: {digest[:50]}...")


def demo_shake():
    """SHAKE extendable output functions."""
    print("\n" + "=" * 60)
    print("SHAKE EXTENDABLE OUTPUT FUNCTIONS")
    print("=" * 60)

    data = b"Data for SHAKE XOF"

    # SHAKE128 with various output lengths
    shake128_16 = hashlib.shake_128(data).hexdigest(16)
    shake128_32 = hashlib.shake_128(data).hexdigest(32)
    shake128_64 = hashlib.shake_128(data).hexdigest(64)

    # SHAKE256 with various output lengths
    shake256_32 = hashlib.shake_256(data).hexdigest(32)
    shake256_64 = hashlib.shake_256(data).hexdigest(64)
    shake256_128 = hashlib.shake_256(data).hexdigest(128)

    print(f"  SHAKE128(16): {shake128_16}")
    print(f"  SHAKE128(32): {shake128_32}")
    print(f"  SHAKE128(64): {shake128_64[:50]}...")
    print(f"  SHAKE256(32): {shake256_32}")
    print(f"  SHAKE256(64): {shake256_64[:50]}...")
    print(f"  SHAKE256(128):{shake256_128[:50]}...")


def demo_blake2():
    """BLAKE2 hash functions."""
    print("\n" + "=" * 60)
    print("BLAKE2 HASH FUNCTIONS")
    print("=" * 60)

    data = b"Data for BLAKE2 hashing"

    # BLAKE2b (optimized for 64-bit)
    blake2b_full = hashlib.blake2b(data).hexdigest()
    blake2b_32 = hashlib.blake2b(data, digest_size=32).hexdigest()
    blake2b_16 = hashlib.blake2b(data, digest_size=16).hexdigest()

    # BLAKE2s (optimized for 32-bit)
    blake2s_full = hashlib.blake2s(data).hexdigest()
    blake2s_16 = hashlib.blake2s(data, digest_size=16).hexdigest()

    # BLAKE2b with key (keyed hashing / MAC)
    key = os.urandom(32)
    blake2b_keyed = hashlib.blake2b(data, key=key).hexdigest()

    # BLAKE2b with salt and personalization
    salt = os.urandom(16)
    person = b"demo-app"
    blake2b_personal = hashlib.blake2b(data, salt=salt, person=person).hexdigest()

    print(f"  BLAKE2b(64):       {blake2b_full[:50]}...")
    print(f"  BLAKE2b(32):       {blake2b_32}")
    print(f"  BLAKE2b(16):       {blake2b_16}")
    print(f"  BLAKE2s(32):       {blake2s_full}")
    print(f"  BLAKE2s(16):       {blake2s_16}")
    print(f"  BLAKE2b(keyed):    {blake2b_keyed[:50]}...")
    print(f"  BLAKE2b(personal): {blake2b_personal[:50]}...")


def demo_md5_sha1():
    """MD5 and SHA-1 (legacy/insecure)."""
    print("\n" + "=" * 60)
    print("LEGACY HASH FUNCTIONS (INSECURE)")
    print("=" * 60)

    data = b"Data to hash with legacy algorithms"

    md5_digest = hashlib.md5(data).hexdigest()
    sha1_digest = hashlib.sha1(data).hexdigest()

    print(f"  MD5:  {md5_digest}")
    print(f"  SHA1: {sha1_digest}")
    print("  WARNING: These are cryptographically broken - do not use for security")


def demo_incremental_hashing():
    """Incremental (streaming) hash updates."""
    print("\n" + "=" * 60)
    print("INCREMENTAL (STREAMING) HASHING")
    print("=" * 60)

    # Hash data in chunks
    hasher = hashlib.sha256()
    chunks = [b"First chunk of data. ", b"Second chunk. ", b"Third and final chunk."]

    for chunk in chunks:
        hasher.update(chunk)

    incremental_digest = hasher.hexdigest()

    # Compare with one-shot hashing
    full_data = b"".join(chunks)
    oneshot_digest = hashlib.sha256(full_data).hexdigest()

    assert incremental_digest == oneshot_digest
    print(f"  Chunks: {len(chunks)}")
    print(f"  Incremental: {incremental_digest}")
    print(f"  One-shot:    {oneshot_digest}")
    print(f"  Match: {incremental_digest == oneshot_digest}")


def demo_hash_copy():
    """Hash object copying for branching computations."""
    print("\n" + "=" * 60)
    print("HASH OBJECT COPYING")
    print("=" * 60)

    common_prefix = b"Common prefix data: "

    hasher = hashlib.sha256()
    hasher.update(common_prefix)

    # Branch 1
    branch1 = hasher.copy()
    branch1.update(b"branch 1 suffix")
    digest1 = branch1.hexdigest()

    # Branch 2
    branch2 = hasher.copy()
    branch2.update(b"branch 2 suffix")
    digest2 = branch2.hexdigest()

    print(f"  Branch 1: {digest1}")
    print(f"  Branch 2: {digest2}")
    print(f"  Different: {digest1 != digest2}")


def demo_hmac_basic():
    """HMAC (Hash-based Message Authentication Code)."""
    print("\n" + "=" * 60)
    print("HMAC (HASH-BASED MAC)")
    print("=" * 60)

    key = secrets.token_bytes(32)
    message = b"Message to authenticate"

    # Create HMAC with SHA-256
    h = hmac.new(key, message, hashlib.sha256)
    mac = h.hexdigest()

    # Verify using compare_digest (constant-time)
    h_verify = hmac.new(key, message, hashlib.sha256)
    is_valid = hmac.compare_digest(h_verify.hexdigest(), mac)

    print(f"  Message: {message}")
    print(f"  HMAC-SHA256: {mac}")
    print(f"  Valid: {is_valid}")


def demo_hmac_algorithms():
    """HMAC with different hash algorithms."""
    print("\n" + "=" * 60)
    print("HMAC WITH MULTIPLE ALGORITHMS")
    print("=" * 60)

    key = secrets.token_bytes(32)
    message = b"Test message for HMAC"

    algorithms = [
        ("HMAC-MD5", hashlib.md5),
        ("HMAC-SHA1", hashlib.sha1),
        ("HMAC-SHA256", hashlib.sha256),
        ("HMAC-SHA384", hashlib.sha384),
        ("HMAC-SHA512", hashlib.sha512),
        ("HMAC-SHA3-256", hashlib.sha3_256),
        ("HMAC-BLAKE2b", lambda: hashlib.blake2b(digest_size=32)),
    ]

    for name, hash_func in algorithms:
        if name == "HMAC-BLAKE2b":
            # BLAKE2 has built-in keyed mode
            h = hashlib.blake2b(message, key=key, digest_size=32)
            mac = h.hexdigest()
        else:
            h = hmac.new(key, message, hash_func)
            mac = h.hexdigest()
        print(f"  {name:15s}: {mac[:40]}...")


def demo_pbkdf2():
    """PBKDF2 key derivation."""
    print("\n" + "=" * 60)
    print("PBKDF2 KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = os.urandom(16)

    # SHA-256 based PBKDF2
    key_256 = hashlib.pbkdf2_hmac('sha256', password, salt, 600000, dklen=32)

    # SHA-512 based PBKDF2
    key_512 = hashlib.pbkdf2_hmac('sha512', password, salt, 600000, dklen=64)

    # SHA-1 based PBKDF2 (for compatibility)
    key_sha1 = hashlib.pbkdf2_hmac('sha1', password, salt, 600000, dklen=20)

    print(f"  Password:     {password}")
    print(f"  Iterations:   600000")
    print(f"  PBKDF2-SHA256: {key_256.hex()}")
    print(f"  PBKDF2-SHA512: {key_512.hex()[:50]}...")
    print(f"  PBKDF2-SHA1:   {key_sha1.hex()}")


def demo_scrypt():
    """Scrypt key derivation (Python 3.6+)."""
    print("\n" + "=" * 60)
    print("SCRYPT KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = os.urandom(16)

    derived = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)

    print(f"  Password:    {password}")
    print(f"  Parameters:  n=16384, r=8, p=1")
    print(f"  Derived key: {derived.hex()}")


def demo_available_algorithms():
    """List available hash algorithms."""
    print("\n" + "=" * 60)
    print("AVAILABLE HASH ALGORITHMS")
    print("=" * 60)

    guaranteed = sorted(hashlib.algorithms_guaranteed)
    available = sorted(hashlib.algorithms_available)

    print(f"  Guaranteed algorithms ({len(guaranteed)}):")
    for alg in guaranteed:
        print(f"    - {alg}")

    print(f"\n  Available algorithms ({len(available)}):")
    for alg in sorted(available)[:20]:
        print(f"    - {alg}")
    if len(available) > 20:
        print(f"    ... and {len(available) - 20} more")


def demo_new_hash():
    """Create hash objects using hashlib.new() by name."""
    print("\n" + "=" * 60)
    print("HASH BY NAME (hashlib.new)")
    print("=" * 60)

    data = b"Data to hash by algorithm name"
    algorithm_names = ["sha256", "sha3_256", "blake2b", "sha512"]

    for name in algorithm_names:
        try:
            h = hashlib.new(name, data)
            print(f"  {name:12s}: {h.hexdigest()[:40]}...")
        except ValueError as e:
            print(f"  {name:12s}: Not available ({e})")


def demo_file_hashing():
    """Hash file contents efficiently."""
    print("\n" + "=" * 60)
    print("FILE HASHING")
    print("=" * 60)

    # Create a temporary test file
    test_data = os.urandom(1024 * 100)  # 100KB
    test_file = "__hashlib_test_file.bin"

    with open(test_file, 'wb') as f:
        f.write(test_data)

    # Hash file using file_digest (Python 3.11+) or manual chunking
    try:
        with open(test_file, 'rb') as f:
            digest = hashlib.file_digest(f, 'sha256')
        file_hash = digest.hexdigest()
        print(f"  file_digest (SHA-256): {file_hash}")
    except AttributeError:
        # Fallback for Python < 3.11
        hasher = hashlib.sha256()
        with open(test_file, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        print(f"  Chunked hash (SHA-256): {file_hash}")

    # Verify against one-shot
    oneshot_hash = hashlib.sha256(test_data).hexdigest()
    assert file_hash == oneshot_hash
    print(f"  One-shot verify: MATCH")

    # Clean up
    os.remove(test_file)
    print(f"  File size: {len(test_data)} bytes")


def demo_compare_digest():
    """Constant-time comparison to prevent timing attacks."""
    print("\n" + "=" * 60)
    print("CONSTANT-TIME COMPARISON")
    print("=" * 60)

    secret = secrets.token_bytes(32)
    message = b"Authenticated message"

    mac = hmac.new(secret, message, hashlib.sha256).digest()

    # Correct comparison (constant-time)
    valid_mac = hmac.new(secret, message, hashlib.sha256).digest()
    is_valid = hmac.compare_digest(mac, valid_mac)

    # Invalid MAC
    invalid_mac = b"\x00" * 32
    is_invalid = hmac.compare_digest(mac, invalid_mac)

    print(f"  Valid MAC comparison: {is_valid}")
    print(f"  Invalid MAC comparison: {is_invalid}")
    print("  (Both comparisons take constant time)")


def demo_hash_properties():
    """Examine hash object properties."""
    print("\n" + "=" * 60)
    print("HASH OBJECT PROPERTIES")
    print("=" * 60)

    h = hashlib.sha256(b"test data")

    print(f"  Algorithm:    {h.name}")
    print(f"  Digest size:  {h.digest_size} bytes")
    print(f"  Block size:   {h.block_size} bytes")
    print(f"  Hex digest:   {h.hexdigest()}")
    print(f"  Raw digest:   {h.digest().hex()}")


def main():
    """Run all hashlib demonstrations."""
    print("PYTHON HASHLIB - COMPREHENSIVE DEMO")
    print("=" * 60)

    # SHA-2 family
    demo_sha2_family()

    # SHA-3 family
    demo_sha3_family()

    # SHAKE XOFs
    demo_shake()

    # BLAKE2
    demo_blake2()

    # Legacy (insecure)
    demo_md5_sha1()

    # Streaming / incremental
    demo_incremental_hashing()
    demo_hash_copy()

    # HMAC
    demo_hmac_basic()
    demo_hmac_algorithms()

    # Key derivation
    demo_pbkdf2()
    demo_scrypt()

    # Utilities
    demo_available_algorithms()
    demo_new_hash()
    demo_file_hashing()
    demo_compare_digest()
    demo_hash_properties()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
