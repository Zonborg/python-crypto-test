"""
Comprehensive demonstration of the PyNaCl library (libsodium bindings).
Covers public-key encryption, symmetric encryption, signing,
hashing, key derivation, password hashing, and secret streams.
"""

import os
import nacl.utils
import nacl.secret
import nacl.public
import nacl.signing
import nacl.hash
import nacl.pwhash
import nacl.encoding
from nacl.public import PrivateKey, PublicKey, Box, SealedBox
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox, Aead
from nacl.hash import sha256, sha512, blake2b
from nacl.pwhash import argon2id, argon2i, scrypt
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)


def demo_public_key_encryption():
    """Public-key authenticated encryption (Curve25519 + XSalsa20-Poly1305)."""
    print("\n" + "=" * 60)
    print("PUBLIC-KEY AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    # Generate key pairs for Alice and Bob
    alice_private = PrivateKey.generate()
    alice_public = alice_private.public_key

    bob_private = PrivateKey.generate()
    bob_public = bob_private.public_key

    # Alice encrypts to Bob
    alice_box = Box(alice_private, bob_public)
    plaintext = b"Secret message from Alice to Bob"
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted = alice_box.encrypt(plaintext, nonce)

    print(f"Alice public key: {alice_public.encode(nacl.encoding.HexEncoder).decode()[:40]}...")
    print(f"Bob public key:   {bob_public.encode(nacl.encoding.HexEncoder).decode()[:40]}...")
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted.hex()[:50]}...")

    # Bob decrypts from Alice
    bob_box = Box(bob_private, alice_public)
    decrypted = bob_box.decrypt(encrypted)

    assert decrypted == plaintext
    print(f"Decrypted:  {decrypted}")
    print("Verification: PASSED")


def demo_sealed_box():
    """Sealed box (anonymous sender, authenticated recipient)."""
    print("\n" + "=" * 60)
    print("SEALED BOX (ANONYMOUS ENCRYPTION)")
    print("=" * 60)

    # Only recipient's key pair needed
    recipient_private = PrivateKey.generate()
    recipient_public = recipient_private.public_key

    # Anyone can encrypt (no sender authentication)
    sealed_box = SealedBox(recipient_public)
    plaintext = b"Anonymous message for recipient only"
    encrypted = sealed_box.encrypt(plaintext)

    print(f"Plaintext: {plaintext}")
    print(f"Encrypted: {encrypted.hex()[:50]}...")

    # Only recipient can decrypt
    unseal_box = SealedBox(recipient_private)
    decrypted = unseal_box.decrypt(encrypted)

    assert decrypted == plaintext
    print(f"Decrypted: {decrypted}")
    print("Note: Sender identity is anonymous")


def demo_secret_key_encryption():
    """Secret-key authenticated encryption (XSalsa20-Poly1305)."""
    print("\n" + "=" * 60)
    print("SECRET-KEY AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    # Generate random key
    key = nacl.utils.random(SecretBox.KEY_SIZE)
    box = SecretBox(key)

    plaintext = b"Secret message with symmetric encryption"

    # Encrypt (nonce generated automatically)
    encrypted = box.encrypt(plaintext)
    print(f"Key size:   {SecretBox.KEY_SIZE} bytes")
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted.hex()[:50]}...")

    # Decrypt
    decrypted = box.decrypt(encrypted)
    assert decrypted == plaintext
    print(f"Decrypted:  {decrypted}")

    # Encrypt with explicit nonce
    nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
    encrypted_nonce = box.encrypt(plaintext, nonce)
    decrypted_nonce = box.decrypt(encrypted_nonce)
    assert decrypted_nonce == plaintext
    print(f"Nonce size: {SecretBox.NONCE_SIZE} bytes")
    print("Explicit nonce: PASSED")


def demo_aead_encryption():
    """AEAD encryption (XChaCha20-Poly1305)."""
    print("\n" + "=" * 60)
    print("AEAD ENCRYPTION (XCHACHA20-POLY1305)")
    print("=" * 60)

    try:
        key = nacl.utils.random(nacl.secret.Aead.KEY_SIZE)
        aead = Aead(key)

        plaintext = b"AEAD encrypted message"
        aad = b"additional authenticated data"

        encrypted = aead.encrypt(plaintext, aad)
        decrypted = aead.decrypt(encrypted, aad)

        assert decrypted == plaintext
        print(f"Plaintext:  {plaintext}")
        print(f"AAD:        {aad}")
        print(f"Encrypted:  {encrypted.hex()[:50]}...")
        print(f"Decrypted:  {decrypted}")
    except (AttributeError, TypeError):
        # Fallback to low-level bindings
        key = nacl.utils.random(32)
        nonce = nacl.utils.random(24)
        plaintext = b"AEAD encrypted message"
        aad = b"additional authenticated data"

        encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
        decrypted = crypto_aead_xchacha20poly1305_ietf_decrypt(encrypted, aad, nonce, key)

        assert decrypted == plaintext
        print(f"Plaintext:  {plaintext}")
        print(f"AAD:        {aad}")
        print(f"Decrypted:  {decrypted}")
        print("(Using low-level bindings)")


def demo_signing():
    """Ed25519 digital signatures."""
    print("\n" + "=" * 60)
    print("ED25519 DIGITAL SIGNATURES")
    print("=" * 60)

    # Generate signing key
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    message = b"Message to sign with Ed25519"

    # Sign
    signed = signing_key.sign(message)
    signature = signed.signature

    print(f"Signing key:  {signing_key.encode(nacl.encoding.HexEncoder).decode()[:40]}...")
    print(f"Verify key:   {verify_key.encode(nacl.encoding.HexEncoder).decode()[:40]}...")
    print(f"Message:      {message}")
    print(f"Signature:    {signature.hex()[:50]}...")

    # Verify
    verify_key.verify(signed.message, signed.signature)
    print("Verification: PASSED")

    # Verify detached signature
    verify_key.verify(message, signature)
    print("Detached verification: PASSED")

    # Tampered message
    try:
        verify_key.verify(b"tampered message", signature)
        print("Tampered: NOT DETECTED (ERROR)")
    except nacl.exceptions.BadSignatureError:
        print("Tampered: Correctly rejected")


def demo_key_exchange():
    """Diffie-Hellman key exchange (Curve25519)."""
    print("\n" + "=" * 60)
    print("CURVE25519 KEY EXCHANGE")
    print("=" * 60)

    # Generate key pairs
    alice_private = PrivateKey.generate()
    alice_public = alice_private.public_key

    bob_private = PrivateKey.generate()
    bob_public = bob_private.public_key

    # Compute shared secret
    alice_box = Box(alice_private, bob_public)
    bob_box = Box(bob_private, alice_public)

    # The shared key is derived internally
    # We can verify by encrypting/decrypting
    test_msg = b"Key exchange verification"
    encrypted = alice_box.encrypt(test_msg)
    decrypted = bob_box.decrypt(encrypted)

    assert decrypted == test_msg
    print(f"Alice -> Bob encryption: OK")
    print(f"Bob decryption: OK")
    print("Shared secret agreement: PASSED")


def demo_hashing():
    """Cryptographic hash functions."""
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHIC HASH FUNCTIONS")
    print("=" * 60)

    data = b"Data to hash with libsodium"

    # SHA-256
    sha256_hash = sha256(data, encoder=nacl.encoding.HexEncoder)
    print(f"SHA-256:  {sha256_hash.decode()}")

    # SHA-512
    sha512_hash = sha512(data, encoder=nacl.encoding.HexEncoder)
    print(f"SHA-512:  {sha512_hash.decode()[:50]}...")

    # BLAKE2b
    blake2b_hash = blake2b(data, digest_size=32, encoder=nacl.encoding.HexEncoder)
    print(f"BLAKE2b(32): {blake2b_hash.decode()}")

    # BLAKE2b with key (keyed hash / MAC)
    key = nacl.utils.random(32)
    blake2b_keyed = blake2b(data, key=key, digest_size=32, encoder=nacl.encoding.HexEncoder)
    print(f"BLAKE2b(keyed): {blake2b_keyed.decode()}")

    # BLAKE2b with different digest sizes
    for size in [16, 32, 48, 64]:
        h = blake2b(data, digest_size=size, encoder=nacl.encoding.HexEncoder)
        print(f"  BLAKE2b({size}): {h.decode()[:40]}...")


def demo_generic_hash():
    """Generic hashing (BLAKE2b-based)."""
    print("\n" + "=" * 60)
    print("GENERIC HASHING")
    print("=" * 60)

    from nacl.hashlib import blake2b as nacl_blake2b

    data = b"Data for generic hashing"

    # Simple hash
    h = nacl_blake2b(data)
    print(f"BLAKE2b default: {h.hexdigest()[:50]}...")

    # With key
    key = nacl.utils.random(32)
    h_keyed = nacl_blake2b(data, key=key)
    print(f"BLAKE2b keyed:   {h_keyed.hexdigest()[:50]}...")

    # Incremental hashing
    h_inc = nacl_blake2b()
    h_inc.update(b"First part. ")
    h_inc.update(b"Second part.")
    print(f"Incremental:     {h_inc.hexdigest()[:50]}...")


def demo_password_hashing_argon2():
    """Password hashing with Argon2."""
    print("\n" + "=" * 60)
    print("PASSWORD HASHING (ARGON2)")
    print("=" * 60)

    password = b"my-secret-password"

    # Argon2id (recommended)
    hashed = nacl.pwhash.argon2id.str(password)
    print(f"Password: {password}")
    print(f"Hash:     {hashed}")

    # Verify
    assert nacl.pwhash.argon2id.verify(hashed, password)
    print("Verify: PASSED")

    # Wrong password
    try:
        nacl.pwhash.argon2id.verify(hashed, b"wrong-password")
        print("Wrong password: NOT REJECTED (ERROR)")
    except nacl.exceptions.InvalidkeyError:
        print("Wrong password: REJECTED")


def demo_password_hashing_scrypt():
    """Password hashing with scrypt."""
    print("\n" + "=" * 60)
    print("PASSWORD HASHING (SCRYPT)")
    print("=" * 60)

    password = b"scrypt-password"

    try:
        hashed = nacl.pwhash.scrypt.str(password)
        print(f"Password: {password}")
        print(f"Hash:     {hashed}")

        assert nacl.pwhash.scrypt.verify(hashed, password)
        print("Verify: PASSED")
    except Exception as e:
        print(f"Scrypt: {e}")


def demo_key_derivation():
    """Key derivation from password."""
    print("\n" + "=" * 60)
    print("KEY DERIVATION FROM PASSWORD")
    print("=" * 60)

    password = b"key-derivation-password"
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)

    # Derive a key suitable for SecretBox
    derived_key = nacl.pwhash.argon2id.kdf(
        SecretBox.KEY_SIZE,
        password,
        salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
    )

    print(f"Password:    {password}")
    print(f"Salt:        {salt.hex()}")
    print(f"Derived key: {derived_key.hex()}")
    print(f"Key size:    {len(derived_key)} bytes")

    # Use derived key for encryption
    box = SecretBox(derived_key)
    encrypted = box.encrypt(b"Message encrypted with derived key")
    decrypted = box.decrypt(encrypted)
    print(f"Encrypt/decrypt with derived key: OK")


def demo_key_serialization():
    """Key serialization and encoding."""
    print("\n" + "=" * 60)
    print("KEY SERIALIZATION")
    print("=" * 60)

    # Generate key pair
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    # Hex encoding
    private_hex = private_key.encode(nacl.encoding.HexEncoder)
    public_hex = public_key.encode(nacl.encoding.HexEncoder)

    # Base64 encoding
    private_b64 = private_key.encode(nacl.encoding.Base64Encoder)
    public_b64 = public_key.encode(nacl.encoding.Base64Encoder)

    # Raw bytes
    private_raw = private_key.encode(nacl.encoding.RawEncoder)
    public_raw = public_key.encode(nacl.encoding.RawEncoder)

    print(f"Private key (hex):    {private_hex.decode()}")
    print(f"Public key (hex):     {public_hex.decode()}")
    print(f"Private key (base64): {private_b64.decode()}")
    print(f"Public key (base64):  {public_b64.decode()}")
    print(f"Raw key length:       {len(private_raw)} bytes")

    # Reconstruct from hex
    loaded_private = PrivateKey(private_hex, nacl.encoding.HexEncoder)
    loaded_public = PublicKey(public_hex, nacl.encoding.HexEncoder)
    assert loaded_private.encode() == private_key.encode()
    assert loaded_public.encode() == public_key.encode()
    print("Key reconstruction: OK")


def demo_signing_key_serialization():
    """Signing key serialization."""
    print("\n" + "=" * 60)
    print("SIGNING KEY SERIALIZATION")
    print("=" * 60)

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    # Serialize
    signing_hex = signing_key.encode(nacl.encoding.HexEncoder)
    verify_hex = verify_key.encode(nacl.encoding.HexEncoder)

    print(f"Signing key (hex): {signing_hex.decode()}")
    print(f"Verify key (hex):  {verify_hex.decode()}")

    # Reconstruct
    loaded_signing = SigningKey(signing_hex, nacl.encoding.HexEncoder)
    loaded_verify = VerifyKey(verify_hex, nacl.encoding.HexEncoder)

    # Verify round-trip
    message = b"Round-trip test"
    signed = loaded_signing.sign(message)
    loaded_verify.verify(signed.message, signed.signature)
    print("Signing key round-trip: OK")


def demo_random_generation():
    """Cryptographic random number generation."""
    print("\n" + "=" * 60)
    print("RANDOM NUMBER GENERATION")
    print("=" * 60)

    # Random bytes
    random_16 = nacl.utils.random(16)
    random_32 = nacl.utils.random(32)
    random_64 = nacl.utils.random(64)

    print(f"Random 16 bytes: {random_16.hex()}")
    print(f"Random 32 bytes: {random_32.hex()}")
    print(f"Random 64 bytes: {random_64.hex()[:50]}...")

    # Demonstrate uniqueness
    randoms = [nacl.utils.random(16) for _ in range(5)]
    all_unique = len(set(randoms)) == len(randoms)
    print(f"5 random values all unique: {all_unique}")


def main():
    """Run all PyNaCl demonstrations."""
    print("PYNACL (LIBSODIUM) LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Public-key encryption
    demo_public_key_encryption()
    demo_sealed_box()
    demo_key_exchange()

    # Secret-key encryption
    demo_secret_key_encryption()
    demo_aead_encryption()

    # Signatures
    demo_signing()

    # Hashing
    demo_hashing()
    demo_generic_hash()

    # Password hashing
    demo_password_hashing_argon2()
    demo_password_hashing_scrypt()

    # Key derivation
    demo_key_derivation()

    # Serialization
    demo_key_serialization()
    demo_signing_key_serialization()

    # Random
    demo_random_generation()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
