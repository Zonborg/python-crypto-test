"""
Comprehensive demonstration of the Python cryptography library.
Covers symmetric encryption, asymmetric encryption, hashing, key derivation,
X.509 certificates, signing, key exchange, and more.
"""

import os
import datetime
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import (
    rsa, dsa, ec, ed25519, ed448, x25519, x448, padding, dh, utils
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305, AESSIV, AESOCB3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap, aes_key_wrap_with_padding, aes_key_unwrap_with_padding
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute,
    BasicConstraints, SubjectAlternativeName, DNSName
)
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet


def demo_fernet():
    """Fernet symmetric encryption (high-level)."""
    print("\n" + "=" * 60)
    print("FERNET SYMMETRIC ENCRYPTION")
    print("=" * 60)

    key = Fernet.generate_key()
    f = Fernet(key)
    plaintext = b"Secret message for Fernet encryption"
    ciphertext = f.encrypt(plaintext)
    decrypted = f.decrypt(ciphertext)
    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext[:50]}...")
    print(f"Decrypted:  {decrypted}")


def demo_aes_cbc():
    """AES encryption in CBC mode."""
    print("\n" + "=" * 60)
    print("AES-CBC ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Pad plaintext to block size
    padder = sym_padding.PKCS7(128).padder()
    plaintext = b"AES CBC mode encryption demo"
    padded_data = padder.update(plaintext) + padder.finalize()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    assert decrypted == plaintext
    print(f"Key size: 256 bits")
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()[:50]}...")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ctr():
    """AES encryption in CTR mode."""
    print("\n" + "=" * 60)
    print("AES-CTR ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

    plaintext = b"AES CTR mode - no padding needed"
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()[:50]}...")
    print(f"Decrypted:  {decrypted}")


def demo_aes_gcm():
    """AES-GCM authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-GCM AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"Authenticated encryption with AES-GCM"
    aad = b"additional authenticated data"

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    decrypted = aesgcm.decrypt(nonce, ciphertext, aad)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"AAD:        {aad}")
    print(f"Ciphertext: {ciphertext.hex()[:50]}...")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ccm():
    """AES-CCM authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-CCM AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    nonce = os.urandom(13)
    plaintext = b"Authenticated encryption with AES-CCM"
    aad = b"ccm additional data"

    aesccm = AESCCM(key)
    ciphertext = aesccm.encrypt(nonce, plaintext, aad)
    decrypted = aesccm.decrypt(nonce, ciphertext, aad)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_chacha20poly1305():
    """ChaCha20-Poly1305 authenticated encryption."""
    print("\n" + "=" * 60)
    print("CHACHA20-POLY1305 AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"ChaCha20-Poly1305 authenticated encryption"
    aad = b"chacha aad"

    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    decrypted = chacha.decrypt(nonce, ciphertext, aad)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_siv():
    """AES-SIV nonce-misuse-resistant encryption."""
    print("\n" + "=" * 60)
    print("AES-SIV ENCRYPTION")
    print("=" * 60)

    key = os.urandom(64)  # AES-SIV requires 512-bit key for AES-256
    plaintext = b"AES-SIV nonce misuse resistant encryption"
    aad = [b"associated data"]

    aessiv = AESSIV(key)
    ciphertext = aessiv.encrypt(plaintext, aad)
    decrypted = aessiv.decrypt(ciphertext, aad)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ocb3():
    """AES-OCB3 authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-OCB3 AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"AES-OCB3 authenticated encryption demo"
    aad = b"ocb3 aad"

    aesocb = AESOCB3(key)
    ciphertext = aesocb.encrypt(nonce, plaintext, aad)
    decrypted = aesocb.decrypt(nonce, ciphertext, aad)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_cfb():
    """AES encryption in CFB mode."""
    print("\n" + "=" * 60)
    print("AES-CFB ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))

    plaintext = b"AES CFB mode encryption"
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ofb():
    """AES encryption in OFB mode."""
    print("\n" + "=" * 60)
    print("AES-OFB ENCRYPTION")
    print("=" * 60)

    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))

    plaintext = b"AES OFB mode encryption"
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ecb():
    """AES encryption in ECB mode (not recommended for most uses)."""
    print("\n" + "=" * 60)
    print("AES-ECB ENCRYPTION (NOT RECOMMENDED)")
    print("=" * 60)

    key = os.urandom(32)
    cipher = Cipher(algorithms.AES(key), modes.ECB())

    padder = sym_padding.PKCS7(128).padder()
    plaintext = b"AES ECB mode demo"
    padded_data = padder.update(plaintext) + padder.finalize()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_chacha20():
    """ChaCha20 stream cipher (without authentication)."""
    print("\n" + "=" * 60)
    print("CHACHA20 STREAM CIPHER")
    print("=" * 60)

    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)

    plaintext = b"ChaCha20 stream cipher demo"
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_triple_des():
    """Triple DES (3DES) encryption."""
    print("\n" + "=" * 60)
    print("TRIPLE DES (3DES) ENCRYPTION")
    print("=" * 60)

    key = os.urandom(24)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))

    padder = sym_padding.PKCS7(64).padder()
    plaintext = b"3DES CBC mode"
    padded_data = padder.update(plaintext) + padder.finalize()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(64).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_rsa_encryption():
    """RSA encryption and decryption with OAEP padding."""
    print("\n" + "=" * 60)
    print("RSA ENCRYPTION (OAEP)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    plaintext = b"RSA OAEP encrypted message"
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    assert decrypted == plaintext
    print(f"Key size:   2048 bits")
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_rsa_signing():
    """RSA signing and verification with PSS padding."""
    print("\n" + "=" * 60)
    print("RSA SIGNING (PSS)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    message = b"Message to be signed with RSA-PSS"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Verification (raises InvalidSignature if invalid)
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_rsa_pkcs1_signing():
    """RSA signing with PKCS1v15 padding."""
    print("\n" + "=" * 60)
    print("RSA SIGNING (PKCS1v15)")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    message = b"Message signed with PKCS1v15"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    print(f"Message:    {message}")
    print("Verification: PASSED")


def demo_dsa_signing():
    """DSA signing and verification."""
    print("\n" + "=" * 60)
    print("DSA SIGNING")
    print("=" * 60)

    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()

    message = b"Message to sign with DSA"
    signature = private_key.sign(message, hashes.SHA256())

    public_key.verify(signature, message, hashes.SHA256())
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_ec_signing():
    """Elliptic Curve (ECDSA) signing and verification."""
    print("\n" + "=" * 60)
    print("ECDSA SIGNING")
    print("=" * 60)

    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    message = b"ECDSA signed message"
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print(f"Curve:      SECP384R1")
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_ed25519():
    """Ed25519 signing and verification."""
    print("\n" + "=" * 60)
    print("ED25519 SIGNING")
    print("=" * 60)

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    message = b"Ed25519 signed message"
    signature = private_key.sign(message)

    public_key.verify(signature, message)
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_ed448():
    """Ed448 signing and verification."""
    print("\n" + "=" * 60)
    print("ED448 SIGNING")
    print("=" * 60)

    private_key = ed448.Ed448PrivateKey.generate()
    public_key = private_key.public_key()

    message = b"Ed448 signed message"
    signature = private_key.sign(message)

    public_key.verify(signature, message)
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_x25519_key_exchange():
    """X25519 Diffie-Hellman key exchange."""
    print("\n" + "=" * 60)
    print("X25519 KEY EXCHANGE")
    print("=" * 60)

    # Generate key pairs for Alice and Bob
    alice_private = x25519.X25519PrivateKey.generate()
    alice_public = alice_private.public_key()

    bob_private = x25519.X25519PrivateKey.generate()
    bob_public = bob_private.public_key()

    # Perform key exchange
    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    assert alice_shared == bob_shared
    print(f"Alice shared key: {alice_shared.hex()[:40]}...")
    print(f"Bob shared key:   {bob_shared.hex()[:40]}...")
    print("Keys match: YES")


def demo_x448_key_exchange():
    """X448 Diffie-Hellman key exchange."""
    print("\n" + "=" * 60)
    print("X448 KEY EXCHANGE")
    print("=" * 60)

    alice_private = x448.X448PrivateKey.generate()
    alice_public = alice_private.public_key()

    bob_private = x448.X448PrivateKey.generate()
    bob_public = bob_private.public_key()

    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    assert alice_shared == bob_shared
    print(f"Shared key length: {len(alice_shared)} bytes")
    print("Keys match: YES")


def demo_ecdh_key_exchange():
    """ECDH (Elliptic Curve Diffie-Hellman) key exchange."""
    print("\n" + "=" * 60)
    print("ECDH KEY EXCHANGE")
    print("=" * 60)

    alice_private = ec.generate_private_key(ec.SECP384R1())
    alice_public = alice_private.public_key()

    bob_private = ec.generate_private_key(ec.SECP384R1())
    bob_public = bob_private.public_key()

    alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
    bob_shared = bob_private.exchange(ec.ECDH(), alice_public)

    assert alice_shared == bob_shared
    print(f"Curve: SECP384R1")
    print(f"Shared key length: {len(alice_shared)} bytes")
    print("Keys match: YES")


def demo_dh_key_exchange():
    """Diffie-Hellman key exchange (classic)."""
    print("\n" + "=" * 60)
    print("DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 60)

    parameters = dh.generate_parameters(generator=2, key_size=2048)

    alice_private = parameters.generate_private_key()
    alice_public = alice_private.public_key()

    bob_private = parameters.generate_private_key()
    bob_public = bob_private.public_key()

    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    assert alice_shared == bob_shared
    print(f"Key size: 2048 bits")
    print(f"Shared key length: {len(alice_shared)} bytes")
    print("Keys match: YES")


def demo_hashes():
    """Cryptographic hash functions."""
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHIC HASH FUNCTIONS")
    print("=" * 60)

    data = b"Data to hash"
    hash_algorithms = [
        ("SHA-224", hashes.SHA224()),
        ("SHA-256", hashes.SHA256()),
        ("SHA-384", hashes.SHA384()),
        ("SHA-512", hashes.SHA512()),
        ("SHA-512/224", hashes.SHA512_224()),
        ("SHA-512/256", hashes.SHA512_256()),
        ("SHA3-224", hashes.SHA3_224()),
        ("SHA3-256", hashes.SHA3_256()),
        ("SHA3-384", hashes.SHA3_384()),
        ("SHA3-512", hashes.SHA3_512()),
        ("BLAKE2b", hashes.BLAKE2b(64)),
        ("BLAKE2s", hashes.BLAKE2s(32)),
        ("SM3", hashes.SM3()),
        ("MD5 (insecure)", hashes.MD5()),
        ("SHA-1 (insecure)", hashes.SHA1()),
    ]

    for name, algorithm in hash_algorithms:
        digest = hashes.Hash(algorithm)
        digest.update(data)
        result = digest.finalize()
        print(f"  {name:15s}: {result.hex()[:40]}...")


def demo_hmac():
    """HMAC (Hash-based Message Authentication Code)."""
    print("\n" + "=" * 60)
    print("HMAC")
    print("=" * 60)

    key = os.urandom(32)
    message = b"Message to authenticate with HMAC"

    h = HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()

    # Verify
    h = HMAC(key, hashes.SHA256())
    h.update(message)
    h.verify(signature)  # Raises InvalidSignature if invalid

    print(f"Message: {message}")
    print(f"HMAC:    {signature.hex()}")
    print("Verification: PASSED")


def demo_poly1305():
    """Poly1305 MAC."""
    print("\n" + "=" * 60)
    print("POLY1305 MAC")
    print("=" * 60)

    key = os.urandom(32)
    message = b"Poly1305 authenticated message"

    p = Poly1305(key)
    p.update(message)
    tag = p.finalize()

    # Verify
    p = Poly1305(key)
    p.update(message)
    p.verify(tag)

    print(f"Message: {message}")
    print(f"Tag:     {tag.hex()}")
    print("Verification: PASSED")


def demo_pbkdf2():
    """PBKDF2 key derivation."""
    print("\n" + "=" * 60)
    print("PBKDF2 KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    derived_key = kdf.derive(password)

    # Verify
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    kdf.verify(password, derived_key)

    print(f"Password:    {password}")
    print(f"Iterations:  600000")
    print(f"Derived key: {derived_key.hex()}")
    print("Verification: PASSED")


def demo_scrypt():
    """Scrypt key derivation."""
    print("\n" + "=" * 60)
    print("SCRYPT KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = os.urandom(16)

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    derived_key = kdf.derive(password)

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    kdf.verify(password, derived_key)

    print(f"Password:    {password}")
    print(f"Parameters:  n=16384, r=8, p=1")
    print(f"Derived key: {derived_key.hex()}")
    print("Verification: PASSED")


def demo_hkdf():
    """HKDF key derivation."""
    print("\n" + "=" * 60)
    print("HKDF KEY DERIVATION")
    print("=" * 60)

    input_key = os.urandom(32)
    salt = os.urandom(16)
    info = b"hkdf-demo"

    # Full HKDF (extract + expand)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    derived_key = hkdf.derive(input_key)

    # HKDF Expand only
    hkdf_expand = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info)
    expanded_key = hkdf_expand.derive(input_key)

    print(f"HKDF derived:  {derived_key.hex()}")
    print(f"HKDF expanded: {expanded_key.hex()}")


def demo_concat_kdf():
    """ConcatKDF key derivation."""
    print("\n" + "=" * 60)
    print("CONCAT KDF KEY DERIVATION")
    print("=" * 60)

    input_key = os.urandom(32)
    otherinfo = b"concat-kdf-demo"

    # ConcatKDF with Hash
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=otherinfo)
    derived_key = ckdf.derive(input_key)

    # ConcatKDF with HMAC
    salt = os.urandom(16)
    ckdf_hmac = ConcatKDFHMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, otherinfo=otherinfo
    )
    derived_key_hmac = ckdf_hmac.derive(input_key)

    print(f"ConcatKDFHash:  {derived_key.hex()}")
    print(f"ConcatKDFHMAC:  {derived_key_hmac.hex()}")


def demo_x963_kdf():
    """X9.63 KDF key derivation."""
    print("\n" + "=" * 60)
    print("X9.63 KDF KEY DERIVATION")
    print("=" * 60)

    input_key = os.urandom(32)
    sharedinfo = b"x963-kdf-demo"

    xkdf = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=sharedinfo)
    derived_key = xkdf.derive(input_key)

    print(f"X9.63 KDF derived: {derived_key.hex()}")


def demo_kbkdf():
    """KBKDF (Key-Based Key Derivation Function)."""
    print("\n" + "=" * 60)
    print("KBKDF KEY DERIVATION")
    print("=" * 60)

    input_key = os.urandom(32)
    label = b"kbkdf-label"
    context = b"kbkdf-context"

    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
    )
    derived_key = kdf.derive(input_key)

    print(f"KBKDF derived: {derived_key.hex()}")


def demo_key_wrapping():
    """AES Key Wrapping (RFC 3394 and RFC 5649)."""
    print("\n" + "=" * 60)
    print("AES KEY WRAPPING")
    print("=" * 60)

    wrapping_key = os.urandom(32)
    key_to_wrap = os.urandom(32)

    # RFC 3394 (key must be multiple of 8 bytes)
    wrapped = aes_key_wrap(wrapping_key, key_to_wrap)
    unwrapped = aes_key_unwrap(wrapping_key, wrapped)
    assert unwrapped == key_to_wrap
    print(f"RFC 3394 wrap/unwrap: PASSED")

    # RFC 5649 (with padding, any key length)
    key_to_wrap_odd = os.urandom(25)
    wrapped_padded = aes_key_wrap_with_padding(wrapping_key, key_to_wrap_odd)
    unwrapped_padded = aes_key_unwrap_with_padding(wrapping_key, wrapped_padded)
    assert unwrapped_padded == key_to_wrap_odd
    print(f"RFC 5649 wrap/unwrap (with padding): PASSED")


def demo_totp():
    """Time-based One-Time Password (TOTP)."""
    print("\n" + "=" * 60)
    print("TOTP (TIME-BASED ONE-TIME PASSWORD)")
    print("=" * 60)

    key = os.urandom(20)
    totp = TOTP(key, 6, hashes.SHA1(), 30)
    time_value = int(datetime.datetime.now().timestamp())
    token = totp.generate(time_value)

    totp.verify(token, time_value)
    print(f"TOTP token: {token.decode()}")
    print("Verification: PASSED")


def demo_hotp():
    """HMAC-based One-Time Password (HOTP)."""
    print("\n" + "=" * 60)
    print("HOTP (HMAC-BASED ONE-TIME PASSWORD)")
    print("=" * 60)

    key = os.urandom(20)
    hotp = HOTP(key, 6, hashes.SHA1())
    counter = 0
    token = hotp.generate(counter)

    hotp.verify(token, counter)
    print(f"HOTP token (counter=0): {token.decode()}")
    print("Verification: PASSED")


def demo_key_serialization():
    """Key serialization and deserialization."""
    print("\n" + "=" * 60)
    print("KEY SERIALIZATION")
    print("=" * 60)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # PEM encoding (private key)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password123")
    )

    # PEM encoding (public key)
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # DER encoding
    der_private = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Load back
    loaded_private = serialization.load_pem_private_key(pem_private, password=b"password123")
    loaded_public = serialization.load_pem_public_key(pem_public)
    loaded_der = serialization.load_der_private_key(der_private, password=None)

    print(f"PEM private key: {pem_private[:50]}...")
    print(f"PEM public key:  {pem_public[:50]}...")
    print(f"DER private key: {len(der_private)} bytes")
    print("Load PEM private: OK")
    print("Load PEM public:  OK")
    print("Load DER private: OK")


def demo_x509_certificate():
    """X.509 certificate generation and inspection."""
    print("\n" + "=" * 60)
    print("X.509 CERTIFICATE")
    print("=" * 60)

    # Generate CA key and self-signed cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "England"),
        NameAttribute(NameOID.LOCALITY_NAME, "London"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "Demo CA"),
        NameAttribute(NameOID.COMMON_NAME, "Demo Certificate Authority"),
    ])

    ca_cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(1000)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Generate end-entity certificate signed by CA
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ee_subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        NameAttribute(NameOID.COMMON_NAME, "demo.example.com"),
    ])

    ee_cert = (
        CertificateBuilder()
        .subject_name(ee_subject)
        .issuer_name(ca_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(2000)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(
            SubjectAlternativeName([DNSName("demo.example.com"), DNSName("www.demo.example.com")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Serialize cert to PEM
    cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM)

    print(f"CA Subject:   {ca_cert.subject.rfc4514_string()}")
    print(f"EE Subject:   {ee_cert.subject.rfc4514_string()}")
    print(f"EE Issuer:    {ee_cert.issuer.rfc4514_string()}")
    print(f"EE Serial:    {ee_cert.serial_number}")
    print(f"EE Not After: {ee_cert.not_valid_after}")
    print(f"EE PEM:       {cert_pem[:50]}...")


def demo_csr():
    """Certificate Signing Request (CSR)."""
    print("\n" + "=" * 60)
    print("CERTIFICATE SIGNING REQUEST (CSR)")
    print("=" * 60)

    from cryptography.x509 import CertificateSigningRequestBuilder

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([
            NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            NameAttribute(NameOID.COMMON_NAME, "csr.example.com"),
        ]))
        .add_extension(
            SubjectAlternativeName([DNSName("csr.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    print(f"CSR Subject: {csr.subject.rfc4514_string()}")
    print(f"CSR PEM:     {csr_pem[:50]}...")
    print(f"CSR Valid:   {csr.is_signature_valid}")


def demo_crl():
    """Certificate Revocation List (CRL)."""
    print("\n" + "=" * 60)
    print("CERTIFICATE REVOCATION LIST (CRL)")
    print("=" * 60)

    from cryptography.x509 import (
        CertificateRevocationListBuilder,
        RevokedCertificateBuilder,
    )

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = Name([NameAttribute(NameOID.COMMON_NAME, "Demo CA")])

    # Create a revoked certificate entry
    revoked = (
        RevokedCertificateBuilder()
        .serial_number(1234)
        .revocation_date(datetime.datetime.now(datetime.timezone.utc))
        .build()
    )

    # Build CRL
    crl = (
        CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(datetime.datetime.now(datetime.timezone.utc))
        .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )

    crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    print(f"CRL Issuer:     {crl.issuer.rfc4514_string()}")
    print(f"CRL entries:    {len(list(crl))}")
    print(f"CRL PEM:        {crl_pem[:50]}...")


def demo_prehashed():
    """Signing with prehashed data."""
    print("\n" + "=" * 60)
    print("PREHASHED SIGNING")
    print("=" * 60)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    message = b"Message to prehash before signing"
    # Prehash the message
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    digest = hasher.finalize()

    # Sign the prehashed digest
    signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    # Verify with prehashed digest
    public_key.verify(
        signature,
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    print(f"Digest:  {digest.hex()}")
    print("Verification: PASSED")


def demo_ec_curves():
    """Demonstrate multiple EC curves."""
    print("\n" + "=" * 60)
    print("ELLIPTIC CURVE VARIETIES")
    print("=" * 60)

    curves = [
        ec.SECP192R1(),
        ec.SECP224R1(),
        ec.SECP256R1(),
        ec.SECP384R1(),
        ec.SECP521R1(),
        ec.SECP256K1(),
        ec.BrainpoolP256R1(),
        ec.BrainpoolP384R1(),
        ec.BrainpoolP512R1(),
    ]

    message = b"Test message for EC curves"
    for curve in curves:
        private_key = ec.generate_private_key(curve)
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        private_key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print(f"  {curve.name:25s} (key_size={curve.key_size}): OK")


def demo_aes_gcm_cipher_mode():
    """AES-GCM via low-level Cipher API."""
    print("\n" + "=" * 60)
    print("AES-GCM (LOW-LEVEL CIPHER API)")
    print("=" * 60)

    key = os.urandom(32)
    iv = os.urandom(12)
    plaintext = b"Low-level AES-GCM encryption"
    aad = b"extra data"

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")
    print(f"Tag:        {tag.hex()}")


def demo_xof():
    """Extendable Output Functions (SHAKE128, SHAKE256)."""
    print("\n" + "=" * 60)
    print("EXTENDABLE OUTPUT FUNCTIONS (XOF)")
    print("=" * 60)

    from cryptography.hazmat.primitives.hashes import SHAKE128, SHAKE256

    data = b"Data for XOF hashing"

    # SHAKE128
    digest = hashes.Hash(SHAKE128(32))
    digest.update(data)
    result128 = digest.finalize()

    # SHAKE256
    digest = hashes.Hash(SHAKE256(64))
    digest.update(data)
    result256 = digest.finalize()

    print(f"SHAKE128(32): {result128.hex()}")
    print(f"SHAKE256(64): {result256.hex()}")


def main():
    """Run all cryptographic demonstrations."""
    print("PYTHON CRYPTOGRAPHY LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Symmetric Encryption
    demo_fernet()
    demo_aes_cbc()
    demo_aes_ctr()
    demo_aes_cfb()
    demo_aes_ofb()
    demo_aes_ecb()
    demo_aes_gcm()
    demo_aes_ccm()
    demo_chacha20poly1305()
    demo_aes_siv()
    demo_aes_ocb3()
    demo_chacha20()
    demo_triple_des()
    demo_aes_gcm_cipher_mode()

    # Asymmetric Encryption
    demo_rsa_encryption()

    # Digital Signatures
    demo_rsa_signing()
    demo_rsa_pkcs1_signing()
    demo_dsa_signing()
    demo_ec_signing()
    demo_ed25519()
    demo_ed448()
    demo_prehashed()
    demo_ec_curves()

    # Key Exchange
    demo_x25519_key_exchange()
    demo_x448_key_exchange()
    demo_ecdh_key_exchange()
    demo_dh_key_exchange()

    # Hashing
    demo_hashes()
    demo_xof()

    # MACs
    demo_hmac()
    demo_poly1305()

    # Key Derivation
    demo_pbkdf2()
    demo_scrypt()
    demo_hkdf()
    demo_concat_kdf()
    demo_x963_kdf()
    demo_kbkdf()

    # Key Wrapping
    demo_key_wrapping()

    # Two-Factor Authentication
    demo_totp()
    demo_hotp()

    # Key Serialization
    demo_key_serialization()

    # X.509 / PKI
    demo_x509_certificate()
    demo_csr()
    demo_crl()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
