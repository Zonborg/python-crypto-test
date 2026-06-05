"""
Comprehensive demonstration of the PyCryptodome library.
Covers symmetric encryption (AES, DES3, ChaCha20), asymmetric encryption (RSA, ECC, DSA),
hashing, MACs, key derivation, and digital signatures.
"""

import os
from Crypto.Cipher import AES, DES3, ChaCha20, ChaCha20_Poly1305, Salsa20, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Hash import (
    SHA256, SHA384, SHA512, SHA224, SHA3_256, SHA3_384, SHA3_512,
    BLAKE2b, BLAKE2s, HMAC, MD5, SHA1, SHAKE128, SHAKE256,
    CMAC, Poly1305, KMAC128, KMAC256, TupleHash128, TupleHash256,
    KangarooTwelve, cSHAKE128, cSHAKE256
)
from Crypto.Protocol.KDF import PBKDF2, scrypt, HKDF, bcrypt as crypto_bcrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def demo_aes_cbc():
    """AES encryption in CBC mode."""
    print("\n" + "=" * 60)
    print("AES-CBC ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"AES CBC mode encryption with PyCryptodome"
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = cipher.iv

    cipher_dec = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher_dec.decrypt(ciphertext), AES.block_size)

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

    key = get_random_bytes(32)
    plaintext = b"AES CTR mode - no padding needed"
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce

    cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher_dec.decrypt(ciphertext)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()[:50]}...")
    print(f"Decrypted:  {decrypted}")


def demo_aes_gcm():
    """AES-GCM authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-GCM AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"Authenticated encryption with AES-GCM"
    aad = b"additional authenticated data"

    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    cipher_dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"AAD:        {aad}")
    print(f"Ciphertext: {ciphertext.hex()[:50]}...")
    print(f"Tag:        {tag.hex()}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ccm():
    """AES-CCM authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-CCM AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(16)
    plaintext = b"AES-CCM authenticated encryption"
    aad = b"ccm associated data"

    cipher = AES.new(key, AES.MODE_CCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    cipher_dec = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_eax():
    """AES-EAX authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-EAX AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"AES-EAX mode authenticated encryption"
    aad = b"eax header data"

    cipher = AES.new(key, AES.MODE_EAX)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    cipher_dec = AES.new(key, AES.MODE_EAX, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_siv():
    """AES-SIV nonce-misuse-resistant encryption."""
    print("\n" + "=" * 60)
    print("AES-SIV ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"AES-SIV nonce misuse resistant encryption"
    aad = [b"associated data component"]

    cipher = AES.new(key, AES.MODE_SIV)
    for component in aad:
        cipher.update(component)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    cipher_dec = AES.new(key, AES.MODE_SIV)
    for component in aad:
        cipher_dec.update(component)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ocb():
    """AES-OCB authenticated encryption."""
    print("\n" + "=" * 60)
    print("AES-OCB AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(16)
    plaintext = b"AES-OCB authenticated encryption demo"
    aad = b"ocb associated data"

    cipher = AES.new(key, AES.MODE_OCB)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    cipher_dec = AES.new(key, AES.MODE_OCB, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_cfb():
    """AES encryption in CFB mode."""
    print("\n" + "=" * 60)
    print("AES-CFB ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"AES CFB mode encryption"

    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(plaintext)
    iv = cipher.iv

    cipher_dec = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted = cipher_dec.decrypt(ciphertext)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_aes_ofb():
    """AES encryption in OFB mode."""
    print("\n" + "=" * 60)
    print("AES-OFB ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"AES OFB mode encryption"

    cipher = AES.new(key, AES.MODE_OFB)
    ciphertext = cipher.encrypt(plaintext)
    iv = cipher.iv

    cipher_dec = AES.new(key, AES.MODE_OFB, iv=iv)
    decrypted = cipher_dec.decrypt(ciphertext)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_triple_des():
    """Triple DES (3DES) encryption."""
    print("\n" + "=" * 60)
    print("TRIPLE DES (3DES) ENCRYPTION")
    print("=" * 60)

    key = DES3.adjust_key_parity(get_random_bytes(24))
    plaintext = b"3DES encryption demo"

    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    iv = cipher.iv

    cipher_dec = DES3.new(key, DES3.MODE_CBC, iv=iv)
    decrypted = unpad(cipher_dec.decrypt(ciphertext), DES3.block_size)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_chacha20():
    """ChaCha20 stream cipher."""
    print("\n" + "=" * 60)
    print("CHACHA20 STREAM CIPHER")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"ChaCha20 stream cipher demo"

    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce

    cipher_dec = ChaCha20.new(key=key, nonce=nonce)
    decrypted = cipher_dec.decrypt(ciphertext)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_chacha20_poly1305():
    """ChaCha20-Poly1305 authenticated encryption."""
    print("\n" + "=" * 60)
    print("CHACHA20-POLY1305 AUTHENTICATED ENCRYPTION")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"ChaCha20-Poly1305 AEAD encryption"
    aad = b"additional data"

    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    cipher_dec = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_salsa20():
    """Salsa20 stream cipher."""
    print("\n" + "=" * 60)
    print("SALSA20 STREAM CIPHER")
    print("=" * 60)

    key = get_random_bytes(32)
    plaintext = b"Salsa20 stream cipher demo"

    cipher = Salsa20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce

    cipher_dec = Salsa20.new(key=key, nonce=nonce)
    decrypted = cipher_dec.decrypt(ciphertext)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_rsa_oaep():
    """RSA encryption with OAEP padding."""
    print("\n" + "=" * 60)
    print("RSA ENCRYPTION (OAEP)")
    print("=" * 60)

    key = RSA.generate(2048)
    public_key = key.publickey()

    plaintext = b"RSA OAEP encrypted message"
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)

    cipher_dec = PKCS1_OAEP.new(key)
    decrypted = cipher_dec.decrypt(ciphertext)

    assert decrypted == plaintext
    print(f"Key size:   2048 bits")
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_rsa_pkcs1v15_encryption():
    """RSA encryption with PKCS#1 v1.5 padding."""
    print("\n" + "=" * 60)
    print("RSA ENCRYPTION (PKCS1v15)")
    print("=" * 60)

    key = RSA.generate(2048)
    public_key = key.publickey()

    plaintext = b"RSA PKCS1v15 encrypted"
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext)

    cipher_dec = PKCS1_v1_5.new(key)
    decrypted = cipher_dec.decrypt(ciphertext, sentinel=None)

    assert decrypted == plaintext
    print(f"Plaintext:  {plaintext}")
    print(f"Decrypted:  {decrypted}")


def demo_rsa_pss_signing():
    """RSA signing with PSS padding."""
    print("\n" + "=" * 60)
    print("RSA SIGNING (PSS)")
    print("=" * 60)

    key = RSA.generate(2048)
    public_key = key.publickey()

    message = b"Message to sign with RSA-PSS"
    h = SHA256.new(message)

    signer = pss.new(key)
    signature = signer.sign(h)

    verifier = pss.new(public_key)
    h_verify = SHA256.new(message)
    verifier.verify(h_verify, signature)

    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_rsa_pkcs1_signing():
    """RSA signing with PKCS#1 v1.5."""
    print("\n" + "=" * 60)
    print("RSA SIGNING (PKCS1v15)")
    print("=" * 60)

    key = RSA.generate(2048)
    public_key = key.publickey()

    message = b"Message signed with PKCS1v15"
    h = SHA256.new(message)

    signer = pkcs1_15.new(key)
    signature = signer.sign(h)

    verifier = pkcs1_15.new(public_key)
    h_verify = SHA256.new(message)
    verifier.verify(h_verify, signature)

    print(f"Message:    {message}")
    print("Verification: PASSED")


def demo_dsa_signing():
    """DSA signing and verification."""
    print("\n" + "=" * 60)
    print("DSA SIGNING")
    print("=" * 60)

    key = DSA.generate(2048)
    public_key = key.publickey()

    message = b"Message to sign with DSA"
    h = SHA256.new(message)

    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)

    verifier = DSS.new(public_key, 'fips-186-3')
    h_verify = SHA256.new(message)
    verifier.verify(h_verify, signature)

    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_ecdsa_signing():
    """ECDSA signing and verification."""
    print("\n" + "=" * 60)
    print("ECDSA SIGNING")
    print("=" * 60)

    key = ECC.generate(curve='P-256')
    public_key = key.public_key()

    message = b"ECDSA signed message"
    h = SHA256.new(message)

    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)

    verifier = DSS.new(public_key, 'fips-186-3')
    h_verify = SHA256.new(message)
    verifier.verify(h_verify, signature)

    print(f"Curve:      P-256")
    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_eddsa_signing():
    """EdDSA (Ed25519) signing and verification."""
    print("\n" + "=" * 60)
    print("EDDSA (ED25519) SIGNING")
    print("=" * 60)

    from Crypto.Signature import eddsa

    key = ECC.generate(curve='Ed25519')
    public_key = key.public_key()

    message = b"Ed25519 signed message"

    signer = eddsa.new(key, 'rfc8032')
    signature = signer.sign(message)

    verifier = eddsa.new(public_key, 'rfc8032')
    verifier.verify(message, signature)

    print(f"Message:    {message}")
    print(f"Signature:  {signature.hex()[:50]}...")
    print("Verification: PASSED")


def demo_hashes():
    """Cryptographic hash functions."""
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHIC HASH FUNCTIONS")
    print("=" * 60)

    data = b"Data to hash"
    hash_classes = [
        ("SHA-224", SHA224),
        ("SHA-256", SHA256),
        ("SHA-384", SHA384),
        ("SHA-512", SHA512),
        ("SHA3-256", SHA3_256),
        ("SHA3-384", SHA3_384),
        ("SHA3-512", SHA3_512),
        ("BLAKE2b", lambda: BLAKE2b.new(digest_bytes=64)),
        ("BLAKE2s", lambda: BLAKE2s.new(digest_bytes=32)),
        ("MD5 (insecure)", MD5),
        ("SHA-1 (insecure)", SHA1),
    ]

    for name, hash_cls in hash_classes:
        if callable(hash_cls) and not hasattr(hash_cls, 'new'):
            h = hash_cls()
        else:
            h = hash_cls.new()
        h.update(data)
        print(f"  {name:15s}: {h.hexdigest()[:40]}...")


def demo_xof():
    """Extendable Output Functions (SHAKE, cSHAKE, KangarooTwelve)."""
    print("\n" + "=" * 60)
    print("EXTENDABLE OUTPUT FUNCTIONS (XOF)")
    print("=" * 60)

    data = b"Data for XOF hashing"

    shake128 = SHAKE128.new()
    shake128.update(data)
    result128 = shake128.read(32)

    shake256 = SHAKE256.new()
    shake256.update(data)
    result256 = shake256.read(64)

    cshake128 = cSHAKE128.new(custom=b"demo")
    cshake128.update(data)
    cshake_result = cshake128.read(32)

    k12 = KangarooTwelve.new(custom=b"demo")
    k12.update(data)
    k12_result = k12.read(32)

    print(f"SHAKE128(32):      {result128.hex()}")
    print(f"SHAKE256(64):      {result256.hex()[:40]}...")
    print(f"cSHAKE128(32):     {cshake_result.hex()}")
    print(f"KangarooTwelve:    {k12_result.hex()}")


def demo_hmac():
    """HMAC (Hash-based Message Authentication Code)."""
    print("\n" + "=" * 60)
    print("HMAC")
    print("=" * 60)

    key = get_random_bytes(32)
    message = b"Message to authenticate with HMAC"

    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    mac = h.hexdigest()

    # Verify
    h_verify = HMAC.new(key, digestmod=SHA256)
    h_verify.update(message)
    h_verify.hexverify(mac)

    print(f"Message: {message}")
    print(f"HMAC:    {mac}")
    print("Verification: PASSED")


def demo_cmac():
    """CMAC (Cipher-based MAC)."""
    print("\n" + "=" * 60)
    print("CMAC")
    print("=" * 60)

    key = get_random_bytes(16)
    message = b"Message for CMAC authentication"

    mac = CMAC.new(key, ciphermod=AES)
    mac.update(message)
    tag = mac.hexdigest()

    # Verify
    mac_verify = CMAC.new(key, ciphermod=AES)
    mac_verify.update(message)
    mac_verify.hexverify(tag)

    print(f"Message: {message}")
    print(f"CMAC:    {tag}")
    print("Verification: PASSED")


def demo_kmac():
    """KMAC (Keccak-based MAC)."""
    print("\n" + "=" * 60)
    print("KMAC")
    print("=" * 60)

    key = get_random_bytes(32)
    data = b"Data for KMAC authentication"

    mac128 = KMAC128.new(key=key, mac_len=16)
    mac128.update(data)
    tag128 = mac128.hexdigest()

    mac256 = KMAC256.new(key=key, mac_len=32)
    mac256.update(data)
    tag256 = mac256.hexdigest()

    print(f"KMAC128: {tag128}")
    print(f"KMAC256: {tag256}")


def demo_tuple_hash():
    """TupleHash."""
    print("\n" + "=" * 60)
    print("TUPLEHASH")
    print("=" * 60)

    data1 = b"first element"
    data2 = b"second element"

    th128 = TupleHash128.new(digest_bytes=32)
    th128.update(data1)
    th128.update(data2)
    result128 = th128.hexdigest()

    th256 = TupleHash256.new(digest_bytes=64)
    th256.update(data1)
    th256.update(data2)
    result256 = th256.hexdigest()

    print(f"TupleHash128: {result128}")
    print(f"TupleHash256: {result256[:40]}...")


def demo_pbkdf2():
    """PBKDF2 key derivation."""
    print("\n" + "=" * 60)
    print("PBKDF2 KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = get_random_bytes(16)

    derived_key = PBKDF2(password, salt, dkLen=32, count=600000, prf=lambda p, s: HMAC.new(p, s, SHA256).digest())

    print(f"Password:    {password}")
    print(f"Iterations:  600000")
    print(f"Derived key: {derived_key.hex()}")


def demo_scrypt_kdf():
    """Scrypt key derivation."""
    print("\n" + "=" * 60)
    print("SCRYPT KEY DERIVATION")
    print("=" * 60)

    password = b"my-secret-password"
    salt = get_random_bytes(16)

    derived_key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

    print(f"Password:    {password}")
    print(f"Parameters:  N=16384, r=8, p=1")
    print(f"Derived key: {derived_key.hex()}")


def demo_hkdf():
    """HKDF key derivation."""
    print("\n" + "=" * 60)
    print("HKDF KEY DERIVATION")
    print("=" * 60)

    master_key = get_random_bytes(32)
    salt = get_random_bytes(16)

    derived_key = HKDF(master_key, 32, salt, SHA256)

    print(f"HKDF derived key: {derived_key.hex()}")


def demo_key_serialization():
    """RSA and ECC key serialization."""
    print("\n" + "=" * 60)
    print("KEY SERIALIZATION")
    print("=" * 60)

    # RSA key
    rsa_key = RSA.generate(2048)
    rsa_pem = rsa_key.export_key(format='PEM', passphrase='password123', pkcs=8, protection='scryptAndAES256-CBC')
    rsa_pub_pem = rsa_key.publickey().export_key(format='PEM')
    rsa_der = rsa_key.export_key(format='DER')

    # Load back
    loaded_rsa = RSA.import_key(rsa_pem, passphrase='password123')
    loaded_pub = RSA.import_key(rsa_pub_pem)

    # ECC key
    ecc_key = ECC.generate(curve='P-256')
    ecc_pem = ecc_key.export_key(format='PEM')
    ecc_pub_pem = ecc_key.public_key().export_key(format='PEM')

    print(f"RSA PEM private: {rsa_pem[:50]}...")
    print(f"RSA PEM public:  {rsa_pub_pem[:50]}...")
    print(f"RSA DER length:  {len(rsa_der)} bytes")
    print(f"ECC PEM private: {ecc_pem[:50]}...")
    print(f"ECC PEM public:  {ecc_pub_pem[:50]}...")
    print("Load RSA private: OK")
    print("Load RSA public:  OK")


def demo_ec_curves():
    """Demonstrate multiple ECC curves."""
    print("\n" + "=" * 60)
    print("ELLIPTIC CURVE VARIETIES")
    print("=" * 60)

    curves = ['P-256', 'P-384', 'P-521', 'Ed25519', 'Ed448', 'Curve25519', 'Curve448']
    message = b"Test message for EC curves"

    for curve_name in curves:
        key = ECC.generate(curve=curve_name)
        if curve_name.startswith('Ed'):
            from Crypto.Signature import eddsa
            signer = eddsa.new(key, 'rfc8032')
            signature = signer.sign(message)
            verifier = eddsa.new(key.public_key(), 'rfc8032')
            verifier.verify(message, signature)
            print(f"  {curve_name:15s}: Sign/Verify OK")
        elif curve_name.startswith('Curve'):
            print(f"  {curve_name:15s}: Key generation OK (DH curve)")
        else:
            h = SHA256.new(message)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            verifier = DSS.new(key.public_key(), 'fips-186-3')
            verifier.verify(SHA256.new(message), signature)
            print(f"  {curve_name:15s}: Sign/Verify OK")


def main():
    """Run all PyCryptodome demonstrations."""
    print("PYCRYPTODOME LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Symmetric Encryption
    demo_aes_cbc()
    demo_aes_ctr()
    demo_aes_gcm()
    demo_aes_ccm()
    demo_aes_eax()
    demo_aes_siv()
    demo_aes_ocb()
    demo_aes_cfb()
    demo_aes_ofb()
    demo_triple_des()
    demo_chacha20()
    demo_chacha20_poly1305()
    demo_salsa20()

    # Asymmetric Encryption
    demo_rsa_oaep()
    demo_rsa_pkcs1v15_encryption()

    # Digital Signatures
    demo_rsa_pss_signing()
    demo_rsa_pkcs1_signing()
    demo_dsa_signing()
    demo_ecdsa_signing()
    demo_eddsa_signing()
    demo_ec_curves()

    # Hashing
    demo_hashes()
    demo_xof()

    # MACs
    demo_hmac()
    demo_cmac()
    demo_kmac()
    demo_tuple_hash()

    # Key Derivation
    demo_pbkdf2()
    demo_scrypt_kdf()
    demo_hkdf()

    # Key Serialization
    demo_key_serialization()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
