"""
Comprehensive demonstration of the PyKCS11 library.
Covers PKCS#11 slot/token enumeration, session management, key generation
(symmetric AES and asymmetric RSA/EC), signing, verification, encryption,
decryption, digest/hashing, and object management.

PyKCS11 is a Python wrapper around PKCS#11 (Cryptoki), the standard API for
Hardware Security Modules (HSMs) and smart cards.  This demo targets SoftHSM2
(a software-only PKCS#11 implementation) but works with any compliant library.

Prerequisites (one of):
  - SoftHSM2 installed and a token initialised:
      softhsm2-util --init-token --slot 0 --label "Demo" --pin 1234 --so-pin 12345678
  - Any other PKCS#11 library (e.g. OpenSC, YubiKey PKCS#11, AWS CloudHSM).

Set the PYKCS11LIB environment variable to the full path of the .so / .dll,
or let PyKCS11 find a default library.
"""

import os
import sys
import hashlib

try:
    import PyKCS11
    from PyKCS11 import PyKCS11Error
    from PyKCS11.LowLevel import (
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_EC_KEY_PAIR_GEN,
        CKM_AES_KEY_GEN,
        CKM_SHA256,
        CKM_SHA384,
        CKM_SHA512,
        CKM_SHA_1,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_AES_CBC_PAD,
        CKM_AES_GCM,
        CKO_PRIVATE_KEY,
        CKO_PUBLIC_KEY,
        CKO_SECRET_KEY,
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_LABEL,
        CKA_ID,
        CKA_MODULUS_BITS,
        CKA_PUBLIC_EXPONENT,
        CKA_ENCRYPT,
        CKA_DECRYPT,
        CKA_SIGN,
        CKA_VERIFY,
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_SENSITIVE,
        CKA_EXTRACTABLE,
        CKA_VALUE_LEN,
        CKK_RSA,
        CKK_EC,
        CKK_AES,
    )
    PYKCS11_AVAILABLE = True
except ImportError:
    PYKCS11_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_pkcs11_lib() -> str | None:
    """Try to locate a PKCS#11 library automatically."""
    candidates = [
        os.environ.get("PYKCS11LIB", ""),
        # SoftHSM2 – Linux
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        # SoftHSM2 – macOS (Homebrew)
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
        # SoftHSM2 – Windows
        r"C:\SoftHSM2\lib\softhsm2-x64.dll",
        r"C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll",
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _load_library() -> "PyKCS11.PyKCS11Lib | None":
    """Load the PKCS#11 library and return the library object, or None."""
    if not PYKCS11_AVAILABLE:
        print("PyKCS11 is not installed – skipping all PKCS#11 demos.")
        return None

    lib_path = _find_pkcs11_lib()
    if lib_path is None:
        print(
            "No PKCS#11 library found.\n"
            "Install SoftHSM2 or set the PYKCS11LIB environment variable.\n"
            "Skipping all PKCS#11 demos."
        )
        return None

    lib = PyKCS11.PyKCS11Lib()
    try:
        lib.load(lib_path)
        print(f"Loaded PKCS#11 library: {lib_path}")
        return lib
    except PyKCS11Error as exc:
        print(f"Failed to load PKCS#11 library '{lib_path}': {exc}")
        return None


def _open_session(lib, pin: str = "1234") -> tuple["PyKCS11.Session | None", int]:
    """Open an RW user session on the first available slot with a token."""
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        print("No token-present slots found – initialise a SoftHSM2 token first.")
        return None, -1

    slot = slots[0]
    session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    session.login(pin)
    return session, slot


# ---------------------------------------------------------------------------
# Demo functions
# ---------------------------------------------------------------------------

def demo_slot_info(lib):
    """List all PKCS#11 slots and token information."""
    print("\n" + "=" * 60)
    print("SLOT AND TOKEN INFORMATION")
    print("=" * 60)

    all_slots = lib.getSlotList(tokenPresent=False)
    present_slots = lib.getSlotList(tokenPresent=True)

    print(f"Total slots:           {len(all_slots)}")
    print(f"Slots with token:      {len(present_slots)}")

    for slot_id in present_slots:
        info = lib.getTokenInfo(slot_id)
        slot_info = lib.getSlotInfo(slot_id)
        print(f"\n  Slot {slot_id}:")
        print(f"    Slot description:  {slot_info.slotDescription.strip()}")
        print(f"    Token label:       {info.label.strip()}")
        print(f"    Manufacturer:      {info.manufacturerID.strip()}")
        print(f"    Model:             {info.model.strip()}")
        print(f"    Serial number:     {info.serialNumber.strip()}")
        flags = info.flags
        print(f"    Token initialised: {bool(flags & PyKCS11.CKF_TOKEN_INITIALIZED)}")
        print(f"    Login required:    {bool(flags & PyKCS11.CKF_LOGIN_REQUIRED)}")


def demo_mechanism_list(lib, slot_id: int):
    """List supported cryptographic mechanisms."""
    print("\n" + "=" * 60)
    print("SUPPORTED MECHANISMS")
    print("=" * 60)

    mechanisms = lib.getMechanismList(slot_id)
    print(f"Total mechanisms supported: {len(mechanisms)}")

    # Show a curated subset
    interesting = [
        "CKM_RSA_PKCS",
        "CKM_RSA_PKCS_KEY_PAIR_GEN",
        "CKM_SHA256_RSA_PKCS",
        "CKM_SHA256_RSA_PKCS_PSS",
        "CKM_EC_KEY_PAIR_GEN",
        "CKM_ECDSA",
        "CKM_ECDSA_SHA256",
        "CKM_AES_KEY_GEN",
        "CKM_AES_CBC",
        "CKM_AES_GCM",
        "CKM_SHA256",
        "CKM_SHA512",
    ]
    for name in interesting:
        present = name in [str(m) for m in mechanisms]
        status = "YES" if present else "no"
        print(f"  {name:<35} {status}")


def demo_rsa_key_pair(session):
    """Generate an RSA-2048 key pair, sign and verify data."""
    print("\n" + "=" * 60)
    print("RSA-2048 KEY PAIR GENERATION + SIGN/VERIFY")
    print("=" * 60)

    pub_template = [
        (CKA_TOKEN, False),
        (CKA_ENCRYPT, True),
        (CKA_VERIFY, True),
        (CKA_MODULUS_BITS, 2048),
        (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),  # 65537
        (CKA_LABEL, "demo-rsa-pub"),
    ]
    priv_template = [
        (CKA_TOKEN, False),
        (CKA_PRIVATE, True),
        (CKA_SENSITIVE, True),
        (CKA_DECRYPT, True),
        (CKA_SIGN, True),
        (CKA_LABEL, "demo-rsa-priv"),
    ]

    pub_key, priv_key = session.generateKeyPair(
        pub_template,
        priv_template,
        mecha=PyKCS11.Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN),
    )
    print("RSA-2048 key pair generated.")

    data = b"RSA sign/verify test with PyKCS11"

    # Sign with SHA-256 + RSA PKCS#1 v1.5
    signature = session.sign(
        priv_key,
        data,
        PyKCS11.Mechanism(CKM_SHA256_RSA_PKCS),
    )
    sig_bytes = bytes(signature)
    print(f"Signature ({len(sig_bytes)} bytes): {sig_bytes.hex()[:40]}...")

    # Verify
    try:
        session.verify(pub_key, data, sig_bytes, PyKCS11.Mechanism(CKM_SHA256_RSA_PKCS))
        print("Signature verified: OK")
    except PyKCS11Error as exc:
        print(f"Verification failed: {exc}")

    # Tampered data should fail
    try:
        result = session.verify(
            pub_key, b"tampered data", sig_bytes, PyKCS11.Mechanism(CKM_SHA256_RSA_PKCS)
        )
        if result is False:
            print("Tampered data correctly rejected.")
        else:
            print("ERROR: tampered data should have failed verification")
    except PyKCS11Error:
        print("Tampered data correctly rejected.")

    return pub_key, priv_key


def demo_rsa_pss(session):
    """Sign and verify with RSA-PSS (SHA-256)."""
    print("\n" + "=" * 60)
    print("RSA-PSS (SHA-256) SIGN/VERIFY")
    print("=" * 60)

    pub_template = [
        (CKA_TOKEN, False),
        (CKA_VERIFY, True),
        (CKA_MODULUS_BITS, 2048),
        (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
    ]
    priv_template = [
        (CKA_TOKEN, False),
        (CKA_PRIVATE, True),
        (CKA_SENSITIVE, True),
        (CKA_SIGN, True),
    ]

    pub_key, priv_key = session.generateKeyPair(
        pub_template,
        priv_template,
        mecha=PyKCS11.Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN),
    )

    data = b"RSA-PSS test payload"

    pss_params = PyKCS11.RSA_PSS_Mechanism(
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA256,
        PyKCS11.LowLevel.CKG_MGF1_SHA256,
        32,
    )

    signature = session.sign(priv_key, data, pss_params)
    sig_bytes = bytes(signature)
    print(f"PSS Signature ({len(sig_bytes)} bytes): {sig_bytes.hex()[:40]}...")

    try:
        session.verify(pub_key, data, sig_bytes, pss_params)
        print("PSS signature verified: OK")
    except PyKCS11Error as exc:
        print(f"PSS verification failed: {exc}")


def demo_rsa_encrypt_decrypt(session, pub_key, priv_key):
    """RSA-OAEP encrypt and decrypt."""
    print("\n" + "=" * 60)
    print("RSA ENCRYPTION / DECRYPTION (RSA-OAEP)")
    print("=" * 60)

    from PyKCS11.LowLevel import CKM_RSA_PKCS_OAEP, CKM_SHA_1, CKG_MGF1_SHA1

    oaep_params = PyKCS11.RSAOAEPMechanism(CKM_SHA_1, CKG_MGF1_SHA1)

    plaintext = b"Encrypt me with RSA-OAEP"
    ciphertext = bytes(session.encrypt(pub_key, list(plaintext), oaep_params))
    print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()[:40]}...")

    decrypted = bytes(session.decrypt(priv_key, list(ciphertext), oaep_params))
    assert decrypted == plaintext
    print(f"Decrypted: {decrypted}")


def demo_ec_key_pair(session):
    """Generate an EC P-256 key pair and sign/verify with ECDSA."""
    print("\n" + "=" * 60)
    print("EC P-256 KEY PAIR GENERATION + ECDSA SIGN/VERIFY")
    print("=" * 60)

    # DER-encoded OID for P-256 (secp256r1): 1.2.840.10045.3.1.7
    p256_oid = bytes([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])

    pub_template = [
        (CKA_TOKEN, False),
        (CKA_VERIFY, True),
        (CKA_LABEL, "demo-ec-pub"),
        (PyKCS11.LowLevel.CKA_EC_PARAMS, list(p256_oid)),
    ]
    priv_template = [
        (CKA_TOKEN, False),
        (CKA_PRIVATE, True),
        (CKA_SENSITIVE, True),
        (CKA_SIGN, True),
        (CKA_LABEL, "demo-ec-priv"),
    ]

    pub_key, priv_key = session.generateKeyPair(
        pub_template,
        priv_template,
        mecha=PyKCS11.Mechanism(CKM_EC_KEY_PAIR_GEN),
    )
    print("EC P-256 key pair generated.")

    data = b"ECDSA sign/verify test"
    # SoftHSM2 supports CKM_ECDSA (raw) but not CKM_ECDSA_SHA256,
    # so we hash the data ourselves and use raw ECDSA.
    from PyKCS11.LowLevel import CKM_ECDSA
    data_hash = hashlib.sha256(data).digest()

    signature = session.sign(priv_key, data_hash, PyKCS11.Mechanism(CKM_ECDSA))
    sig_bytes = bytes(signature)
    print(f"ECDSA Signature ({len(sig_bytes)} bytes): {sig_bytes.hex()[:40]}...")

    try:
        session.verify(pub_key, data_hash, sig_bytes, PyKCS11.Mechanism(CKM_ECDSA))
        print("ECDSA signature verified: OK")
    except PyKCS11Error as exc:
        print(f"ECDSA verification failed: {exc}")


def demo_aes_key(session):
    """Generate AES-256 key, encrypt and decrypt with AES-CBC."""
    print("\n" + "=" * 60)
    print("AES-256 KEY GENERATION + AES-CBC-PAD ENCRYPT/DECRYPT")
    print("=" * 60)

    aes_template = [
        (CKA_TOKEN, False),
        (CKA_SENSITIVE, True),
        (CKA_ENCRYPT, True),
        (CKA_DECRYPT, True),
        (CKA_VALUE_LEN, 32),  # 256-bit
        (CKA_LABEL, "demo-aes-key"),
    ]

    aes_key = session.generateKey(aes_template, PyKCS11.Mechanism(CKM_AES_KEY_GEN))
    print("AES-256 key generated.")

    # AES-CBC with PKCS#7 padding — IV must be 16 bytes
    iv = [0x00] * 16
    plaintext = list(b"AES-CBC encrypted with PyKCS11!!")  # 32 bytes

    ciphertext = bytes(
        session.encrypt(aes_key, plaintext, PyKCS11.Mechanism(CKM_AES_CBC_PAD, iv))
    )
    print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()[:40]}...")

    decrypted = bytes(
        session.decrypt(aes_key, list(ciphertext), PyKCS11.Mechanism(CKM_AES_CBC_PAD, iv))
    )
    assert decrypted == bytes(plaintext)
    print(f"Decrypted: {decrypted}")


def demo_digest(session):
    """Compute SHA-256, SHA-384, and SHA-512 digests via PKCS#11."""
    print("\n" + "=" * 60)
    print("DIGEST (SHA-256 / SHA-384 / SHA-512)")
    print("=" * 60)

    data = b"Hash this data with PyKCS11"

    for mech_id, name in [
        (CKM_SHA256, "SHA-256"),
        (CKM_SHA384, "SHA-384"),
        (CKM_SHA512, "SHA-512"),
    ]:
        digest = bytes(session.digest(data, PyKCS11.Mechanism(mech_id)))
        print(f"{name}: {digest.hex()}")

    # Cross-check SHA-256 against Python's hashlib
    expected = hashlib.sha256(data).digest()
    pkcs11_sha256 = bytes(session.digest(data, PyKCS11.Mechanism(CKM_SHA256)))
    assert pkcs11_sha256 == expected
    print(f"\nhashlib SHA-256:   {expected.hex()}")
    print(f"PKCS#11 SHA-256:   {pkcs11_sha256.hex()}")
    print("SHA-256 cross-check: OK")


def demo_find_objects(session):
    """Demonstrate object enumeration and attribute retrieval."""
    print("\n" + "=" * 60)
    print("OBJECT ENUMERATION AND ATTRIBUTE RETRIEVAL")
    print("=" * 60)

    # Generate a labelled key so we have something to find
    label = "findable-aes-key"
    aes_template = [
        (CKA_TOKEN, False),
        (CKA_VALUE_LEN, 32),
        (CKA_ENCRYPT, True),
        (CKA_DECRYPT, True),
        (CKA_LABEL, label),
    ]
    session.generateKey(aes_template, PyKCS11.Mechanism(CKM_AES_KEY_GEN))

    # Find all objects matching the label
    objects = session.findObjects([(CKA_LABEL, label)])
    print(f"Objects found with label '{label}': {len(objects)}")

    for obj in objects:
        attrs = session.getAttributeValue(obj, [CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL])
        cls_map = {
            PyKCS11.LowLevel.CKO_SECRET_KEY: "CKO_SECRET_KEY",
            PyKCS11.LowLevel.CKO_PRIVATE_KEY: "CKO_PRIVATE_KEY",
            PyKCS11.LowLevel.CKO_PUBLIC_KEY: "CKO_PUBLIC_KEY",
        }
        key_type_map = {
            PyKCS11.LowLevel.CKK_AES: "CKK_AES",
            PyKCS11.LowLevel.CKK_RSA: "CKK_RSA",
            PyKCS11.LowLevel.CKK_EC: "CKK_EC",
        }
        print(
            f"  class={cls_map.get(attrs[0], attrs[0])}  "
            f"key_type={key_type_map.get(attrs[1], attrs[1])}  "
            f"label={attrs[2]}"
        )


def demo_random(session):
    """Generate random bytes using the PKCS#11 token's RNG."""
    print("\n" + "=" * 60)
    print("HARDWARE RANDOM NUMBER GENERATION")
    print("=" * 60)

    for size in (16, 32, 64):
        rand = bytes(session.generateRandom(size))
        print(f"{size * 8}-bit random: {rand.hex()}")


def demo_multi_sign_algos(session):
    """Demonstrate multiple RSA signing algorithms side-by-side."""
    print("\n" + "=" * 60)
    print("MULTIPLE RSA SIGNING ALGORITHMS")
    print("=" * 60)

    pub_template = [
        (CKA_TOKEN, False),
        (CKA_VERIFY, True),
        (CKA_MODULUS_BITS, 2048),
        (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
    ]
    priv_template = [
        (CKA_TOKEN, False),
        (CKA_PRIVATE, True),
        (CKA_SENSITIVE, True),
        (CKA_SIGN, True),
    ]

    pub_key, priv_key = session.generateKeyPair(
        pub_template,
        priv_template,
        mecha=PyKCS11.Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN),
    )

    data = b"Multi-algorithm signing demo"

    for mech_id, name in [
        (CKM_SHA256_RSA_PKCS, "SHA256-RSA-PKCS1v15"),
        (CKM_SHA384_RSA_PKCS, "SHA384-RSA-PKCS1v15"),
        (CKM_SHA512_RSA_PKCS, "SHA512-RSA-PKCS1v15"),
    ]:
        sig = bytes(session.sign(priv_key, data, PyKCS11.Mechanism(mech_id)))
        try:
            session.verify(pub_key, data, sig, PyKCS11.Mechanism(mech_id))
            status = "OK"
        except PyKCS11Error:
            status = "FAILED"
        print(f"  {name:<30} sig_len={len(sig)}  verify={status}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Run all PyKCS11 demonstrations."""
    print("PYKCS11 LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    lib = _load_library()
    if lib is None:
        print("\nInstall SoftHSM2 and initialise a token to run these demos:")
        print("  softhsm2-util --init-token --slot 0 --label Demo --pin 1234 --so-pin 12345678")
        print("Then re-run this script.")
        sys.exit(0)

    session, slot_id = _open_session(lib, pin="1234")
    if session is None:
        sys.exit(1)

    try:
        demo_slot_info(lib)
        demo_mechanism_list(lib, slot_id)
        demo_random(session)
        demo_digest(session)

        pub_key, priv_key = demo_rsa_key_pair(session)
        demo_rsa_encrypt_decrypt(session, pub_key, priv_key)
        demo_rsa_pss(session)
        demo_multi_sign_algos(session)

        demo_ec_key_pair(session)
        demo_aes_key(session)
        demo_find_objects(session)
    finally:
        session.logout()
        session.closeSession()
        print("\nSession closed.")

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
