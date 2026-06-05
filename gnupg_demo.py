"""
Comprehensive demonstration of the python-gnupg library.
Covers key generation, key management, encryption/decryption,
signing/verification, key import/export, and trust management.
"""

import gnupg
import tempfile
import os
import shutil


def get_gpg_instance():
    """Create a GPG instance with a temporary home directory."""
    gpg_home = tempfile.mkdtemp(prefix="gnupg_demo_")
    gpg = gnupg.GPG(gnupghome=gpg_home)
    return gpg, gpg_home


def demo_key_generation():
    """GPG key pair generation."""
    print("\n" + "=" * 60)
    print("GPG KEY GENERATION")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        # Generate RSA key
        input_data = gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Demo User",
            name_email="demo@example.com",
            name_comment="Test Key",
            passphrase="demo-passphrase",
            expire_date="1y",
        )
        key = gpg.gen_key(input_data)

        print(f"Key generated:")
        print(f"  Fingerprint: {key.fingerprint}")
        print(f"  Type: RSA-2048")
        print(f"  Name: Demo User <demo@example.com>")
        print(f"  Status: {key.status}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_key_generation_ecc():
    """GPG ECC key generation."""
    print("\n" + "=" * 60)
    print("GPG ECC KEY GENERATION")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        input_data = gpg.gen_key_input(
            key_type="EDDSA",
            key_curve="ed25519",
            key_usage="sign",
            subkey_type="ECDH",
            subkey_curve="cv25519",
            subkey_usage="encrypt",
            name_real="ECC Demo User",
            name_email="ecc@example.com",
            passphrase="ecc-passphrase",
        )
        key = gpg.gen_key(input_data)

        print(f"ECC Key generated:")
        print(f"  Fingerprint: {key.fingerprint}")
        print(f"  Type: Ed25519 + Cv25519")
        print(f"  Status: {key.status}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_symmetric_encryption():
    """Symmetric (passphrase-only) encryption."""
    print("\n" + "=" * 60)
    print("GPG SYMMETRIC ENCRYPTION")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        plaintext = "This is a secret message for symmetric encryption"
        passphrase = "symmetric-passphrase"

        # Encrypt
        encrypted = gpg.encrypt(
            plaintext,
            recipients=None,
            symmetric="AES256",
            passphrase=passphrase,
            armor=True,
        )
        print(f"Plaintext:  {plaintext}")
        print(f"Encrypted:  {str(encrypted)[:60]}...")
        print(f"Status:     {encrypted.status}")
        print(f"OK:         {encrypted.ok}")

        # Decrypt
        decrypted = gpg.decrypt(str(encrypted), passphrase=passphrase)
        print(f"Decrypted:  {str(decrypted)}")
        print(f"Status:     {decrypted.status}")
        assert str(decrypted) == plaintext
        print("Verification: PASSED")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_asymmetric_encryption():
    """Asymmetric (public key) encryption."""
    print("\n" + "=" * 60)
    print("GPG ASYMMETRIC ENCRYPTION")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        # Generate recipient key
        input_data = gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Recipient",
            name_email="recipient@example.com",
            passphrase="recipient-pass",
        )
        key = gpg.gen_key(input_data)

        plaintext = "Secret message for asymmetric encryption"

        # Encrypt to recipient
        encrypted = gpg.encrypt(
            plaintext,
            recipients=[key.fingerprint],
            armor=True,
        )
        print(f"Plaintext:  {plaintext}")
        print(f"Encrypted:  {str(encrypted)[:60]}...")
        print(f"OK:         {encrypted.ok}")

        # Decrypt
        decrypted = gpg.decrypt(str(encrypted), passphrase="recipient-pass")
        print(f"Decrypted:  {str(decrypted)}")
        assert str(decrypted) == plaintext
        print("Verification: PASSED")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_signing():
    """GPG message signing."""
    print("\n" + "=" * 60)
    print("GPG MESSAGE SIGNING")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        # Generate signing key
        input_data = gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Signer",
            name_email="signer@example.com",
            passphrase="signer-pass",
        )
        key = gpg.gen_key(input_data)

        message = "Message to be signed"

        # Clear-text signature
        signed = gpg.sign(message, passphrase="signer-pass", keyid=key.fingerprint)
        print(f"Message:    {message}")
        print(f"Signed:     {str(signed)[:60]}...")
        print(f"Status:     {signed.status}")
        print(f"Fingerprint: {signed.fingerprint}")

        # Verify signature
        verified = gpg.verify(str(signed))
        print(f"Valid:      {verified.valid}")
        print(f"Key ID:     {verified.key_id}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_detached_signature():
    """GPG detached signature."""
    print("\n" + "=" * 60)
    print("GPG DETACHED SIGNATURE")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        input_data = gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Detached Signer",
            name_email="detached@example.com",
            passphrase="detach-pass",
        )
        key = gpg.gen_key(input_data)

        message = "Message with detached signature"

        # Create detached signature
        signed = gpg.sign(
            message,
            passphrase="detach-pass",
            keyid=key.fingerprint,
            detach=True,
        )
        print(f"Message:    {message}")
        print(f"Detached sig: {str(signed)[:60]}...")
        print(f"Status:     {signed.status}")

        # Verify detached signature with data
        # Write message to temp file for verification
        msg_file = os.path.join(gpg_home, "message.txt")
        sig_file = os.path.join(gpg_home, "message.txt.sig")
        with open(msg_file, 'w') as f:
            f.write(message)
        with open(sig_file, 'w') as f:
            f.write(str(signed))

        with open(sig_file, 'rb') as f:
            verified = gpg.verify_file(f, data_filename=msg_file)
        print(f"Valid: {verified.valid}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_key_export_import():
    """GPG key export and import."""
    print("\n" + "=" * 60)
    print("GPG KEY EXPORT/IMPORT")
    print("=" * 60)

    gpg1, gpg_home1 = get_gpg_instance()
    gpg2, gpg_home2 = get_gpg_instance()

    try:
        # Generate key in first keyring
        input_data = gpg1.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Export User",
            name_email="export@example.com",
            passphrase="export-pass",
        )
        key = gpg1.gen_key(input_data)

        # Export public key
        pub_key = gpg1.export_keys(key.fingerprint)
        print(f"Public key exported: {len(pub_key)} chars")
        print(f"  {pub_key[:60]}...")

        # Export private key
        priv_key = gpg1.export_keys(key.fingerprint, secret=True, passphrase="export-pass")
        print(f"Private key exported: {len(priv_key)} chars")

        # Import into second keyring
        import_result = gpg2.import_keys(pub_key)
        print(f"Import count: {import_result.count}")
        print(f"Fingerprints: {import_result.fingerprints}")

        # List keys in second keyring
        keys = gpg2.list_keys()
        print(f"Keys in keyring 2: {len(keys)}")
        if keys:
            print(f"  UID: {keys[0]['uids'][0]}")
    finally:
        shutil.rmtree(gpg_home1, ignore_errors=True)
        shutil.rmtree(gpg_home2, ignore_errors=True)


def demo_key_listing():
    """List and inspect GPG keys."""
    print("\n" + "=" * 60)
    print("GPG KEY LISTING")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        # Generate multiple keys
        for name, email in [("Alice", "alice@example.com"), ("Bob", "bob@example.com")]:
            input_data = gpg.gen_key_input(
                key_type="RSA",
                key_length=2048,
                name_real=name,
                name_email=email,
                passphrase=f"{name.lower()}-pass",
            )
            gpg.gen_key(input_data)

        # List public keys
        pub_keys = gpg.list_keys()
        print(f"Public keys: {len(pub_keys)}")
        for key in pub_keys:
            print(f"  {key['uids'][0]}")
            print(f"    Fingerprint: {key['fingerprint']}")
            print(f"    Key length:  {key['length']}")
            print(f"    Algorithm:   {key['algo']}")
            print(f"    Expires:     {key.get('expires', 'never')}")

        # List secret keys
        sec_keys = gpg.list_keys(True)
        print(f"Secret keys: {len(sec_keys)}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_encrypt_file():
    """Encrypt and decrypt files."""
    print("\n" + "=" * 60)
    print("GPG FILE ENCRYPTION")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        # Generate key
        input_data = gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="File User",
            name_email="file@example.com",
            passphrase="file-pass",
        )
        key = gpg.gen_key(input_data)

        # Create test file
        test_file = os.path.join(gpg_home, "test_document.txt")
        with open(test_file, 'w') as f:
            f.write("This is a secret document content.\n" * 10)

        # Encrypt file
        with open(test_file, 'rb') as f:
            encrypted = gpg.encrypt_file(f, recipients=[key.fingerprint], output=test_file + ".gpg")

        print(f"File encrypted: {encrypted.ok}")
        print(f"Output size: {os.path.getsize(test_file + '.gpg')} bytes")

        # Decrypt file
        with open(test_file + ".gpg", 'rb') as f:
            decrypted = gpg.decrypt_file(f, passphrase="file-pass", output=test_file + ".dec")

        print(f"File decrypted: {decrypted.ok}")

        # Verify content
        with open(test_file + ".dec", 'r') as f:
            content = f.read()
        with open(test_file, 'r') as f:
            original = f.read()
        assert content == original
        print("Content verification: PASSED")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_sign_and_encrypt():
    """Combined signing and encryption."""
    print("\n" + "=" * 60)
    print("GPG SIGN AND ENCRYPT")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        # Generate sender and recipient keys
        sender_input = gpg.gen_key_input(
            key_type="RSA", key_length=2048,
            name_real="Sender", name_email="sender@example.com",
            passphrase="sender-pass",
        )
        sender_key = gpg.gen_key(sender_input)

        recipient_input = gpg.gen_key_input(
            key_type="RSA", key_length=2048,
            name_real="Recipient", name_email="recipient@example.com",
            passphrase="recipient-pass",
        )
        recipient_key = gpg.gen_key(recipient_input)

        message = "Signed and encrypted message"

        # Sign and encrypt
        encrypted = gpg.encrypt(
            message,
            recipients=[recipient_key.fingerprint],
            sign=sender_key.fingerprint,
            passphrase="sender-pass",
        )
        print(f"Sign+Encrypt OK: {encrypted.ok}")

        # Decrypt and verify
        decrypted = gpg.decrypt(str(encrypted), passphrase="recipient-pass")
        print(f"Decrypted: {str(decrypted)}")
        print(f"Status: {decrypted.status}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def demo_key_trust():
    """GPG key trust levels."""
    print("\n" + "=" * 60)
    print("GPG KEY TRUST MANAGEMENT")
    print("=" * 60)

    gpg, gpg_home = get_gpg_instance()

    try:
        input_data = gpg.gen_key_input(
            key_type="RSA", key_length=2048,
            name_real="Trust User", name_email="trust@example.com",
            passphrase="trust-pass",
        )
        key = gpg.gen_key(input_data)

        # Trust levels
        trust_levels = {
            'TRUST_UNDEFINED': 'trust level not set',
            'TRUST_NEVER': 'never trust this key',
            'TRUST_MARGINAL': 'marginal trust',
            'TRUST_FULLY': 'full trust',
            'TRUST_ULTIMATE': 'ultimate trust (own key)',
        }

        print("Trust levels:")
        for level, desc in trust_levels.items():
            print(f"  {level:20s}: {desc}")

        # Show key trust info
        keys = gpg.list_keys()
        if keys:
            print(f"\nCurrent key trust: {keys[0].get('trust', 'unknown')}")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def main():
    """Run all GnuPG demonstrations."""
    print("PYTHON-GNUPG LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Key Generation
    demo_key_generation()
    demo_key_generation_ecc()

    # Encryption
    demo_symmetric_encryption()
    demo_asymmetric_encryption()
    demo_encrypt_file()
    demo_sign_and_encrypt()

    # Signing
    demo_signing()
    demo_detached_signature()

    # Key Management
    demo_key_export_import()
    demo_key_listing()
    demo_key_trust()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
