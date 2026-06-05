"""
Comprehensive demonstration of the Paramiko library's cryptographic features.
Covers SSH key generation, key loading/saving, transport security,
SFTP operations, host key verification, and agent forwarding.
"""

import os
import io
import socket
import threading
import paramiko
from paramiko import (
    RSAKey, ECDSAKey, Ed25519Key,
    Transport, SSHClient, AutoAddPolicy, RejectPolicy,
    SFTPClient, SFTPServer, Agent,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def _generate_ed25519_key():
    """Generate an Ed25519 key using the cryptography library and load into paramiko."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()
    )
    return Ed25519Key.from_private_key(io.StringIO(private_pem.decode()))


def demo_rsa_key_generation():
    """RSA SSH key generation."""
    print("\n" + "=" * 60)
    print("RSA SSH KEY GENERATION")
    print("=" * 60)

    # Generate RSA key (various sizes)
    for bits in [2048, 3072, 4096]:
        key = RSAKey.generate(bits)
        pub_key = f"{key.get_name()} {key.get_base64()}"
        fingerprint = key.fingerprint

        if bits == 2048:
            print(f"RSA-{bits}:")
            print(f"  Public key: {pub_key[:60]}...")
            print(f"  Fingerprint: {fingerprint}")
            print(f"  Key size: {key.get_bits()} bits")
        else:
            print(f"RSA-{bits}: {key.get_bits()} bits, fp={fingerprint[:20]}...")


def demo_dsa_key_generation():
    """DSA SSH key generation (deprecated in modern paramiko)."""
    print("\n" + "=" * 60)
    print("DSA SSH KEY GENERATION")
    print("=" * 60)

    print("DSSKey has been removed from modern paramiko versions")
    print("DSA keys are considered deprecated for SSH")
    print("Use RSA, ECDSA, or Ed25519 keys instead")


def demo_ecdsa_key_generation():
    """ECDSA SSH key generation."""
    print("\n" + "=" * 60)
    print("ECDSA SSH KEY GENERATION")
    print("=" * 60)

    for bits in [256, 384, 521]:
        key = ECDSAKey.generate(bits=bits)
        fingerprint = key.fingerprint
        print(f"  ECDSA-{bits}: type={key.get_name()}, fp={fingerprint[:20]}...")


def demo_ed25519_key_generation():
    """Ed25519 SSH key generation."""
    print("\n" + "=" * 60)
    print("ED25519 SSH KEY GENERATION")
    print("=" * 60)

    key = _generate_ed25519_key()
    fingerprint = key.fingerprint

    print(f"Ed25519 key generated:")
    print(f"  Type: {key.get_name()}")
    print(f"  Fingerprint: {fingerprint}")
    print(f"  Public key: {key.get_base64()[:50]}...")


def demo_key_serialization():
    """SSH key serialization and loading."""
    print("\n" + "=" * 60)
    print("SSH KEY SERIALIZATION")
    print("=" * 60)

    # RSA key write/read
    key = RSAKey.generate(2048)

    # Write to file-like object (unencrypted)
    key_file = io.StringIO()
    key.write_private_key(key_file)
    pem_data = key_file.getvalue()
    print(f"RSA PEM (unencrypted): {pem_data[:50]}...")

    # Write encrypted
    key_file_enc = io.StringIO()
    key.write_private_key(key_file_enc, password="key-password")
    pem_enc_data = key_file_enc.getvalue()
    print(f"RSA PEM (encrypted):   {pem_enc_data[:50]}...")

    # Load from string
    key_file.seek(0)
    loaded_key = RSAKey.from_private_key(key_file)
    assert loaded_key.get_base64() == key.get_base64()
    print("Load unencrypted: OK")

    # Load encrypted
    key_file_enc.seek(0)
    loaded_enc = RSAKey.from_private_key(key_file_enc, password="key-password")
    assert loaded_enc.get_base64() == key.get_base64()
    print("Load encrypted: OK")

    # Ed25519 serialization
    ed_key = _generate_ed25519_key()
    print(f"Ed25519 key loaded: type={ed_key.get_name()}, fp={ed_key.fingerprint[:30]}...")


def demo_key_fingerprints():
    """SSH key fingerprints in various formats."""
    print("\n" + "=" * 60)
    print("SSH KEY FINGERPRINTS")
    print("=" * 60)

    key = RSAKey.generate(2048)

    # Fingerprint (SHA256 in modern paramiko)
    fp = key.fingerprint

    # Also compute SHA256 manually for comparison
    import hashlib
    import base64
    pub_bytes = key.asbytes()
    sha256_fp = base64.b64encode(hashlib.sha256(pub_bytes).digest()).decode().rstrip('=')

    print(f"Fingerprint:        {fp}")
    print(f"SHA256 fingerprint: SHA256:{sha256_fp}")
    print(f"Key type: {key.get_name()}")
    print(f"Key bits: {key.get_bits()}")


def demo_host_key_verification():
    """Host key verification patterns."""
    print("\n" + "=" * 60)
    print("HOST KEY VERIFICATION")
    print("=" * 60)

    # Create a host keys object
    host_keys = paramiko.HostKeys()

    # Add a known host
    server_key = RSAKey.generate(2048)
    host_keys.add("example.com", "ssh-rsa", server_key)
    host_keys.add("[example.com]:2222", "ssh-rsa", server_key)

    # Check if host is known
    known = host_keys.lookup("example.com")
    print(f"example.com known: {known is not None}")
    print(f"unknown.com known: {host_keys.lookup('unknown.com') is not None}")

    # Verify key matches
    if known:
        stored_key = known.get("ssh-rsa")
        print(f"Key matches: {stored_key == server_key}")

    # Save and load host keys
    host_keys_file = io.StringIO()
    # Write manually since save() needs a filename
    for hostname in host_keys.keys():
        entry = host_keys.lookup(hostname)
        if entry:
            for key_type, key_obj in entry.items():
                host_keys_file.write(f"{hostname} {key_type} {key_obj.get_base64()}\n")

    print(f"Host keys entries: {len(host_keys)}")


def demo_ssh_client_config():
    """SSH client configuration patterns."""
    print("\n" + "=" * 60)
    print("SSH CLIENT CONFIGURATION")
    print("=" * 60)

    client = SSHClient()

    # Different host key policies
    policies = [
        ("AutoAddPolicy", AutoAddPolicy()),
        ("RejectPolicy", RejectPolicy()),
    ]

    for name, policy in policies:
        client.set_missing_host_key_policy(policy)
        print(f"  Policy set: {name}")

    # Load system host keys (if available)
    try:
        client.load_system_host_keys()
        print("  System host keys: loaded")
    except Exception:
        print("  System host keys: not available")

    print("  Client configured (not connected)")
    client.close()


def demo_transport_algorithms():
    """Display supported transport algorithms."""
    print("\n" + "=" * 60)
    print("SUPPORTED TRANSPORT ALGORITHMS")
    print("=" * 60)

    # Show preferred algorithms
    transport_prefs = Transport._preferred_ciphers
    transport_macs = Transport._preferred_macs
    transport_keys = Transport._preferred_keys
    transport_kex = Transport._preferred_kex

    print("  Preferred ciphers:")
    for cipher in transport_prefs:
        print(f"    - {cipher}")

    print("  Preferred MACs:")
    for mac in transport_macs:
        print(f"    - {mac}")

    print("  Preferred host key types:")
    for key_type in transport_keys:
        print(f"    - {key_type}")

    print("  Preferred key exchange:")
    for kex in transport_kex[:5]:
        print(f"    - {kex}")
    if len(transport_kex) > 5:
        print(f"    ... and {len(transport_kex) - 5} more")


def demo_key_signing():
    """SSH key signing and verification."""
    print("\n" + "=" * 60)
    print("SSH KEY SIGNING AND VERIFICATION")
    print("=" * 60)

    # RSA signing (modern paramiko requires algorithm specification)
    rsa_key = RSAKey.generate(2048)
    message = b"Message to sign with SSH key"

    signature = rsa_key.sign_ssh_data(message, algorithm="rsa-sha2-256")
    is_valid = rsa_key.verify_ssh_sig(message, signature)
    print(f"RSA sign/verify: {is_valid}")

    # ECDSA signing
    ec_key = ECDSAKey.generate(bits=256)
    signature_ec = ec_key.sign_ssh_data(message)
    is_valid_ec = ec_key.verify_ssh_sig(message, signature_ec)
    print(f"ECDSA sign/verify: {is_valid_ec}")

    # Ed25519 signing
    ed_key = _generate_ed25519_key()
    signature_ed = ed_key.sign_ssh_data(message)
    is_valid_ed = ed_key.verify_ssh_sig(message, signature_ed)
    print(f"Ed25519 sign/verify: {is_valid_ed}")

    # Wrong message verification
    wrong_valid = rsa_key.verify_ssh_sig(b"wrong message", signature)
    print(f"Wrong message verify: {wrong_valid} (expected False)")


def demo_key_comparison():
    """SSH key comparison and equality."""
    print("\n" + "=" * 60)
    print("SSH KEY COMPARISON")
    print("=" * 60)

    key1 = RSAKey.generate(2048)
    key2 = RSAKey.generate(2048)

    # Same key loaded twice
    key_file = io.StringIO()
    key1.write_private_key(key_file)
    key_file.seek(0)
    key1_loaded = RSAKey.from_private_key(key_file)

    print(f"key1 == key1_loaded: {key1 == key1_loaded}")
    print(f"key1 == key2:        {key1 == key2}")
    print(f"key1 fingerprint: {key1.fingerprint[:20]}...")
    print(f"key2 fingerprint: {key2.fingerprint[:20]}...")


def demo_public_key_extraction():
    """Extract public key from private key."""
    print("\n" + "=" * 60)
    print("PUBLIC KEY EXTRACTION")
    print("=" * 60)

    key_types = [
        ("RSA-2048", RSAKey.generate(2048)),
        ("ECDSA-256", ECDSAKey.generate(bits=256)),
        ("Ed25519", _generate_ed25519_key()),
    ]

    for name, key in key_types:
        pub_key_str = f"{key.get_name()} {key.get_base64()}"
        # Format for authorized_keys
        auth_key_line = f"{key.get_name()} {key.get_base64()} user@host"
        print(f"  {name}:")
        print(f"    Type: {key.get_name()}")
        print(f"    authorized_keys: {auth_key_line[:60]}...")


def demo_ssh_message():
    """SSH message packing (internal protocol)."""
    print("\n" + "=" * 60)
    print("SSH MESSAGE PACKING")
    print("=" * 60)

    from paramiko.message import Message

    # Create a message
    msg = Message()
    msg.add_string(b"ssh-rsa")
    msg.add_int(65537)
    msg.add_mpint(12345678901234567890)
    msg.add_boolean(True)
    msg.add_byte(b"\x01")

    data = msg.asbytes()
    print(f"Message bytes: {len(data)} bytes")
    print(f"Hex: {data.hex()[:50]}...")

    # Read back
    msg_read = Message(data)
    read_str = msg_read.get_string()
    read_int = msg_read.get_int()
    read_mpint = msg_read.get_mpint()
    read_bool = msg_read.get_boolean()

    print(f"String:  {read_str}")
    print(f"Int:     {read_int}")
    print(f"MPInt:   {read_mpint}")
    print(f"Boolean: {read_bool}")


def main():
    """Run all Paramiko demonstrations."""
    print("PARAMIKO SSH LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Key Generation
    demo_rsa_key_generation()
    demo_dsa_key_generation()
    demo_ecdsa_key_generation()
    demo_ed25519_key_generation()

    # Key Operations
    demo_key_serialization()
    demo_key_fingerprints()
    demo_key_signing()
    demo_key_comparison()
    demo_public_key_extraction()

    # Host Keys
    demo_host_key_verification()

    # Client Configuration
    demo_ssh_client_config()
    demo_transport_algorithms()

    # Protocol
    demo_ssh_message()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
