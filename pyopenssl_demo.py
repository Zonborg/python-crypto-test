"""
Comprehensive demonstration of the pyOpenSSL library.
Covers SSL/TLS context creation, X.509 certificates, CSRs,
key pair generation, certificate verification, and crypto operations.
"""

import datetime
import ipaddress
from OpenSSL import crypto, SSL


def demo_rsa_key_generation():
    """RSA key pair generation."""
    print("\n" + "=" * 60)
    print("RSA KEY PAIR GENERATION")
    print("=" * 60)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Export PEM
    private_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    public_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, key)

    print(f"Key type: RSA")
    print(f"Key bits: {key.bits()}")
    print(f"Private PEM: {private_pem[:50]}...")
    print(f"Public PEM:  {public_pem[:50]}...")


def demo_dsa_key_generation():
    """DSA key pair generation."""
    print("\n" + "=" * 60)
    print("DSA KEY PAIR GENERATION")
    print("=" * 60)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_DSA, 2048)

    private_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    print(f"Key type: DSA")
    print(f"Key bits: {key.bits()}")
    print(f"Private PEM: {private_pem[:50]}...")


def demo_ec_key_generation():
    """Elliptic Curve key generation."""
    print("\n" + "=" * 60)
    print("EC KEY GENERATION")
    print("=" * 60)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)  # pyOpenSSL EC via PKey

    # For EC, use the crypto module's underlying approach
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    # Load into pyOpenSSL
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, ec_pem)
    print(f"EC key loaded, bits: {pkey.bits()}")
    print(f"EC PEM: {ec_pem[:50]}...")


def demo_self_signed_certificate():
    """Self-signed X.509 certificate creation."""
    print("\n" + "=" * 60)
    print("SELF-SIGNED X.509 CERTIFICATE")
    print("=" * 60)

    # Generate key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create certificate
    cert = crypto.X509()
    cert.get_subject().C = "GB"
    cert.get_subject().ST = "England"
    cert.get_subject().L = "London"
    cert.get_subject().O = "Demo Organization"
    cert.get_subject().OU = "Security Team"
    cert.get_subject().CN = "demo.example.com"

    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Export
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

    print(f"Subject:    {cert.get_subject().CN}")
    print(f"Issuer:     {cert.get_issuer().CN}")
    print(f"Serial:     {cert.get_serial_number()}")
    print(f"Not Before: {cert.get_notBefore()}")
    print(f"Not After:  {cert.get_notAfter()}")
    print(f"PEM:        {cert_pem[:50]}...")
    print(f"DER size:   {len(cert_der)} bytes")


def demo_ca_signed_certificate():
    """Certificate signed by a CA."""
    print("\n" + "=" * 60)
    print("CA-SIGNED CERTIFICATE")
    print("=" * 60)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Create CA key and certificate using cryptography
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Demo Certificate Authority"),
    ])
    ca_cert_crypto = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True,
            digital_signature=False, key_encipherment=False,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Create end-entity certificate signed by CA
    ee_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "server.example.com"),
    ])
    ee_cert_crypto = (
        x509.CertificateBuilder()
        .subject_name(ee_subject)
        .issuer_name(ca_subject)
        .public_key(ee_private_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("server.example.com"),
            x509.DNSName("www.server.example.com"),
        ]), critical=False)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Load into pyOpenSSL for display
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
        ca_cert_crypto.public_bytes(serialization.Encoding.PEM))
    ee_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
        ee_cert_crypto.public_bytes(serialization.Encoding.PEM))

    print(f"CA Subject:  {ca_cert.get_subject().CN}")
    print(f"EE Subject:  {ee_cert.get_subject().CN}")
    print(f"EE Issuer:   {ee_cert.get_issuer().CN}")
    print(f"EE Serial:   {ee_cert.get_serial_number()}")
    print("CA signing: OK")


def demo_certificate_signing_request():
    """Certificate Signing Request (CSR)."""
    print("\n" + "=" * 60)
    print("CERTIFICATE SIGNING REQUEST (CSR)")
    print("=" * 60)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "England"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "csr.example.com"),
        ]))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("csr.example.com"),
            x509.DNSName("www.csr.example.com"),
        ]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    # Export
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Load into pyOpenSSL for display
    req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)
    print(f"Subject: {req.get_subject().CN}")
    print(f"CSR PEM: {csr_pem[:50]}...")

    # Verify CSR signature
    assert req.verify(crypto.load_privatekey(crypto.FILETYPE_PEM,
        private_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))
    print("CSR signature: VALID")


def demo_certificate_verification():
    """Certificate chain verification."""
    print("\n" + "=" * 60)
    print("CERTIFICATE CHAIN VERIFICATION")
    print("=" * 60)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

    # Create CA using cryptography lib (need basicConstraints for store verification)
    ca_private_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert_crypto = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(ca_private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Create end-entity cert signed by CA
    ee_private_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee_cert_crypto = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(ee_private_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )

    # Load into pyOpenSSL
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
        ca_cert_crypto.public_bytes(serialization.Encoding.PEM))
    ee_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
        ee_cert_crypto.public_bytes(serialization.Encoding.PEM))

    # Verify using X509Store
    store = crypto.X509Store()
    store.add_cert(ca_cert)

    ctx = crypto.X509StoreContext(store, ee_cert)
    try:
        ctx.verify_certificate()
        print("Certificate verification: PASSED")
    except crypto.X509StoreContextError as e:
        print(f"Certificate verification: FAILED ({e})")

    # Test with untrusted cert
    untrusted_key = crypto.PKey()
    untrusted_key.generate_key(crypto.TYPE_RSA, 2048)

    untrusted_cert = crypto.X509()
    untrusted_cert.get_subject().CN = "untrusted.example.com"
    untrusted_cert.set_serial_number(999)
    untrusted_cert.gmtime_adj_notBefore(0)
    untrusted_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    untrusted_cert.set_issuer(untrusted_cert.get_subject())
    untrusted_cert.set_pubkey(untrusted_key)
    untrusted_cert.sign(untrusted_key, "sha256")

    ctx2 = crypto.X509StoreContext(store, untrusted_cert)
    try:
        ctx2.verify_certificate()
        print("Untrusted cert verification: PASSED (unexpected)")
    except crypto.X509StoreContextError:
        print("Untrusted cert verification: Correctly rejected")


def demo_pkcs12():
    """PKCS#12 (PFX) certificate bundle."""
    print("\n" + "=" * 60)
    print("PKCS#12 (PFX) BUNDLE")
    print("=" * 60)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    # Generate key and cert
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs12.example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs12.example.com")]))
        .public_key(private_key.public_key())
        .serial_number(100)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    # Create PKCS12
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"Demo PKCS12",
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"p12password"),
    )

    # Load back
    loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(p12_data, b"p12password")

    print(f"PKCS12 size:    {len(p12_data)} bytes")
    print(f"Loaded cert CN: {loaded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"Loaded key size: {loaded_key.key_size} bits")
    print("PKCS12 round-trip: OK")


def demo_crl():
    """Certificate Revocation List (CRL)."""
    print("\n" + "=" * 60)
    print("CERTIFICATE REVOCATION LIST (CRL)")
    print("=" * 60)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Create CA
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRL Demo CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Create CRL with revoked certificate
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(datetime.datetime.utcnow())
        .next_update(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(1)
            .revocation_date(datetime.datetime(2024, 1, 1))
            .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
            .build()
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    print(f"CRL Issuer: {crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"Revoked entries: {len(list(crl))}")
    print(f"CRL PEM: {crl_pem[:50]}...")


def demo_signing_and_verification():
    """Data signing and verification."""
    print("\n" + "=" * 60)
    print("DATA SIGNING AND VERIFICATION")
    print("=" * 60)

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding

    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Sign data
    data = b"Data to sign with pyOpenSSL"
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Verify
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        print(f"Data:      {data}")
        print(f"Signature: {signature.hex()[:50]}...")
        print("Verification: PASSED")
    except Exception:
        print("Verification: FAILED")

    # Test with wrong data
    try:
        public_key.verify(signature, b"tampered data", padding.PKCS1v15(), hashes.SHA256())
        print("Tampered verification: PASSED (unexpected)")
    except Exception:
        print("Tampered verification: Correctly rejected")


def demo_ssl_context():
    """SSL/TLS context configuration."""
    print("\n" + "=" * 60)
    print("SSL/TLS CONTEXT CONFIGURATION")
    print("=" * 60)

    # Create key and cert for the context
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Create SSL context
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.use_privatekey(key)
    ctx.use_certificate(cert)

    # Set cipher list
    ctx.set_cipher_list(b"HIGH:!aNULL:!MD5:!RC4")

    # Verify mode
    ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda *args: True)

    print("SSL Context created with TLS method")
    print("Cipher list: HIGH:!aNULL:!MD5:!RC4")
    print("Verify mode: VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT")
    print("Context configuration: OK")


def demo_certificate_extensions():
    """X.509 certificate extensions using cryptography library."""
    print("\n" + "=" * 60)
    print("X.509 CERTIFICATE EXTENSIONS")
    print("=" * 60)

    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    # Generate key using cryptography
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "extensions.example.com"),
    ])

    # Build certificate with extensions
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("extensions.example.com"),
                x509.DNSName("*.extensions.example.com"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .sign(private_key, hashes.SHA256())
    )

    # Display extensions using cryptography library directly
    print(f"Extension count: {len(cert.extensions)}")
    for ext in cert.extensions:
        print(f"  {ext.oid._name:25s}: {str(ext.value)[:40]}")


def demo_key_serialization():
    """Key serialization in various formats."""
    print("\n" + "=" * 60)
    print("KEY SERIALIZATION")
    print("=" * 60)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # PEM format
    pem_unenc = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    pem_enc = crypto.dump_privatekey(
        crypto.FILETYPE_PEM, key,
        cipher="aes-256-cbc",
        passphrase=b"password123"
    )

    # DER format
    der = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)

    # Load back
    loaded_unenc = crypto.load_privatekey(crypto.FILETYPE_PEM, pem_unenc)
    loaded_enc = crypto.load_privatekey(crypto.FILETYPE_PEM, pem_enc, passphrase=b"password123")

    print(f"PEM (unencrypted): {len(pem_unenc)} bytes")
    print(f"PEM (encrypted):   {len(pem_enc)} bytes")
    print(f"DER:               {len(der)} bytes")
    print(f"Load unencrypted:  OK ({loaded_unenc.bits()} bits)")
    print(f"Load encrypted:    OK ({loaded_enc.bits()} bits)")


def demo_certificate_text():
    """Display certificate in human-readable text."""
    print("\n" + "=" * 60)
    print("CERTIFICATE TEXT DISPLAY")
    print("=" * 60)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "GB"
    cert.get_subject().O = "Demo Org"
    cert.get_subject().CN = "text.example.com"
    cert.set_serial_number(12345)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Dump as text
    cert_text = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
    lines = cert_text.decode().split('\n')[:15]
    for line in lines:
        print(f"  {line}")
    print("  ...")


def main():
    """Run all pyOpenSSL demonstrations."""
    print("PYOPENSSL LIBRARY - COMPREHENSIVE DEMO")
    print("=" * 60)

    # Key Generation
    demo_rsa_key_generation()
    demo_dsa_key_generation()
    demo_ec_key_generation()

    # Certificates
    demo_self_signed_certificate()
    demo_ca_signed_certificate()
    demo_certificate_extensions()
    demo_certificate_text()

    # CSR
    demo_certificate_signing_request()

    # Verification
    demo_certificate_verification()

    # PKCS#12
    demo_pkcs12()

    # CRL
    demo_crl()

    # Signing
    demo_signing_and_verification()

    # SSL/TLS
    demo_ssl_context()

    # Serialization
    demo_key_serialization()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
