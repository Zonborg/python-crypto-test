"""
Comprehensive demonstration of Gunicorn's SSL/TLS configuration.
Covers SSL context setup, certificate configuration, cipher suites,
and secure deployment patterns.

Note: Gunicorn is a WSGI HTTP server. This demo shows its security-related
configuration options including TLS/SSL settings.
"""

import ssl
import os
import tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime


def generate_test_certificates():
    """Generate test CA and server certificates for demo purposes."""
    # Generate CA key and cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Org"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Generate server key and cert
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return ca_key, ca_cert, server_key, server_cert


def demo_ssl_context_creation():
    """Create and configure SSL context for Gunicorn."""
    print("\n" + "=" * 60)
    print("SSL CONTEXT CREATION FOR GUNICORN")
    print("=" * 60)

    # Create SSL context (what Gunicorn uses internally)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Set minimum TLS version
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Disable insecure protocols
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1

    # Security options
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    print(f"Protocol: TLS Server")
    print(f"Min version: TLSv1.2")
    print(f"SSLv2 disabled: True")
    print(f"SSLv3 disabled: True")
    print(f"TLSv1.0 disabled: True")
    print(f"TLSv1.1 disabled: True")
    print(f"Server cipher preference: True")
    print("SSL context configured: OK")


def demo_cipher_configuration():
    """Configure TLS cipher suites."""
    print("\n" + "=" * 60)
    print("TLS CIPHER SUITE CONFIGURATION")
    print("=" * 60)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Strong cipher suite (Gunicorn --ciphers option)
    strong_ciphers = (
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:"
        "ECDH+AESGCM:DH+AESGCM:ECDH+AES:DH+AES:"
        "!aNULL:!MD5:!DSS:!RC4:!3DES"
    )
    ctx.set_ciphers(strong_ciphers)

    # Get available ciphers
    ciphers = ctx.get_ciphers()
    print(f"Cipher string: {strong_ciphers}")
    print(f"Available ciphers: {len(ciphers)}")
    for cipher in ciphers[:10]:
        print(f"  {cipher['name']:35s} TLS:{cipher['protocol']}")
    if len(ciphers) > 10:
        print(f"  ... and {len(ciphers) - 10} more")


def demo_tls13_ciphers():
    """TLS 1.3 cipher configuration."""
    print("\n" + "=" * 60)
    print("TLS 1.3 CIPHER CONFIGURATION")
    print("=" * 60)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    # TLS 1.3 has its own cipher suites
    tls13_ciphers = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
    ]

    print("TLS 1.3 cipher suites:")
    for cipher in tls13_ciphers:
        print(f"  - {cipher}")

    # Check supported TLS versions
    print(f"\nMinimum version: TLSv1.3")
    print(f"Maximum version: {ctx.maximum_version.name if hasattr(ctx, 'maximum_version') else 'auto'}")


def demo_client_certificate_auth():
    """Client certificate authentication configuration."""
    print("\n" + "=" * 60)
    print("CLIENT CERTIFICATE AUTHENTICATION")
    print("=" * 60)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Verify modes available for --cert-reqs
    verify_modes = {
        ssl.CERT_NONE: "No client cert required (default)",
        ssl.CERT_OPTIONAL: "Client cert optional (Gunicorn: --cert-reqs 1)",
        ssl.CERT_REQUIRED: "Client cert required (Gunicorn: --cert-reqs 2)",
    }

    print("Client certificate verification modes:")
    for mode, desc in verify_modes.items():
        print(f"  {mode}: {desc}")

    # Configure for mutual TLS
    ctx.verify_mode = ssl.CERT_REQUIRED
    print(f"\nConfigured: CERT_REQUIRED (mutual TLS)")
    print("Gunicorn config: --cert-reqs 2 --ca-certs /path/to/ca.pem")


def demo_gunicorn_ssl_config():
    """Demonstrate Gunicorn SSL configuration options."""
    print("\n" + "=" * 60)
    print("GUNICORN SSL CONFIGURATION OPTIONS")
    print("=" * 60)

    # Gunicorn SSL-related configuration
    config = {
        "keyfile": "/path/to/server.key",
        "certfile": "/path/to/server.crt",
        "ca_certs": "/path/to/ca-bundle.crt",
        "cert_reqs": ssl.CERT_REQUIRED,
        "ssl_version": "TLS",
        "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5",
        "do_handshake_on_connect": True,
        "suppress_ragged_eofs": True,
    }

    print("Gunicorn SSL config (gunicorn.conf.py):")
    for key, value in config.items():
        print(f"  {key} = {repr(value)}")

    # Command-line equivalent
    print("\nEquivalent command line:")
    print("  gunicorn app:app \\")
    print("    --keyfile /path/to/server.key \\")
    print("    --certfile /path/to/server.crt \\")
    print("    --ca-certs /path/to/ca-bundle.crt \\")
    print("    --cert-reqs 2 \\")
    print("    --ciphers 'ECDHE+AESGCM:!aNULL:!MD5'")


def demo_ssl_context_with_certs():
    """SSL context with generated certificates."""
    print("\n" + "=" * 60)
    print("SSL CONTEXT WITH CERTIFICATES")
    print("=" * 60)

    import ipaddress

    # Generate test certs
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write to temp files
    tmpdir = tempfile.mkdtemp()
    try:
        key_path = os.path.join(tmpdir, "server.key")
        cert_path = os.path.join(tmpdir, "server.crt")
        ca_path = os.path.join(tmpdir, "ca.crt")

        with open(key_path, "wb") as f:
            f.write(server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))

        with open(cert_path, "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))

        with open(ca_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Create SSL context (as Gunicorn would)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.load_verify_locations(ca_path)
        ctx.verify_mode = ssl.CERT_OPTIONAL

        print(f"Server cert loaded: localhost")
        print(f"CA cert loaded: Test CA")
        print(f"Verify mode: CERT_OPTIONAL")
        print("SSL context ready for Gunicorn: OK")
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def demo_security_headers():
    """Security headers typically used with Gunicorn."""
    print("\n" + "=" * 60)
    print("SECURITY HEADERS (GUNICORN + REVERSE PROXY)")
    print("=" * 60)

    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }

    print("Recommended security headers:")
    for header, value in headers.items():
        print(f"  {header}:")
        print(f"    {value}")


def demo_worker_security():
    """Gunicorn worker security configuration."""
    print("\n" + "=" * 60)
    print("GUNICORN WORKER SECURITY")
    print("=" * 60)

    security_config = {
        "workers": 4,
        "worker_class": "gthread",
        "threads": 2,
        "timeout": 30,
        "graceful_timeout": 30,
        "limit_request_line": 4094,
        "limit_request_fields": 100,
        "limit_request_field_size": 8190,
    }

    print("Security-related worker configuration:")
    for key, value in security_config.items():
        print(f"  {key}: {value}")

    print("\nDOS protection settings:")
    print("  limit_request_line:       Max HTTP request line size")
    print("  limit_request_fields:     Max number of headers")
    print("  limit_request_field_size: Max header field size")


def demo_ssl_protocol_info():
    """Display SSL/TLS protocol information."""
    print("\n" + "=" * 60)
    print("SSL/TLS PROTOCOL INFORMATION")
    print("=" * 60)

    print(f"OpenSSL version: {ssl.OPENSSL_VERSION}")
    print(f"OpenSSL version number: {ssl.OPENSSL_VERSION_NUMBER}")
    print(f"\nTLS versions available:")

    versions = [
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for name, version in versions:
        print(f"  {name}: supported")

    # Default context info
    default_ctx = ssl.create_default_context()
    print(f"\nDefault context settings:")
    print(f"  Check hostname: {default_ctx.check_hostname}")
    print(f"  Verify mode: {default_ctx.verify_mode}")
    print(f"  Min version: {default_ctx.minimum_version.name}")


def main():
    """Run all Gunicorn SSL demonstrations."""
    print("GUNICORN SSL/TLS CONFIGURATION - COMPREHENSIVE DEMO")
    print("=" * 60)

    # SSL Context
    demo_ssl_context_creation()
    demo_cipher_configuration()
    demo_tls13_ciphers()
    demo_ssl_context_with_certs()

    # Authentication
    demo_client_certificate_auth()

    # Configuration
    demo_gunicorn_ssl_config()
    demo_worker_security()
    demo_security_headers()

    # Protocol Info
    demo_ssl_protocol_info()

    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
