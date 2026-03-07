# scanner/cert_parser.py
# Second phase of scanning after TLS.
# Takes the raw certificate chain from tls_scanner.py
# and extracts every field required by CERT-In Annexure-A.
# This is what populates the certificate section of the CBOM.
# Called by scan_task.py after run_tls_scan() completes.

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import NameOID, ExtensionOID
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─── RESULT OBJECT ──────────────────────────────────────────
@dataclass
class CertResult:
    # Basic identity
    subject:              str           = None
    issuer:               str           = None
    serial_number:        str           = None

    # Validity
    not_valid_before:     datetime      = None
    not_valid_after:      datetime      = None
    days_to_expiry:       int           = None
    is_expired:           bool          = False

    # Cryptographic details — CERT-In required
    signature_algorithm:  str           = None
    signature_algorithm_oid: str        = None
    public_key_type:      str           = None
    public_key_size:      int           = None

    # Certificate details
    san_list:             list[str]     = field(default_factory=list)
    key_usage:            list[str]     = field(default_factory=list)
    extended_key_usage:   list[str]     = field(default_factory=list)
    is_self_signed:       bool          = False
    is_ca:                bool          = False

    # URLs
    ocsp_url:             str           = None
    crl_url:              str           = None

    # Format — CERT-In required
    cert_format:          str           = "X.509"
    cert_extension:       str           = ".crt"

    # Flags
    is_leaf:              bool          = False
    warnings:             list[str]     = field(default_factory=list)

    def to_dict(self):
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before.isoformat() if self.not_valid_before else None,
            "not_valid_after": self.not_valid_after.isoformat() if self.not_valid_after else None,
            "days_to_expiry": self.days_to_expiry,
            "is_expired": self.is_expired,
            "signature_algorithm": self.signature_algorithm,
            "signature_algorithm_oid": self.signature_algorithm_oid,
            "public_key_type": self.public_key_type,
            "public_key_size": self.public_key_size,
            "san_list": self.san_list,
            "key_usage": self.key_usage,
            "is_self_signed": self.is_self_signed,
            "is_ca": self.is_ca,
            "ocsp_url": self.ocsp_url,
            "crl_url": self.crl_url,
            "cert_format": self.cert_format,
            "cert_extension": self.cert_extension,
            "is_leaf": self.is_leaf,
            "warnings": self.warnings,
        }


# ─── MAIN FUNCTION ──────────────────────────────────────────
def parse_cert_chain(cert_chain: list) -> list[CertResult]:
    # Entry point called by scan_task.py
    # Takes raw DER bytes list from tls_scanner.py
    # Returns list of CertResult (leaf first, root last)
    if not cert_chain:
        return []

    results = []
    for i, raw_cert in enumerate(cert_chain):
        try:
            cert_result = parse_single_cert(raw_cert)
            cert_result.is_leaf = (i == 0)
            results.append(cert_result)
        except Exception as e:
            # Don't let one bad cert break the whole chain
            empty = CertResult()
            empty.warnings.append(f"Failed to parse cert {i}: {e}")
            results.append(empty)

    return results


# ─── SINGLE CERT PARSER ─────────────────────────────────────
def parse_single_cert(raw_cert_der: bytes) -> CertResult:
    cert = x509.load_der_x509_certificate(raw_cert_der)
    result = CertResult()

    # ── Subject and Issuer ───────────────────────────────────
    result.subject = cert.subject.rfc4514_string()
    result.issuer  = cert.issuer.rfc4514_string()
    result.serial_number = str(cert.serial_number)
    result.is_self_signed = (cert.subject == cert.issuer)

    # ── Validity ────────────────────────────────────────────
    now = datetime.now(timezone.utc)

    result.not_valid_before = cert.not_valid_before_utc
    result.not_valid_after  = cert.not_valid_after_utc
    result.is_expired       = now > cert.not_valid_after_utc
    result.days_to_expiry   = (cert.not_valid_after_utc - now).days

    # ── Warnings ────────────────────────────────────────────
    if result.is_expired:
        result.warnings.append("CRITICAL: Certificate is expired")
    elif result.days_to_expiry < 30:
        result.warnings.append(f"WARNING: Expires in {result.days_to_expiry} days")
    if result.is_self_signed:
        result.warnings.append("WARNING: Self-signed certificate")

    # ── Signature Algorithm ─────────────────────────────────
    try:
        sig_algo = cert.signature_algorithm_oid
        result.signature_algorithm_oid = sig_algo.dotted_string
        result.signature_algorithm = get_signature_algorithm_name(
            sig_algo.dotted_string
        )

        # Flag weak signature algorithms
        if result.signature_algorithm in ["SHA1withRSA", "MD5withRSA", "SHA1withECDSA"]:
            result.warnings.append(
                f"CRITICAL: Weak signature algorithm {result.signature_algorithm}"
            )
    except Exception:
        result.signature_algorithm = "UNKNOWN"

    # ── Public Key ──────────────────────────────────────────
    try:
        pub_key = cert.public_key()
        result.public_key_type, result.public_key_size = get_key_info(pub_key)

        # Flag weak key sizes
        if result.public_key_type == "RSA" and result.public_key_size < 2048:
            result.warnings.append(
                f"CRITICAL: RSA key size {result.public_key_size} is too small"
            )
        if result.public_key_type == "EC" and result.public_key_size < 256:
            result.warnings.append(
                f"WARNING: EC key size {result.public_key_size} is small"
            )
    except Exception:
        result.public_key_type = "UNKNOWN"

    # ── SANs (Subject Alternative Names) ────────────────────
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        result.san_list = [str(name.value) for name in san_ext.value]
    except Exception:
        pass

    # ── Key Usage ───────────────────────────────────────────
    try:
        ku = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        usages = []
        for usage in ["digital_signature", "key_encipherment",
                      "key_agreement", "key_cert_sign", "crl_sign"]:
            try:
                if getattr(ku, usage, False):
                    usages.append(usage)
            except Exception:
                pass
        result.key_usage = usages
    except Exception:
        pass

    # ── Is CA ───────────────────────────────────────────────
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        result.is_ca = bc.ca
    except Exception:
        result.is_ca = False

    # ── OCSP URL ────────────────────────────────────────────
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        for access in aia:
            from cryptography.x509.oid import AuthorityInformationAccessOID
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                result.ocsp_url = access.access_location.value
    except Exception:
        pass

    # ── CRL URL ─────────────────────────────────────────────
    try:
        crl = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        for point in crl:
            if point.full_name:
                result.crl_url = point.full_name[0].value
                break
    except Exception:
        pass

    return result


# ─── HELPER: KEY INFO ───────────────────────────────────────
def get_key_info(pub_key) -> tuple[str, int]:
    # Returns (key_type, key_size_in_bits)
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "EC", pub_key.key_size

    if isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA", pub_key.key_size

    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256

    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 448

    return "UNKNOWN", 0


# ─── HELPER: SIGNATURE ALGORITHM NAME ───────────────────────
def get_signature_algorithm_name(oid: str) -> str:
    # Maps OID dotted string to human readable name
    OID_MAP = {
        "1.2.840.113549.1.1.5":  "SHA1withRSA",
        "1.2.840.113549.1.1.11": "SHA256withRSA",
        "1.2.840.113549.1.1.12": "SHA384withRSA",
        "1.2.840.113549.1.1.13": "SHA512withRSA",
        "1.2.840.10045.4.3.2":   "SHA256withECDSA",
        "1.2.840.10045.4.3.3":   "SHA384withECDSA",
        "1.2.840.10045.4.3.4":   "SHA512withECDSA",
        "1.3.101.112":           "Ed25519",
        "1.3.101.113":           "Ed448",
        "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    }
    return OID_MAP.get(oid, f"UNKNOWN({oid})")