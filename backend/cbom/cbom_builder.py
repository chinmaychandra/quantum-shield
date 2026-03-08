# CBOM structure:
#   metadata        → scan info, tool, timestamp
#   components[]    → one entry per cryptographic asset discovered
#     → algorithms  → name, OID, primitive, mode, padding
#     → keys        → size, state, mechanism, creation date
#     → protocols   → name, version, cipher suites
#     → certificates→ subject, issuer, expiry, chain
#   vulnerabilities → HNDL risk findings per component

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from scanner.tls_scanner import TLSScanResult
from scanner.cert_parser import CertResult
from scanner.api_prober import APIProbeResult
from scanner.discovery import DiscoveryResult
from classifier.pqc_classifier import ClassificationResult
from classifier.risk_scorer  import RiskScore
from utils.logger  import get_logger

logger = get_logger(__name__)


CYCLONEDX_VERSION   = "1.6"
CYCLONEDX_SCHEMA    = "http://cyclonedx.org/schema/bom/1.6"
COMPONENT_TYPE      = "cryptographic-asset"
TOOL_NAME           = "QuantumShieldScanner"
TOOL_VERSION        = "1.0.0"
TOOL_VENDOR         = "Team Arrogance — PSB Hackathon 2026"


def build_cbom(
    host:           str,
    discovery:      DiscoveryResult,
    tls_result:     TLSScanResult,
    cert_chain:     list[CertResult],
    api_result:     APIProbeResult,
    classification: ClassificationResult,
    risk_score:     RiskScore,
    scan_id:        str,
) -> dict:
    """
    Called by scan_task.py with all phase outputs.
    Returns a fully populated CycloneDX 1.6 CBOM dict.
    """
    now = datetime.now(timezone.utc).isoformat()

    cbom = {
        "bomFormat":   "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":     1,
        "metadata":    _build_metadata(host, scan_id, now),
        "components":  [],
        "vulnerabilities": [],
        "dependencies": [],
    }

    #TLS protocol
    if tls_result:
        tls_component = _build_tls_component(host, tls_result, classification)
        cbom["components"].append(tls_component)

    #Certificates :One per chain
    for i, cert in enumerate(cert_chain):
        cert_component = _build_cert_component(host, cert, i, classification)
        cbom["components"].append(cert_component)

    #API auth
    if api_result and api_result.auth_mechanism and api_result.auth_mechanism != "None":
        api_component = _build_api_component(host, api_result, classification)
        cbom["components"].append(api_component)

    #Vuln
    cbom["vulnerabilities"] = _build_vulnerabilities(
        host, classification, risk_score
    )

    if discovery:
        cbom["dependencies"] = _build_discovery_metadata(discovery)

    logger.info(
        f"[cbom_builder] {host} → "
        f"Built CBOM with {len(cbom['components'])} components, "
        f"{len(cbom['vulnerabilities'])} findings"
    )

    return cbom

def _build_metadata(host: str, scan_id: str, timestamp: str) -> dict:
    return {
        "timestamp": timestamp,
        "tools": [{
            "vendor":  TOOL_VENDOR,
            "name":    TOOL_NAME,
            "version": TOOL_VERSION,
        }],
        "component": {
            "type":    "device",
            "name":    host,
            "bom-ref": f"asset:{host}",
        },
        "properties": [
            { "name": "scan:id",     "value": scan_id },
            { "name": "scan:target", "value": host },
            { "name": "scan:standard", "value": "CERT-In Annexure-A" },
            { "name": "scan:nist-pqc", "value": "FIPS-203/204/205" },
        ]
    }


def _build_tls_component(
    host:           str,
    tls:            TLSScanResult,
    classification: ClassificationResult,
) -> dict:
    """
    Covers CERT-In Annexure-A: Protocol fields
    - Protocol Name, Version, Supported Cipher Suites,
      Key Exchange, Session Resumption, Compression
    """
    comp = {
        "type":    COMPONENT_TYPE,
        "bom-ref": f"tls:{host}",
        "name":    f"TLS Protocol — {host}",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type":    "tls",
                "version": tls.best_version or "Unknown",
                "cipherSuites": tls.supported_ciphers[:20] if tls.supported_ciphers else [],
                # CERT-In Annexure-A: Key Exchange Algorithm
                "ikev2TransformTypes": [{
                    "type":      "keyExchange",
                    "algorithm": tls.key_exchange or "Unknown",
                    "curve":     tls.key_exchange_curve or "N/A",
                    "bits":      tls.key_exchange_bits or 0,
                }],
            },
            # CERT-In Annexure-A: Quantum safety classification
            "classicalSecurityLevel": _key_bits_to_classical(tls.key_exchange_bits),
            "quantumSecurityLevel":   _key_bits_to_quantum(tls.key_exchange_bits),
        },
        "properties": [
            { "name": "tls:bestVersion",     "value": tls.best_version  or "Unknown" },
            { "name": "tls:worstVersion",    "value": tls.worst_version or "Unknown" },
            { "name": "tls:totalCiphers",    "value": str(len(tls.supported_ciphers or [])) },
            { "name": "tls:sessionResumption","value": str(tls.session_resumption) },
            { "name": "tls:compression",     "value": str(tls.compression_enabled) },
            { "name": "tls:fallbackSCSV",    "value": str(tls.fallback_scsv) },
            { "name": "tls:heartbleed",      "value": str(tls.heartbleed_vulnerable) },
            { "name": "tls:robot",           "value": str(tls.robot_vulnerable) },
            { "name": "pqc:tier",            "value": str(classification.worst_tier) },
            { "name": "pqc:tierLabel",       "value": classification.worst_tier_label },
            { "name": "pqc:keyExchangeAlgo", "value": tls.key_exchange or "Unknown" },
        ],
    }

    # Flag vulnerabilities inline
    if tls.heartbleed_vulnerable:
        comp["properties"].append({ "name": "vuln:heartbleed", "value": "true" })
    if tls.robot_vulnerable:
        comp["properties"].append({ "name": "vuln:robot", "value": "true" })

    return comp

def _build_cert_component(
    host:           str,
    cert:           CertResult,
    index:          int,
    classification: ClassificationResult,
) -> dict:
    """
    Covers CERT-In Annexure-A: Certificate fields
    - Format, Subject, Issuer, Serial, Validity, Signature Algorithm,
      Public Key Type/Size, SANs, Key Usage, OCSP, CRL
    """
    cert_type = "leaf" if cert.is_leaf else f"intermediate-{index}"

    comp = {
        "type":    COMPONENT_TYPE,
        "bom-ref": f"cert:{host}:{cert_type}",
        "name":    f"Certificate [{cert_type}] — {cert.subject or host}",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                # CERT-In Annexure-A mandatory fields
                "subjectName":          cert.subject or "Unknown",
                "issuerName":           cert.issuer  or "Unknown",
                "notValidBefore":       cert.not_valid_before.isoformat() if cert.not_valid_before else None,
                "notValidAfter":        cert.not_valid_after.isoformat()  if cert.not_valid_after  else None,
                "certificateFormat":    cert.cert_format    or "X.509",
                "certificateExtension": cert.cert_extension or ".crt",
                # Signature
                "signatureAlgorithmRef": f"algo:{cert.signature_algorithm}:{host}",
            },
            # CERT-In Annexure-A: Algorithm fields
            "algorithmProperties": {
                "primitive":         _sig_algo_to_primitive(cert.signature_algorithm),
                "parameterSetIdentifier": cert.signature_algorithm_oid or "Unknown",
                "classicalSecurityLevel": _key_bits_to_classical(cert.public_key_size),
                "quantumSecurityLevel":   _key_bits_to_quantum(cert.public_key_size),
                "cryptoFunctions":   ["sign", "verify"],
                "nistQuantumSecurityLevel": _tier_to_nist_level(
                    classification.cert_sig_class.tier
                    if classification.cert_sig_class else 3
                ),
            },
        },
        "properties": [
            { "name": "cert:serialNumber",      "value": cert.serial_number    or "Unknown" },
            { "name": "cert:publicKeyType",     "value": cert.public_key_type  or "Unknown" },
            { "name": "cert:publicKeySize",     "value": str(cert.public_key_size or 0) },
            { "name": "cert:signatureAlgorithm","value": cert.signature_algorithm or "Unknown" },
            { "name": "cert:signatureAlgoOID",  "value": cert.signature_algorithm_oid or "Unknown" },
            { "name": "cert:daysToExpiry",      "value": str(cert.days_to_expiry or 0) },
            { "name": "cert:isExpired",         "value": str(cert.is_expired) },
            { "name": "cert:isSelfSigned",      "value": str(cert.is_self_signed) },
            { "name": "cert:isCA",              "value": str(cert.is_ca) },
            { "name": "cert:ocspUrl",           "value": cert.ocsp_url or "Not present" },
            { "name": "cert:crlUrl",            "value": cert.crl_url  or "Not present" },
            { "name": "cert:keyUsage",          "value": ", ".join(cert.key_usage or []) },
            { "name": "cert:sans",              "value": ", ".join((cert.san_list or [])[:10]) },
        ],
    }

    # CERT-In: Key State — active / expired / expiring-soon
    key_state = _determine_key_state(cert)
    comp["cryptoProperties"]["algorithmProperties"]["keyState"] = key_state

    return comp

def _build_api_component(
    host:           str,
    api:            APIProbeResult,
    classification: ClassificationResult,
) -> dict:
    """
    Covers CERT-In Annexure-A: Application-layer crypto
    - Auth mechanism, JWT algorithm, security headers
    """
    comp = {
        "type":    COMPONENT_TYPE,
        "bom-ref": f"api:{host}",
        "name":    f"API Authentication — {host}",
        "cryptoProperties": {
            "assetType": "relatedCryptoMaterial",
            "relatedCryptoMaterialProperties": {
                "type":       "token",
                "mechanism":  api.auth_mechanism or "Unknown",
                "algorithm":  api.jwt_algorithm  or "N/A",
            },
        },
        "properties": [
            { "name": "api:authMechanism",  "value": api.auth_mechanism  or "None" },
            { "name": "api:jwtAlgorithm",   "value": api.jwt_algorithm   or "N/A"  },
            { "name": "api:hstsPresent",    "value": str(api.hsts_present) },
            { "name": "api:hstMaxAge",      "value": str(api.hsts_max_age or 0) },
            { "name": "api:cspPresent",     "value": str(api.csp_present) },
            { "name": "api:corsWildcard",   "value": str(api.cors_wildcard) },
            { "name": "api:serverHeader",   "value": api.server_header or "Not disclosed" },
        ],
    }
    return comp

def _build_vulnerabilities(
    host:           str,
    classification: ClassificationResult,
    risk_score:     RiskScore,
) -> list[dict]:
    """
    HNDL findings — one vulnerability entry per Tier 3/4 component.
    Format matches CycloneDX 1.6 vulnerability schema.
    """
    vulns = []

    for comp in classification.all_components:
        if comp.tier < 3:
            continue   # Tier 1 and 2 are not vulnerabilities

        severity = "critical" if comp.tier == 4 else "high"
        vuln_id  = f"HNDL-{host}-{comp.component}".upper().replace(".", "-")

        vuln = {
            "id":          vuln_id,
            "bom-ref":     f"vuln:{host}:{comp.component}",
            "source": {
                "name": "QuantumShieldScanner",
                "url":  "https://github.com/chinmaychandra/quantum-shield",
            },
            "ratings": [{
                "source":   { "name": "QuantumShieldScanner" },
                "score":    risk_score.final_score,
                "severity": severity,
                "method":   "HNDL-Score",
                "vector":   f"HNDL/T:{comp.tier}/W:{COMP_WEIGHTS.get(comp.component, 0)}",
            }],
            "description": (
                f"{comp.component.replace('_', ' ').title()} uses {comp.algorithm} "
                f"({comp.tier_label}) — vulnerable to Harvest Now Decrypt Later attacks "
                f"from Cryptanalytically Relevant Quantum Computers (CRQCs)."
            ),
            "recommendation": _get_remediation_for_component(comp),
            "affects": [{
                "ref": f"asset:{host}",
            }],
            "properties": [
                { "name": "pqc:tier",        "value": str(comp.tier) },
                { "name": "pqc:tierLabel",   "value": comp.tier_label },
                { "name": "pqc:primitive",   "value": comp.primitive },
                { "name": "pqc:nistStatus",  "value": comp.nist_status },
            ],
        }
        vulns.append(vuln)

    return vulns


def _build_discovery_metadata(discovery: DiscoveryResult) -> list[dict]:
    deps = []

    if discovery.ip_addresses:
        deps.append({
            "ref":      f"asset:{discovery.host}",
            "provides": [{ "ref": f"ip:{ip}" } for ip in discovery.ip_addresses],
        })

    return deps

def _determine_key_state(cert: CertResult) -> str:
    # CERT-In Annexure-A: Key State field
    if cert.is_expired:
        return "destroyed"          # expired = no longer valid
    if cert.days_to_expiry and cert.days_to_expiry < 30:
        return "deactivated"        # about to expire
    if cert.is_ca:
        return "active"
    return "active"

def _key_bits_to_classical(bits: Optional[int]) -> int:
    # Classical security level in bits
    if not bits:
        return 0
    RSA_CLASSICAL = { 512: 56, 1024: 80, 2048: 112, 3072: 128, 4096: 140 }
    if bits in RSA_CLASSICAL:
        return RSA_CLASSICAL[bits]
    return bits // 2   # EC keys: n-bit key ≈ n/2-bit classical security

def _key_bits_to_quantum(bits: Optional[int]) -> int:
    # Post-quantum security level in bits (Grover's algorithm)
    # Symmetric: n-bit key → n/2-bit quantum security
    # Asymmetric (RSA/EC): effectively 0 (broken by Shor's)
    if not bits:
        return 0
    return 0   # RSA/EC keys → 0 post-quantum security (Shor's algorithm)

def _tier_to_nist_level(tier: int) -> int:
    # NIST PQC security levels 1-5
    return { 1: 5, 2: 3, 3: 0, 4: 0 }.get(tier, 0)

def _sig_algo_to_primitive(algo: Optional[str]) -> str:
    if not algo:
        return "signature"
    a = algo.upper()
    if "RSA"  in a: return "signature"
    if "ECDSA"in a: return "signature"
    if "ED25519" in a: return "signature"
    if "ML-DSA"  in a: return "signature"
    if "ML-KEM"  in a: return "kem"
    return "signature"

def _get_remediation_for_component(comp) -> str:
    remap = {
        "key_exchange": "Migrate to ML-KEM-768 (FIPS 203). Use X25519Kyber768 hybrid as interim step.",
        "cipher":       "Upgrade to TLS_AES_256_GCM_SHA384. Disable all RC4/DES/3DES cipher suites.",
        "tls_version":  "Enforce TLS 1.3 minimum. Disable TLS 1.0, 1.1, and SSL 3.0 immediately.",
        "certificate":  "Plan migration to ML-DSA-65 (FIPS 204) when CA/Browser Forum support is available.",
        "api":          "Migrate to ML-DSA JWT when IETF PQC JWT RFC is finalised (ref: NIST IR 8413).",
    }
    return remap.get(comp.component, "Migrate to NIST PQC standardised algorithm.")

COMP_WEIGHTS = {
    "key_exchange": 0.30,
    "cipher":       0.25,
    "tls_version":  0.20,
    "certificate":  0.15,
    "api":          0.10,
}