# Tier 1 🟢 Fully Quantum Safe     → ML-KEM, ML-DSA, SLH-DSA
# Tier 2 🟡 PQC Transitioning      → Hybrid schemes
# Tier 3 🔴 Quantum Vulnerable      → RSA, ECDSA, ECDH, X25519, DHE
# Tier 4 ☠️  Immediately Remediate  → RC4, DES, 3DES, MD5, SHA-1, TLS 1.0/1.1

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from scanner.tls_scanner import TLSScanResult
from scanner.cert_parser  import CertResult
from scanner.api_prober   import APIProbeResult
from utils.logger         import get_logger

logger = get_logger(__name__)


_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "algorithm_registry.json")

def _load_registry() -> dict:
    with open(_REGISTRY_PATH, "r") as f:
        entries = json.load(f)
    # Build lookup: normalized name → entry
    return { e["algorithm"].upper(): e for e in entries }

REGISTRY: dict = _load_registry()


# result object
@dataclass
class ComponentClassification:
    component:    str           # "key_exchange" | "cipher" | "tls_version" | "certificate" | "api"
    algorithm:    str           # raw algorithm name as discovered
    tier:         int           # 1-4
    tier_label:   str           # "Fully Quantum Safe" | "PQC Transitioning" | etc.
    primitive:    str           # "KEM" | "Signature" | "Symmetric" | "Hash" | "Protocol"
    nist_status:  str           # "STANDARDIZED" | "CANDIDATE" | "LEGACY" | "DEPRECATED"
    oid:          Optional[str] = None
    notes:        str           = ""

@dataclass
class ClassificationResult:
    host:                   str
    key_exchange_class:     Optional[ComponentClassification] = None
    cipher_class:           Optional[ComponentClassification] = None
    tls_version_class:      Optional[ComponentClassification] = None
    cert_sig_class:         Optional[ComponentClassification] = None   # leaf cert sig algo
    api_auth_class:         Optional[ComponentClassification] = None
    worst_tier:             int           = 1    # overall worst tier found
    worst_tier_label:       str           = "Fully Quantum Safe"
    all_components:         list          = field(default_factory=list)
    warnings:               list[str]     = field(default_factory=list)

    def to_dict(self):
        return {
            "host":             self.host,
            "worst_tier":       self.worst_tier,
            "worst_tier_label": self.worst_tier_label,
            "components": [
                {
                    "component":   c.component,
                    "algorithm":   c.algorithm,
                    "tier":        c.tier,
                    "tier_label":  c.tier_label,
                    "primitive":   c.primitive,
                    "nist_status": c.nist_status,
                    "oid":         c.oid,
                    "notes":       c.notes,
                }
                for c in self.all_components
            ],
            "warnings": self.warnings,
        }


# Tier Classification
TIER_LABELS = {
    1: "Fully Quantum Safe",
    2: "PQC Transitioning",
    3: "Quantum Vulnerable",
    4: "Immediately Remediate",
}


#classifier logic
def classify(
    host:       str,
    tls_result: TLSScanResult,
    cert_chain: list[CertResult],
    api_result: APIProbeResult,
) -> ClassificationResult:
    
    result = ClassificationResult(host=host)

    # 1. Classify key exchange
    if tls_result and tls_result.key_exchange:
        kx_class = _classify_algorithm(
            algorithm=tls_result.key_exchange,
            component="key_exchange",
            extra_info=tls_result.key_exchange_curve,
        )
        result.key_exchange_class = kx_class
        result.all_components.append(kx_class)

    # 2. Classify best negotiated cipher suite
    if tls_result and tls_result.supported_ciphers:
        # Use the best (first) cipher as representative
        best_cipher = tls_result.supported_ciphers[0]
        cipher_class = _classify_cipher_suite(best_cipher)
        result.cipher_class = cipher_class
        result.all_components.append(cipher_class)

    # 3. Classify TLS version
    if tls_result and tls_result.best_version:
        version_class = _classify_tls_version(tls_result.best_version)
        result.tls_version_class = version_class
        result.all_components.append(version_class)

        
        if tls_result.worst_version:
            worst_ver_class = _classify_tls_version(tls_result.worst_version)
            if worst_ver_class.tier > version_class.tier:
                result.warnings.append(
                    f"Server still supports {tls_result.worst_version} "
                    f"(Tier {worst_ver_class.tier} — {worst_ver_class.tier_label})"
                )

    # 4. Classify leaf certificate signature algorithm
    leaf_certs = [c for c in cert_chain if c.is_leaf and c.signature_algorithm]
    if leaf_certs:
        leaf = leaf_certs[0]
        cert_class = _classify_algorithm(
            algorithm=leaf.signature_algorithm,
            component="certificate",
            extra_info=f"key_type={leaf.public_key_type} key_size={leaf.public_key_size}",
        )
        cert_class.oid = leaf.signature_algorithm_oid
        result.cert_sig_class = cert_class
        result.all_components.append(cert_class)

        # Propagate cert warnings
        result.warnings.extend(leaf.warnings)

    # 5. Classify API auth mechanism
    if api_result and api_result.auth_mechanism:
        api_class = _classify_api_auth(
            auth_mechanism=api_result.auth_mechanism,
            jwt_algorithm=api_result.jwt_algorithm,
        )
        result.api_auth_class = api_class
        result.all_components.append(api_class)

    # 6. Compute overall worst tier
    if result.all_components:
        result.worst_tier = max(c.tier for c in result.all_components)
        result.worst_tier_label = TIER_LABELS[result.worst_tier]

    logger.info(
        f"[classifier] {host} → Tier {result.worst_tier} ({result.worst_tier_label})"
    )
    return result



def _classify_algorithm(
    algorithm:  str,
    component:  str,
    extra_info: Optional[str] = None,
) -> ComponentClassification:
    
    normalized = algorithm.upper().strip()

    # Direct registry lookup
    if normalized in REGISTRY:
        entry = REGISTRY[normalized]
        return ComponentClassification(
            component   = component,
            algorithm   = algorithm,
            tier        = entry["tier"],
            tier_label  = TIER_LABELS[entry["tier"]],
            primitive   = entry.get("primitive", "Unknown"),
            nist_status = entry.get("nist_status", "UNKNOWN"),
            notes       = entry.get("notes", ""),
        )

    # Heuristic fallback — handles versioned names like "RSA-4096"
    tier, primitive, nist_status, notes = _heuristic_classify(normalized, extra_info)

    return ComponentClassification(
        component   = component,
        algorithm   = algorithm,
        tier        = tier,
        tier_label  = TIER_LABELS[tier],
        primitive   = primitive,
        nist_status = nist_status,
        notes       = notes or f"Not in registry — classified via heuristic",
    )



def _classify_cipher_suite(cipher_suite: str) -> ComponentClassification:
    
    upper = cipher_suite.upper()

    # Tier 4: broken ciphers
    if any(x in upper for x in ["RC4", "DES", "NULL", "ANON", "EXPORT", "MD5"]):
        return ComponentClassification(
            component   = "cipher",
            algorithm   = cipher_suite,
            tier        = 4,
            tier_label  = TIER_LABELS[4],
            primitive   = "Symmetric",
            nist_status = "DEPRECATED",
            notes       = "Broken cipher — immediate remediation required",
        )

    # Tier 3: SHA-1 in cipher suite name
    if "SHA" in upper and "SHA256" not in upper and "SHA384" not in upper and "SHA512" not in upper:
        if "SHA " in upper or upper.endswith("SHA"):
            return ComponentClassification(
                component   = "cipher",
                algorithm   = cipher_suite,
                tier        = 3,
                tier_label  = TIER_LABELS[3],
                primitive   = "Symmetric",
                nist_status = "LEGACY",
                notes       = "SHA-1 MAC — quantum vulnerable hash",
            )

    # AES-GCM / AES-CCM / ChaCha20 are symmetric — quantum-safe with 256-bit keys
    # 128-bit provides ~64-bit post-quantum security (Grover) — acceptable but not ideal
    if any(x in upper for x in ["AES_256", "CHACHA20"]):
        return ComponentClassification(
            component   = "cipher",
            algorithm   = cipher_suite,
            tier        = 1,
            tier_label  = TIER_LABELS[1],
            primitive   = "Symmetric",
            nist_status = "STANDARDIZED",
            notes       = "256-bit symmetric — quantum safe (Grover provides only quadratic speedup)",
        )

    if "AES_128" in upper:
        return ComponentClassification(
            component   = "cipher",
            algorithm   = cipher_suite,
            tier        = 2,
            tier_label  = TIER_LABELS[2],
            primitive   = "Symmetric",
            nist_status = "STANDARDIZED",
            notes       = "128-bit symmetric — 64-bit post-quantum security (Grover). Acceptable transitional.",
        )

    # Default: treat as unknown but not broken
    return ComponentClassification(
        component   = "cipher",
        algorithm   = cipher_suite,
        tier        = 3,
        tier_label  = TIER_LABELS[3],
        primitive   = "Symmetric",
        nist_status = "UNKNOWN",
        notes       = "Unknown cipher suite — classified conservative Tier 3",
    )



def _classify_tls_version(version: str) -> ComponentClassification:
    """
    TLS version strings from sslyze:
    "SSL_2_0", "SSL_3_0", "TLS_1_0", "TLS_1_1", "TLS_1_2", "TLS_1_3"
    """
    VERSION_TIERS = {
        "SSL_2_0": 4,
        "SSL_3_0": 4,
        "TLS_1_0": 4,
        "TLS_1_1": 4,
        "TLS_1_2": 3,
        "TLS_1_3": 1,   # TLS 1.3 uses ECDHE/X25519 by default — still Tier 3 for KE
                         # but the protocol itself is current
    }
    upper = version.upper().replace(" ", "_").replace(".", "_")
    tier  = VERSION_TIERS.get(upper, 3)

    return ComponentClassification(
        component   = "tls_version",
        algorithm   = version,
        tier        = tier,
        tier_label  = TIER_LABELS[tier],
        primitive   = "Protocol",
        nist_status = "DEPRECATED" if tier == 4 else ("LEGACY" if tier == 3 else "STANDARDIZED"),
        notes       = _tls_version_note(upper),
    )

def _tls_version_note(version: str) -> str:
    notes = {
        "SSL_2_0": "Broken protocol — DROWN attack. Immediate remediation required.",
        "SSL_3_0": "Broken protocol — POODLE attack. Immediate remediation required.",
        "TLS_1_0": "Deprecated per RFC 8996 (2021). PCI-DSS non-compliant.",
        "TLS_1_1": "Deprecated per RFC 8996 (2021). Should be disabled.",
        "TLS_1_2": "Current but uses classical key exchange. Plan migration to TLS 1.3 + PQC KEM.",
        "TLS_1_3": "Current protocol. Awaiting IANA registration of PQC cipher suites.",
    }
    return notes.get(version, "Unknown TLS version")



def _classify_api_auth(
    auth_mechanism: str,
    jwt_algorithm:  Optional[str],
) -> ComponentClassification:
    """
    Maps API authentication mechanism to PQC tier.
    JWT with RSA/ECDSA = Tier 3 (quantum vulnerable asymmetric).
    JWT with HMAC = Tier 2 (symmetric — not quantum vulnerable but no PQC standard yet).
    """
    if auth_mechanism == "JWT" and jwt_algorithm:
        upper = jwt_algorithm.upper()

        if upper.startswith("RS"):
            return ComponentClassification(
                component   = "api",
                algorithm   = f"JWT/{jwt_algorithm}",
                tier        = 3,
                tier_label  = TIER_LABELS[3],
                primitive   = "Signature",
                nist_status = "LEGACY",
                notes       = f"JWT signed with RSA ({jwt_algorithm}) — quantum vulnerable. Migrate to ML-DSA when IETF PQC JWT standard finalised.",
            )
        if upper.startswith("ES"):
            return ComponentClassification(
                component   = "api",
                algorithm   = f"JWT/{jwt_algorithm}",
                tier        = 3,
                tier_label  = TIER_LABELS[3],
                primitive   = "Signature",
                nist_status = "LEGACY",
                notes       = f"JWT signed with ECDSA ({jwt_algorithm}) — quantum vulnerable. Migrate to ML-DSA when IETF PQC JWT standard finalised.",
            )
        if upper.startswith("HS"):
            return ComponentClassification(
                component   = "api",
                algorithm   = f"JWT/{jwt_algorithm}",
                tier        = 2,
                tier_label  = TIER_LABELS[2],
                primitive   = "MAC",
                nist_status = "STANDARDIZED",
                notes       = f"JWT with HMAC ({jwt_algorithm}) — symmetric, not quantum vulnerable. No PQC JWT standard yet (ref: NIST IR 8413).",
            )

    if auth_mechanism == "BasicAuth":
        return ComponentClassification(
            component   = "api",
            algorithm   = "BasicAuth",
            tier        = 4,
            tier_label  = TIER_LABELS[4],
            primitive   = "Authentication",
            nist_status = "DEPRECATED",
            notes       = "Basic Auth — credentials transmitted base64 encoded. Immediate upgrade required regardless of quantum risk.",
        )

    if auth_mechanism == "mTLS":
        # mTLS inherits tier from the cert's key — flag for further cert inspection
        return ComponentClassification(
            component   = "api",
            algorithm   = "mTLS",
            tier        = 3,
            tier_label  = TIER_LABELS[3],
            primitive   = "Authentication",
            nist_status = "LEGACY",
            notes       = "mTLS client auth — inherits quantum vulnerability from underlying certificate key algorithm.",
        )

    # APIKey / None / OAuth2
    return ComponentClassification(
        component   = "api",
        algorithm   = auth_mechanism or "None",
        tier        = 2,
        tier_label  = TIER_LABELS[2],
        primitive   = "Authentication",
        nist_status = "UNKNOWN",
        notes       = f"Auth mechanism '{auth_mechanism}' — quantum risk depends on transport layer (TLS). Classified Tier 2 conservatively.",
    )



def _heuristic_classify(
    normalized: str,
    extra_info: Optional[str],
) -> tuple[int, str, str, str]:
    """
    Returns (tier, primitive, nist_status, notes)
    when algorithm is not found in registry.
    """

    # ── Tier 1 patterns ──
    if any(x in normalized for x in ["ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA",
                                       "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS",
                                       "FALCON", "BIKE", "HQC", "NTRU", "FRODOKEM"]):
        return 1, "KEM/Signature", "STANDARDIZED", "Post-quantum algorithm — Tier 1 safe"

    # ── Tier 2 patterns ──
    if any(x in normalized for x in ["KYBER768", "X25519KYBER", "P256KYBER",
                                       "HYBRID", "XWING"]):
        return 2, "KEM", "CANDIDATE", "Hybrid PQC — transitional Tier 2"

    # ── Tier 4 patterns ──
    if any(x in normalized for x in ["RC4", "DES", "3DES", "TRIPLEDES",
                                       "MD5", "SHA1", "SHA-1", "NULL",
                                       "EXPORT", "ANON", "SSL2", "SSL3",
                                       "TLS10", "TLS11", "TLS_1_0", "TLS_1_1"]):
        return 4, "Deprecated", "DEPRECATED", "Broken algorithm — immediate remediation required"

    # ── Tier 3 patterns ──
    if any(x in normalized for x in ["RSA", "ECDH", "ECDSA", "DHE", "DH",
                                       "X25519", "X448", "ED25519", "ED448",
                                       "P-256", "P-384", "P-521", "SECP"]):
        return 3, "Asymmetric", "LEGACY", "Classical public-key — quantum vulnerable"

    # ── Unknown — conservative Tier 3 ──
    return 3, "Unknown", "UNKNOWN", "Not in registry and not matched by heuristic — conservative Tier 3"