# Issues a cryptographically signed PQC Readiness Badge per scanned asset.

# Badge is a JSON object signed with Ed25519 (PyNaCl).
# Ed25519 is itself quantum-safe at the signing level — ironic that
# we use a modern signature to certify PQC readiness of others.


import json
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Optional

import nacl.signing
import nacl.encoding
import nacl.exceptions

from config import settings
from classifier.pqc_classifier import ClassificationResult
from classifier.risk_scorer    import RiskScore
from utils.logger              import get_logger

# Badge lifecycle:
#   ISSUED    → fresh scan, asset passed threshold
#   VALID     → badge still within expiry, asset not regressed
#   REVOKED   → asset re-scanned and tier worsened
#   EXPIRED   → badge older than 90 days

logger = get_logger(__name__)

BADGE_VALIDITY_DAYS  = 90     # badge expires after 90 days
BADGE_VERSION        = "1.0"
ISSUER_NAME          = "QuantumShieldScanner — PSB Hackathon 2026"

TIER_TO_LABEL = {
    1: "QUANTUM_SAFE",
    2: "PQC_TRANSITIONING",
    3: "QUANTUM_VULNERABLE",
    4: "CRITICAL_RISK",
}

TIER_TO_BADGE_COLOR = {
    1: "#22C55E",   # green
    2: "#F6C90E",   # yellow
    3: "#EF4444",   # red
    4: "#7F1D1D",   # dark red
}


# PQC Badge Object 
@dataclass
class PQCBadge:
    host:           str
    pqc_label:      str       # "QUANTUM_SAFE" | "PQC_TRANSITIONING" | etc.
    pqc_tier:       int       # 1-4
    risk_score:     int       # 0-100
    risk_label:     str       # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    issued_at:      str       # ISO timestamp
    expires_at:     str       # ISO timestamp (issued + 90 days)
    fingerprint:    str       # SHA-256 of badge payload
    signature:      str       # Ed25519 signature (base64)
    public_key:     str       # Ed25519 public key (base64) — for verification
    status:         str       # "ISSUED"
    badge_color:    str       # hex color for UI
    algorithms_found: list    # all algorithms discovered during scan
    revocation_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "version":          BADGE_VERSION,
            "host":             self.host,
            "pqc_label":        self.pqc_label,
            "pqc_tier":         self.pqc_tier,
            "risk_score":       self.risk_score,
            "risk_label":       self.risk_label,
            "issued_at":        self.issued_at,
            "expires_at":       self.expires_at,
            "fingerprint":      self.fingerprint,
            "signature":        self.signature,
            "public_key":       self.public_key,
            "status":           self.status,
            "badge_color":      self.badge_color,
            "issuer":           ISSUER_NAME,
            "algorithms_found": self.algorithms_found,
            "revocation_reason": self.revocation_reason,
        }


def issue_badge(
    classification: ClassificationResult,
    risk_score:     RiskScore,
) -> PQCBadge:
    """
    Called by scan_task.py after CBOM is built.
    Signs a badge payload with Ed25519 and returns PQCBadge.
    """
    now        = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=BADGE_VALIDITY_DAYS)
    tier       = classification.worst_tier

    algorithms_found = [
        {
            "component":   c.component,
            "algorithm":   c.algorithm,
            "tier":        c.tier,
            "tier_label":  c.tier_label,
            "primitive":   c.primitive,
            "nist_status": c.nist_status,
        }
        for c in classification.all_components
    ]

    payload = {
        "version":          BADGE_VERSION,
        "host":             classification.host,
        "pqc_label":        TIER_TO_LABEL[tier],
        "pqc_tier":         tier,
        "risk_score":       risk_score.final_score,
        "risk_label":       risk_score.label,
        "issued_at":        now.isoformat(),
        "expires_at":       expires_at.isoformat(),
        "issuer":           ISSUER_NAME,
        "algorithms_found": algorithms_found,
        "status":           "ISSUED",
    }

    canonical   = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    payload["fingerprint"] = fingerprint

    # Sign with Ed25519 
    signature, public_key_b64 = _sign_payload(canonical)

    badge = PQCBadge(
        host             = classification.host,
        pqc_label        = TIER_TO_LABEL[tier],
        pqc_tier         = tier,
        risk_score       = risk_score.final_score,
        risk_label       = risk_score.label,
        issued_at        = now.isoformat(),
        expires_at       = expires_at.isoformat(),
        fingerprint      = fingerprint,
        signature        = signature,
        public_key       = public_key_b64,
        status           = "ISSUED",
        badge_color      = TIER_TO_BADGE_COLOR[tier],
        algorithms_found = algorithms_found,
    )

    logger.info(
        f"[label_issuer] Badge issued for {classification.host} → "
        f"{badge.pqc_label} | Score={badge.risk_score} | "
        f"Fingerprint={fingerprint[:16]}..."
    )

    return badge
##
def revoke_badge(
    existing_badge_json: dict,
    reason:              str,
) -> dict:
    """
    Called by scan_task.py when re-scan shows tier regression.
    Marks existing badge as REVOKED and re-signs revocation.

    Regression = new worst_tier > old pqc_tier
    Example: was Tier 2 (PQC_TRANSITIONING), now Tier 3 (QUANTUM_VULNERABLE)
    """
    existing_badge_json["status"]            = "REVOKED"
    existing_badge_json["revocation_reason"] = reason
    existing_badge_json["revoked_at"]        = datetime.now(timezone.utc).isoformat()

    # Re-fingerprint the revoked badge
    # Remove old signature fields before re-fingerprinting
    for field in ["signature", "fingerprint", "public_key"]:
        existing_badge_json.pop(field, None)

    canonical   = json.dumps(existing_badge_json, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    signature, public_key_b64 = _sign_payload(canonical)

    existing_badge_json["fingerprint"] = fingerprint
    existing_badge_json["signature"]   = signature
    existing_badge_json["public_key"]  = public_key_b64

    logger.warning(
        f"[label_issuer] Badge REVOKED for {existing_badge_json.get('host')} → "
        f"Reason: {reason}"
    )

    return existing_badge_json

def check_regression(
    existing_badge_json: Optional[dict],
    new_classification:  ClassificationResult,
) -> tuple[bool, str]:
    """
    Compares new scan tier against existing badge tier.
    Returns (is_regression, reason_string).
    Called by scan_task.py before issuing new badge.
    """
    if not existing_badge_json:
        return False, ""

    old_tier = existing_badge_json.get("pqc_tier", 1)
    new_tier = new_classification.worst_tier

    if new_tier > old_tier:
        reason = (
            f"PQC tier regressed from {old_tier} "
            f"({TIER_TO_LABEL.get(old_tier, 'Unknown')}) "
            f"to {new_tier} "
            f"({TIER_TO_LABEL.get(new_tier, 'Unknown')}) "
            f"on re-scan at {datetime.now(timezone.utc).isoformat()}"
        )
        return True, reason

    return False, ""

def verify_badge(badge_json: dict) -> tuple[bool, str]:
    """
    Verifies Ed25519 signature on a badge.
    Called by middleware's /verify endpoint.
    Returns (is_valid, message).
    """
    try:
        signature_b64  = badge_json.get("signature")
        public_key_b64 = badge_json.get("public_key")

        if not signature_b64 or not public_key_b64:
            return False, "Badge missing signature or public key"

        # Check expiry
        expires_at = datetime.fromisoformat(badge_json.get("expires_at", ""))
        if datetime.now(timezone.utc) > expires_at:
            return False, "Badge has expired"

        # Check revocation
        if badge_json.get("status") == "REVOKED":
            return False, f"Badge is revoked: {badge_json.get('revocation_reason', '')}"

        # Reconstruct the canonical payload that was signed
        verify_payload = {k: v for k, v in badge_json.items()
                          if k not in ("signature", "public_key")}
        canonical = json.dumps(verify_payload, sort_keys=True, separators=(",", ":"))

        # Verify Ed25519 signature
        pub_key_bytes = base64.b64decode(public_key_b64)
        sig_bytes     = base64.b64decode(signature_b64)

        verify_key = nacl.signing.VerifyKey(pub_key_bytes)
        verify_key.verify(canonical.encode(), sig_bytes)

        return True, "Badge is valid and signature verified"

    except nacl.exceptions.BadSignatureError:
        return False, "Invalid signature — badge may have been tampered with"
    except Exception as e:
        return False, f"Verification failed: {str(e)}"


def _sign_payload(canonical: str) -> tuple[str, str]:
    """
    Signs canonical JSON string with Ed25519.
    Returns (signature_b64, public_key_b64).

    Private key loaded from settings.BADGE_PRIVATE_KEY
    which is a base64-encoded 32-byte Ed25519 seed stored in .env
    """
    try:
        # Load private key from env
        private_key_bytes = base64.b64decode(settings.BADGE_PRIVATE_KEY)
        signing_key       = nacl.signing.SigningKey(private_key_bytes)

    except Exception:
        logger.warning(
            "[label_issuer] BADGE_PRIVATE_KEY not set — "
            "using ephemeral key. DO NOT use in production."
        )
        signing_key = nacl.signing.SigningKey.generate()

    signed        = signing_key.sign(canonical.encode())
    signature_b64 = base64.b64encode(signed.signature).decode()
    public_key_b64 = base64.b64encode(
        bytes(signing_key.verify_key)
    ).decode()

    return signature_b64, public_key_b64


def generate_badge_keypair() -> tuple[str, str]:
    """
    One-time utility to generate Ed25519 keypair for .env setup.
    Run once: python -c "from cbom.label_issuer import generate_badge_keypair; print(generate_badge_keypair())"
    Output: (private_key_b64, public_key_b64)
    Store private_key_b64 as BADGE_PRIVATE_KEY in .env
    """
    signing_key    = nacl.signing.SigningKey.generate()
    private_key_b64 = base64.b64encode(bytes(signing_key)).decode()
    public_key_b64  = base64.b64encode(bytes(signing_key.verify_key)).decode()
    return private_key_b64, public_key_b64