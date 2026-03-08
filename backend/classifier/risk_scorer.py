# Weight distribution (must sum to 100):
#   Key Exchange   30%  ← highest weight: directly enables HNDL
#   Cipher Suite   25%  ← bulk encryption strength
#   TLS Version    20%  ← protocol-level security
#   Certificate    15%  ← signature algorithm on cert
#   API Auth       10%  ← application-layer auth mechanism
#
# Score per tier:
#   Tier 1 (Fully Quantum Safe)    →   0
#   Tier 2 (PQC Transitioning)     →  35
#   Tier 3 (Quantum Vulnerable)    →  70
#   Tier 4 (Immediately Remediate) → 100
#
# Final label:
#   80–100 → CRITICAL
#   60–79  → HIGH
#   40–59  → MEDIUM
#   0–39   → LOW

from dataclasses import dataclass, field
from classifier.pqc_classifier import ClassificationResult
from utils.logger import get_logger

logger = get_logger(__name__)


WEIGHTS = {
    "key_exchange": 0.30,
    "cipher":       0.25,
    "tls_version":  0.20,
    "certificate":  0.15,
    "api":          0.10,
}

TIER_SCORES = {
    1: 0,
    2: 35,
    3: 70,
    4: 100,
}

DEFAULT_SCORE_WHEN_MISSING = 0

@dataclass
class ComponentScore:
    component:    str     # "key_exchange" | "cipher" | etc.
    algorithm:    str     # human-readable algorithm name
    tier:         int     # 1-4
    raw_score:    int     # TIER_SCORES[tier] → 0, 35, 70, 100
    weight:       float   # 0.0–1.0
    weighted:     float   # raw_score * weight → contribution to final score

@dataclass
class RiskScore:
    host:           str
    final_score:    int           # 0–100, rounded
    label:          str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    breakdown:      list[ComponentScore] = field(default_factory=list)
    dominant_risk:  str           = ""   # which component is driving the score highest
    remediation_priority: list[str] = field(default_factory=list)
    cert_expiry_days: int         = None  # passed through for DB storage

    def to_dict(self):
        return {
            "host":          self.host,
            "final_score":   self.final_score,
            "label":         self.label,
            "dominant_risk": self.dominant_risk,
            "breakdown": [
                {
                    "component":  c.component,
                    "algorithm":  c.algorithm,
                    "tier":       c.tier,
                    "raw_score":  c.raw_score,
                    "weight":     c.weight,
                    "weighted":   round(c.weighted, 2),
                }
                for c in self.breakdown
            ],
            "remediation_priority": self.remediation_priority,
            "cert_expiry_days":     self.cert_expiry_days,
        }


def compute_risk_score(
    classification: ClassificationResult,
    cert_expiry_days: int = None,
) -> RiskScore:
    """
    Called by scan_task.py after pqc_classifier.classify() completes.
    Returns a fully populated RiskScore.
    """
    result = RiskScore(host=classification.host)
    result.cert_expiry_days = cert_expiry_days

    component_map = {
        "key_exchange": classification.key_exchange_class,
        "cipher":       classification.cipher_class,
        "tls_version":  classification.tls_version_class,
        "certificate":  classification.cert_sig_class,
        "api":          classification.api_auth_class,
    }

    weighted_total = 0.0
    highest_weighted = 0.0

    for component, cls in component_map.items():
        weight    = WEIGHTS[component]
        tier      = cls.tier if cls else 1
        algorithm = cls.algorithm if cls else "Not detected"
        raw       = TIER_SCORES[tier]
        weighted  = raw * weight

        cs = ComponentScore(
            component  = component,
            algorithm  = algorithm,
            tier       = tier,
            raw_score  = raw,
            weight     = weight,
            weighted   = weighted,
        )
        result.breakdown.append(cs)
        weighted_total += weighted

        # Track which component contributes most to risk
        if weighted > highest_weighted:
            highest_weighted    = weighted
            result.dominant_risk = component

    # ── Cert expiry bonus penalty ────────────────────────────
    # Expired or near-expiry cert adds flat points to the score
    # This is ADDITIVE — doesn't affect the weighted breakdown
    expiry_penalty = _cert_expiry_penalty(cert_expiry_days)
    raw_total      = weighted_total + expiry_penalty

    result.final_score = min(100, max(0, round(raw_total)))

    result.label = _score_to_label(result.final_score)

    result.remediation_priority = _build_remediation_priority(
        result.breakdown,
        cert_expiry_days,
        classification.warnings,
    )

    logger.info(
        f"[risk_scorer] {classification.host} → "
        f"Score={result.final_score} Label={result.label} "
        f"DominantRisk={result.dominant_risk}"
    )

    return result


def _cert_expiry_penalty(days: int) -> float:
    """
    Adds flat penalty to score based on certificate expiry.
    Does not affect breakdown weights — purely additive.
    """
    if days is None:
        return 0.0
    if days < 0:
        return 15.0   # already expired — severe penalty
    if days < 7:
        return 10.0   # expiring in < 1 week
    if days < 30:
        return 5.0    # expiring in < 1 month
    if days < 90:
        return 2.0    # expiring in < 3 months — mild heads-up
    return 0.0

def _score_to_label(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"

def _build_remediation_priority(
    breakdown:        list[ComponentScore],
    cert_expiry_days: int,
    warnings:         list[str],
) -> list[str]:
    """
    Generates a human-readable, ordered remediation list.
    Sorted by weighted score descending — highest risk first.
    """
    steps = []

    # Sort components by weighted score descending
    sorted_components = sorted(breakdown, key=lambda c: c.weighted, reverse=True)

    REMEDIATION_TEMPLATES = {
        "key_exchange": {
            4: "IMMEDIATE: Disable all classic key exchange (RSA-KE, DHE, ECDHE). Replace with ML-KEM-768 (FIPS 203) hybrid mode.",
            3: "HIGH: Key exchange ({algo}) is quantum vulnerable. Migrate to X25519Kyber768 hybrid, then ML-KEM-768 post-standardisation.",
            2: "MEDIUM: Key exchange is hybrid PQC transitional. Plan migration to pure ML-KEM-768 (FIPS 203) within 12 months.",
            1: "✓ Key exchange is quantum safe.",
        },
        "cipher": {
            4: "IMMEDIATE: Disable broken cipher ({algo}). Enable only AES-256-GCM or ChaCha20-Poly1305.",
            3: "HIGH: Cipher suite ({algo}) uses weak MAC or key size. Upgrade to TLS_AES_256_GCM_SHA384.",
            2: "MEDIUM: Cipher uses 128-bit key ({algo}). Consider upgrading to 256-bit for full quantum safety.",
            1: "✓ Cipher suite is quantum safe.",
        },
        "tls_version": {
            4: "IMMEDIATE: Disable {algo} — broken protocol with known exploits (POODLE/DROWN). Enable TLS 1.3 only.",
            3: "HIGH: {algo} is deprecated per RFC 8996. Disable and enforce TLS 1.3 minimum.",
            2: "MEDIUM: TLS version is acceptable. Plan full TLS 1.3 adoption.",
            1: "✓ TLS version is current.",
        },
        "certificate": {
            4: "IMMEDIATE: Certificate uses deprecated algorithm ({algo}). Replace with ECDSA P-256 now; migrate to ML-DSA-65 (FIPS 204) when CA support available.",
            3: "HIGH: Certificate signature ({algo}) is quantum vulnerable. Plan migration to ML-DSA-65 (FIPS 204) — target when public CAs support it.",
            2: "MEDIUM: Certificate uses transitional algorithm. Monitor NIST/CA-Browser Forum PQC certificate roadmap.",
            1: "✓ Certificate signature algorithm is quantum safe.",
        },
        "api": {
            4: "IMMEDIATE: Replace BasicAuth with token-based authentication over TLS 1.3.",
            3: "HIGH: API auth ({algo}) uses quantum-vulnerable asymmetric algorithm. Migrate to ML-DSA JWT when IETF PQC JWT RFC is finalised.",
            2: "MEDIUM: API auth uses symmetric mechanism ({algo}). Monitor IETF PQC JWT standard progress (NIST IR 8413).",
            1: "✓ API auth mechanism is quantum safe.",
        },
    }

    for cs in sorted_components:
        template = REMEDIATION_TEMPLATES.get(cs.component, {}).get(cs.tier, "")
        if template and not template.startswith("✓"):
            steps.append(template.format(algo=cs.algorithm))

    # Cert expiry step — prepend if urgent
    if cert_expiry_days is not None:
        if cert_expiry_days < 0:
            steps.insert(0, "IMMEDIATE: Certificate is EXPIRED. Renew immediately — asset is already untrusted.")
        elif cert_expiry_days < 30:
            steps.insert(0, f"URGENT: Certificate expires in {cert_expiry_days} days. Renew before expiry to avoid outage.")
        elif cert_expiry_days < 90:
            steps.append(f"NOTE: Certificate expires in {cert_expiry_days} days. Schedule renewal.")

    # Add warnings from classifier
    for w in warnings:
        if w.startswith("CRITICAL") or w.startswith("WARNING"):
            steps.append(w)

    return steps