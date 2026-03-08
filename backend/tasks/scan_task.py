# wires the entire backend pipeline into one Celery task.

# Full pipeline (in order):
#   Phase 1 → Discovery      (scanner/discovery.py)
#   Phase 2 → TLS Scan       (scanner/tls_scanner.py)
#   Phase 3 → Cert Parse     (scanner/cert_parser.py)
#   Phase 4 → API Probe      (scanner/api_prober.py)
#   Phase 5 → PQC Classify   (classifier/pqc_classifier.py)
#   Phase 6 → Risk Score     (classifier/risk_scorer.py)
#   Phase 7 → Build CBOM     (cbom/cbom_builder.py)
#   Phase 8 → Issue Badge    (cbom/label_issuer.py)
#   Phase 9 → Persist to DB  (db/repository.py)
#
# Progress published to Redis pub/sub after every phase and WebSocket manager can push live updates to frontend.


import traceback
from datetime import datetime, timezone

from celery  import Task
from worker  import celery_app
from config  import settings

# Scanner Imports
from scanner.discovery   import discover
from scanner.tls_scanner import scan_tls
from scanner.cert_parser import parse_cert_chain
from scanner.api_prober  import probe_api

# Classifier Imports
from classifier.pqc_classifier import classify
from classifier.risk_scorer    import compute_risk_score

# CBOM Imports
from cbom.cbom_builder  import build_cbom
from cbom.label_issuer  import issue_badge, revoke_badge, check_regression

# Db imports
from db.repository import (
    update_scan_status,
    update_scan_phase,
    save_cbom_record,
    get_latest_badge_by_host,
)

# Utils
from utils.progress import publish_progress
from utils.logger   import get_logger

logger = get_logger(__name__)

# Published to Redis so frontend progress bar knows exact phase
PHASES = {
    1: "DISCOVERY",
    2: "TLS_SCAN",
    3: "CERT_PARSE",
    4: "API_PROBE",
    5: "PQC_CLASSIFY",
    6: "RISK_SCORE",
    7: "BUILD_CBOM",
    8: "ISSUE_BADGE",
    9: "PERSIST",
}

PHASE_LABELS = {
    1: "Discovering assets via DNS + CT logs",
    2: "Interrogating TLS — enumerating cipher suites",
    3: "Parsing certificate chain",
    4: "Probing API security headers & auth",
    5: "Classifying algorithms against NIST PQC standards",
    6: "Computing HNDL risk score",
    7: "Building CycloneDX 1.6 CBOM",
    8: "Issuing signed PQC readiness badge",
    9: "Persisting results to database",
}


@celery_app.task(
    bind=True,
    name="tasks.scan_task.run_scan",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,        # only ack after task completes — no lost scans
    track_started=True,
)
def run_scan(self: Task, scan_id: str, host: str, user_id: int) -> dict:
    """
    Main Celery task — runs the full scan pipeline for a single host.

    Args:
        scan_id:  UUID string — matches ScanRecord.id in DB
        host:     target hostname e.g. "netbanking.pnb.co.in"
        user_id:  ID of the user who triggered the scan

    Returns:
        dict with scan summary — stored as Celery task result
    """
    logger.info(f"[scan_task] START scan_id={scan_id} host={host} user={user_id}")

    #Marked running in DB
    update_scan_status(scan_id, "RUNNING")

    discovery   = None
    tls_result  = None
    cert_chain  = []
    api_result  = None

    try:
        # Phase : 1
        _phase_start(scan_id, 1)
        try:
            discovery = discover(host)
            logger.info(f"[scan_task] P1 done — {len(discovery.ip_addresses)} IPs, "
                        f"{len(discovery.subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[scan_task] P1 discovery failed: {e} — continuing")
            # Discovery failure is non-fatal — we can still scan the base host
        _phase_done(scan_id, 1)

        # Phase : 2
        _phase_start(scan_id, 2)
        try:
            tls_result = scan_tls(host)
            logger.info(f"[scan_task] P2 done — "
                        f"best={tls_result.best_version} "
                        f"ciphers={len(tls_result.supported_ciphers or [])}")
        except Exception as e:
            logger.error(f"[scan_task] P2 TLS scan failed: {e}")
            _fail_scan(scan_id, "TLS_SCAN_FAILED", str(e))
            raise   # TLS failure IS fatal — no point continuing
        _phase_done(scan_id, 2)

        # Phase : 3
        _phase_start(scan_id, 3)
        try:
            raw_chain  = tls_result.certificate_chain_raw or []
            cert_chain = parse_cert_chain(raw_chain) if raw_chain else []
            logger.info(f"[scan_task] P3 done — {len(cert_chain)} certs parsed")
        except Exception as e:
            logger.warning(f"[scan_task] P3 cert parse failed: {e} — continuing")
            cert_chain = []
        _phase_done(scan_id, 3)

        # Phase : 4
        _phase_start(scan_id, 4)
        try:
            api_result = probe_api(host)
            logger.info(f"[scan_task] P4 done — "
                        f"auth={api_result.auth_mechanism} "
                        f"hsts={api_result.hsts_present}")
        except Exception as e:
            logger.warning(f"[scan_task] P4 API probe failed: {e} — continuing")
            api_result = None
        _phase_done(scan_id, 4)

        # Phase : 5
        _phase_start(scan_id, 5)
        classification = classify(
            host       = host,
            tls_result = tls_result,
            cert_chain = cert_chain,
            api_result = api_result,
        )
        logger.info(f"[scan_task] P5 done — "
                    f"tier={classification.worst_tier} "
                    f"({classification.worst_tier_label})")
        _phase_done(scan_id, 5)

        # Phase : 6
        _phase_start(scan_id, 6)
        # Pull cert expiry days from leaf cert
        leaf_certs       = [c for c in cert_chain if c.is_leaf]
        cert_expiry_days = leaf_certs[0].days_to_expiry if leaf_certs else None

        risk_score = compute_risk_score(
            classification   = classification,
            cert_expiry_days = cert_expiry_days,
        )
        logger.info(f"[scan_task] P6 done — "
                    f"score={risk_score.final_score} "
                    f"label={risk_score.label}")
        _phase_done(scan_id, 6)

        # Phase : 7
        _phase_start(scan_id, 7)
        cbom = build_cbom(
            host           = host,
            discovery      = discovery,
            tls_result     = tls_result,
            cert_chain     = cert_chain,
            api_result     = api_result,
            classification = classification,
            risk_score     = risk_score,
            scan_id        = scan_id,
        )
        logger.info(f"[scan_task] P7 done — "
                    f"components={len(cbom.get('components', []))} "
                    f"vulns={len(cbom.get('vulnerabilities', []))}")
        _phase_done(scan_id, 7)

       # Phase : 8
        _phase_start(scan_id, 8)

        # Check if a previous badge exists — revoke if tier regressed
        existing_badge = get_latest_badge_by_host(host)
        is_regression, regression_reason = check_regression(
            existing_badge_json = existing_badge,
            new_classification  = classification,
        )

        if is_regression and existing_badge:
            logger.warning(f"[scan_task] Tier regression detected for {host} — "
                           f"revoking old badge")
            revoke_badge(existing_badge, regression_reason)
            # Save revoked badge back to DB
            # (repository handles upsert by host + fingerprint)
            save_cbom_record(
                scan_id    = scan_id,
                host       = host,
                cbom_json  = cbom,
                badge_json = existing_badge,
                risk_score = risk_score.final_score,
                risk_label = risk_score.label,
                pqc_tier   = classification.worst_tier,
                revoked    = True,
            )

        # Always issue a fresh badge for this scan
        badge = issue_badge(
            classification = classification,
            risk_score     = risk_score,
        )
        logger.info(f"[scan_task] P8 done — badge={badge.pqc_label} "
                    f"fingerprint={badge.fingerprint[:16]}...")
        _phase_done(scan_id, 8)

        # Phase : 9
        _phase_start(scan_id, 9)
        save_cbom_record(
            scan_id    = scan_id,
            host       = host,
            cbom_json  = cbom,
            badge_json = badge.to_dict(),
            risk_score = risk_score.final_score,
            risk_label = risk_score.label,
            pqc_tier   = classification.worst_tier,
            revoked    = False,
        )
        update_scan_status(scan_id, "COMPLETED")
        _phase_done(scan_id, 9)

        # ── Build final summary ──────────────────────────────
        summary = _build_summary(
            scan_id        = scan_id,
            host           = host,
            classification = classification,
            risk_score     = risk_score,
            badge          = badge,
            cert_chain     = cert_chain,
            is_regression  = is_regression,
        )

    
        publish_progress(scan_id, {
            "event":   "scan:complete",
            "scan_id": scan_id,
            "summary": summary,
        })

        logger.info(
            f"[scan_task] COMPLETE scan_id={scan_id} host={host} "
            f"tier={classification.worst_tier} score={risk_score.final_score} "
            f"label={risk_score.label}"
        )

        return summary

    except Exception as e:
        logger.error(
            f"[scan_task] FAILED scan_id={scan_id} host={host} "
            f"error={str(e)}\n{traceback.format_exc()}"
        )
        _fail_scan(scan_id, "UNEXPECTED_ERROR", str(e))
        raise self.retry(exc=e)

def _phase_start(scan_id: str, phase_num: int):
    """Publish phase start to Redis + update DB phase."""
    label = PHASE_LABELS[phase_num]
    name  = PHASES[phase_num]

    publish_progress(scan_id, {
        "event":       "scan:progress",
        "scan_id":     scan_id,
        "phase":       phase_num,
        "phase_name":  name,
        "phase_label": label,
        "total_phases": len(PHASES),
        "status":      "RUNNING",
        "percent":     int(((phase_num - 1) / len(PHASES)) * 100),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    })
    update_scan_phase(scan_id, name)
    logger.debug(f"[scan_task] Phase {phase_num} START — {label}")


def _phase_done(scan_id: str, phase_num: int):
    """Publish phase completion to Redis."""
    publish_progress(scan_id, {
        "event":       "scan:progress",
        "scan_id":     scan_id,
        "phase":       phase_num,
        "phase_name":  PHASES[phase_num],
        "phase_label": PHASE_LABELS[phase_num],
        "total_phases": len(PHASES),
        "status":      "DONE",
        "percent":     int((phase_num / len(PHASES)) * 100),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    })
    logger.debug(f"[scan_task] Phase {phase_num} DONE — {PHASES[phase_num]}")


def _fail_scan(scan_id: str, error_code: str, error_detail: str):
    """Mark scan as FAILED in DB and publish failure event."""
    update_scan_status(scan_id, "FAILED")
    publish_progress(scan_id, {
        "event":        "scan:failed",
        "scan_id":      scan_id,
        "error_code":   error_code,
        "error_detail": error_detail,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    })

def _build_summary(
    scan_id:        str,
    host:           str,
    classification,
    risk_score,
    badge,
    cert_chain:     list,
    is_regression:  bool,
) -> dict:
    """
    Builds the final summary dict returned by the Celery task
    and sent to Shivang's WebSocket on scan:complete event.
    """
    leaf_certs = [c for c in cert_chain if c.is_leaf]

    return {
        # Core identifiers
        "scan_id":     scan_id,
        "host":        host,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),

        # PQC classification
        "pqc_tier":       classification.worst_tier,
        "pqc_label":      classification.worst_tier_label,
        "dominant_risk":  risk_score.dominant_risk,

        # Risk score
        "risk_score":     risk_score.final_score,
        "risk_label":     risk_score.label,
        "risk_breakdown": [
            {
                "component": c.component,
                "algorithm": c.algorithm,
                "tier":      c.tier,
                "weighted":  round(c.weighted, 2),
            }
            for c in risk_score.breakdown
        ],

        # Badge
        "badge_label":       badge.pqc_label,
        "badge_color":       badge.badge_color,
        "badge_fingerprint": badge.fingerprint,
        "badge_expires_at":  badge.expires_at,
        "badge_status":      badge.status,
        "is_regression":     is_regression,

        # Certificate summary
        "cert_subject":      leaf_certs[0].subject       if leaf_certs else None,
        "cert_expiry_days":  leaf_certs[0].days_to_expiry if leaf_certs else None,
        "cert_is_expired":   leaf_certs[0].is_expired     if leaf_certs else None,
        "cert_sig_algo":     leaf_certs[0].signature_algorithm if leaf_certs else None,

        # Remediation
        "remediation_steps": risk_score.remediation_priority,

        # Warnings
        "warnings": classification.warnings,
    }