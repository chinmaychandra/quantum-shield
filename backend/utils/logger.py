# logger.py — shared logging setup for backend components

# Structured logging for every scan event
# Writes to console and file for audit trail

import logging
import asyncio
from db.repository import write_audit_log

# ─── CONSOLE LOGGER ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("quantum_scanner")

# ─── AUDIT LOGGER ───────────────────────────────────────────
def log_event(
    action: str,
    user_id: str = None,
    target: str = None,
    result: str = "SUCCESS",
    detail: str = None
):
    # Logs to console immediately
    logger.info(f"[{action}] user={user_id} target={target} result={result}")

    # Logs to DB asynchronously
    # Using asyncio.create_task so it doesn't block the scanner
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(
                write_audit_log(
                    action=action,
                    user_id=user_id,
                    target=target,
                    result=result,
                    detail=detail
                )
            )
    except Exception as e:
        # Never let logging break the scan
        logger.error(f"Audit log write failed: {e}")

# core logging shortcuts
def log_scan_started(scan_id: str, host: str):
    log_event("SCAN_STARTED", target=host, detail=f"scan_id={scan_id}")

def log_scan_complete(scan_id: str, host: str, label: str, score: int):
    log_event("SCAN_COMPLETE", target=host, detail=f"scan_id={scan_id} label={label} score={score}")

def log_scan_failed(scan_id: str, host: str, error: str):
    log_event("SCAN_FAILED", target=host, result="FAILED", detail=f"scan_id={scan_id} error={error}")