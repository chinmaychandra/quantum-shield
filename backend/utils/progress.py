# progress.py — helper utilities for tracking and reporting scan progress

# Publishes scan progress events to Redis pub/sub channel.
# scan_task.py calls publish_progress() after every phase.
# Middleware subscribes to this channel and forwards events to frontend via WebSocket in real time.

import redis
import json
from config import settings

redis_client = redis.Redis.from_url(settings.REDIS_URL)

def publish_progress(
    scan_id: str,
    phase: str,
    percent: int,
    findings: dict = None,
):
    payload = json.dumps({
        "scan_id": scan_id,
        "phase": phase,
        "percent": percent,
        "findings": findings or {},
        "complete": percent == 100
    })

    redis_client.publish("scan:progress", payload)

class ScanPhase:
    DISCOVERY       = ("Discovery",            10)
    TLS_SCAN        = ("TLS Interrogation",     30)
    CERT_ANALYSIS   = ("Certificate Analysis",  50)
    API_PROBE       = ("API Probing",           65)
    CLASSIFICATION  = ("PQC Classification",    80)
    BUILDING_CBOM   = ("Building CBOM",         90)
    COMPLETE        = ("Complete",             100)