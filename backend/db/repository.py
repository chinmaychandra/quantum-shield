# repository.py — data access layer for creating and querying scans and assets

# db/repository.py
# All database read and write operations live here.
# No raw SQL anywhere. No DB calls from any other file.
# scan_task.py calls save_scan_result() after scan completes.
# Middleware reads inventory and scan results from here.

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, update
from db.models import Base, User, ScanRecord, CBOMRecord, AuditLog
from config import settings
from datetime import datetime
import uuid

# ─── ENGINE SETUP ───────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=10,
    max_overflow=20
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# ─── TABLE CREATION ─────────────────────────────────────────
async def create_tables():
    # Call this once on startup to create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# ─── SCAN RECORD ────────────────────────────────────────────
async def create_scan_record(
    host: str,
    port: int,
    asset_type: str,
    scan_profile: str,
    requested_by: str = None
) -> str:
    # Creates a new scan record when job is submitted
    # Returns scan_id for tracking
    scan_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as session:
        record = ScanRecord(
            id=scan_id,
            host=host,
            port=port,
            asset_type=asset_type,
            scan_profile=scan_profile,
            status="QUEUED",
            requested_by=requested_by,
            created_at=datetime.utcnow()
        )
        session.add(record)
        await session.commit()

    return scan_id


async def update_scan_status(scan_id: str, status: str):
    # Updates scan status as it progresses
    # QUEUED → RUNNING → COMPLETE or FAILED
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(ScanRecord)
            .where(ScanRecord.id == scan_id)
            .values(
                status=status,
                completed_at=datetime.utcnow() if status in ["COMPLETE", "FAILED"] else None
            )
        )
        await session.commit()


# ─── CBOM RECORD ────────────────────────────────────────────
async def save_scan_result(
    scan_id: str,
    cbom: dict,
    risk_score: int,
    label: dict,
    tls_version: str = None,
    key_exchange: str = None,
    cipher: str = None,
    cert_expiry_days: int = None
):
    # Called by scan_task.py after scan completes
    # Saves full CBOM + risk score + PQC label to DB
    async with AsyncSessionLocal() as session:
        record = CBOMRecord(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            host=cbom["metadata"]["target"],
            cbom_json=cbom,
            risk_score=risk_score,
            pqc_label=label["label"],
            pqc_tier=label["tier"],
            badge_json=label,
            tls_version=tls_version,
            key_exchange=key_exchange,
            cipher=cipher,
            cert_expiry_days=cert_expiry_days,
            created_at=datetime.utcnow()
        )
        session.add(record)
        await session.commit()

    # Mark scan as complete
    await update_scan_status(scan_id, "COMPLETE")


# ─── INVENTORY READS ────────────────────────────────────────
async def get_all_inventory() -> list[CBOMRecord]:
    # Returns all scanned assets for inventory table
    # Middleware calls this for GET /inventory
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(CBOMRecord)
            .order_by(CBOMRecord.created_at.desc())
        )
        return result.scalars().all()


async def get_scan_by_id(scan_id: str) -> CBOMRecord | None:
    # Returns one asset's full CBOM by scan_id
    # Middleware calls this for GET /scan/{id}
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(CBOMRecord)
            .where(CBOMRecord.scan_id == scan_id)
        )
        return result.scalar_one_or_none()


async def get_latest_scan_by_host(host: str) -> CBOMRecord | None:
    # Returns most recent scan for a specific host
    # Used for CI/CD webhook gate check
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(CBOMRecord)
            .where(CBOMRecord.host == host)
            .order_by(CBOMRecord.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


async def get_dashboard_summary() -> dict:
    # Returns counts for dashboard summary cards
    # Total, Vulnerable, PQC Ready, Critical
    async with AsyncSessionLocal() as session:
        all_records = await session.execute(select(CBOMRecord))
        records = all_records.scalars().all()

        total = len(records)
        vulnerable = len([r for r in records if r.pqc_tier == 3])
        critical = len([r for r in records if r.pqc_tier == 4])
        pqc_ready = len([r for r in records if r.pqc_tier == 1])

        return {
            "total_assets": total,
            "vulnerable": vulnerable,
            "critical": critical,
            "pqc_ready": pqc_ready,
            "transitioning": total - vulnerable - critical - pqc_ready
        }


# ─── USER ───────────────────────────────────────────────────
async def get_user_by_email(email: str) -> User | None:
    # Used by middleware auth service for login
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()


async def create_user(
    email: str,
    password_hash: str,
    role: str = "checker"
) -> User:
    # Creates a new user (Admin only action)
    async with AsyncSessionLocal() as session:
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            password_hash=password_hash,
            role=role,
            created_at=datetime.utcnow()
        )
        session.add(user)
        await session.commit()
        return user


# ─── AUDIT LOG ──────────────────────────────────────────────
async def write_audit_log(
    action: str,
    user_id: str = None,
    target: str = None,
    result: str = "SUCCESS",
    detail: str = None
):
    # Logs every important action for compliance
    # Called from scan_task.py and middleware
    async with AsyncSessionLocal() as session:
        log = AuditLog(
            user_id=user_id,
            action=action,
            target=target,
            result=result,
            detail=detail,
            timestamp=datetime.utcnow()
        )
        session.add(log)
        await session.commit()


async def get_audit_logs(limit: int = 100) -> list[AuditLog]:
    # Returns recent audit logs for Admin view
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        return result.scalars().all()