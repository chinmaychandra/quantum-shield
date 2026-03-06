# models.py — ORM models for assets, scans, and CBOM entities

# db/models.py
# SQLAlchemy table definitions.
# Defines exactly what gets stored in PostgreSQL.
# repository.py uses these models for all reads and writes.
# Never write raw SQL anywhere else in the project.

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, JSON, DateTime, Text, Boolean
from datetime import datetime

class Base(DeclarativeBase):
    pass

# users       → who can log in, what role they have
class User(Base):
    __tablename__ = "users"

    id:           Mapped[str]      = mapped_column(String, primary_key=True)
    email:        Mapped[str]      = mapped_column(String, unique=True, nullable=False)
    password_hash:Mapped[str]      = mapped_column(String, nullable=False)
    role:         Mapped[str]      = mapped_column(String, default="checker")
    # role is either "admin" or "checker"
    is_active:    Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# scans       → every scan job submitted, its status
class ScanRecord(Base):
    __tablename__ = "scans"

    id:           Mapped[str]      = mapped_column(String, primary_key=True)
    host:         Mapped[str]      = mapped_column(String, nullable=False)
    port:         Mapped[int]      = mapped_column(Integer, default=443)
    asset_type:   Mapped[str]      = mapped_column(String)
    # asset_type: "API" | "WebServer" | "VPN"
    scan_profile: Mapped[str]      = mapped_column(String, default="FULL")
    # scan_profile: "QUICK" | "FULL" | "PASSIVE"
    status:       Mapped[str]      = mapped_column(String, default="QUEUED")
    # status: "QUEUED" | "RUNNING" | "COMPLETE" | "FAILED"
    requested_by: Mapped[str]      = mapped_column(String, nullable=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)


# cbom        → the actual results, risk score, PQC label, badge
class CBOMRecord(Base):
    __tablename__ = "cbom"

    id:          Mapped[str]      = mapped_column(String, primary_key=True)
    scan_id:     Mapped[str]      = mapped_column(String, nullable=False)
    host:        Mapped[str]      = mapped_column(String, nullable=False)
    cbom_json:   Mapped[dict]     = mapped_column(JSON, nullable=False)
    # full CycloneDX 1.6 CBOM stored as JSON
    risk_score:  Mapped[int]      = mapped_column(Integer, nullable=False)
    # 0-100, higher = more vulnerable
    pqc_label:   Mapped[str]      = mapped_column(String, nullable=False)
    # "Fully Quantum Safe" | "PQC Transitioning" |
    # "Quantum Vulnerable" | "Immediately Remediate"
    pqc_tier:    Mapped[int]      = mapped_column(Integer, nullable=False)
    # 1 | 2 | 3 | 4
    badge_json:  Mapped[dict]     = mapped_column(JSON, nullable=True)
    # signed PQC badge artifact
    tls_version: Mapped[str]      = mapped_column(String, nullable=True)
    key_exchange:Mapped[str]      = mapped_column(String, nullable=True)
    cipher:      Mapped[str]      = mapped_column(String, nullable=True)
    cert_expiry_days: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at:  Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# audit_log   → every action anyone takes, for compliance
class AuditLog(Base):
    __tablename__ = "audit_log"

    id:        Mapped[int]      = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id:   Mapped[str]      = mapped_column(String, nullable=True)
    action:    Mapped[str]      = mapped_column(String, nullable=False)
    # e.g. "SCAN_SUBMITTED", "LOGIN", "REPORT_DOWNLOADED"
    target:    Mapped[str]      = mapped_column(String, nullable=True)
    # the host that was scanned or acted on
    result:    Mapped[str]      = mapped_column(String, nullable=True)
    # "SUCCESS" | "FAILED"
    detail:    Mapped[str]      = mapped_column(Text, nullable=True)
    # any extra info worth logging
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)