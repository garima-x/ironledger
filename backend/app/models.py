"""SQLAlchemy ORM models (from garima's modular backend)."""
import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime
from .db_sql import Base


class LedgerBlock(Base):
    __tablename__ = "ledger_blocks"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=datetime.utcnow)
    source = Column(String, nullable=False)
    command = Column(String, nullable=False)
    entity = Column(String, nullable=False)
    params_json = Column(Text, nullable=False, default="{}")
    prev_hash = Column(String(64), nullable=False)
    onchain_hash = Column(String(64), nullable=False, unique=True, index=True)
    preimage = Column(Text, nullable=False)
    tx_hash = Column(String, nullable=True)
    onchain_index = Column(Integer, nullable=True)
    anchor_error = Column(Text, nullable=True)
    # Off-chain mutable fields — tampering changes these while onchain_hash stays fixed
    offchain_command = Column(String, nullable=False)
    offchain_params_json = Column(Text, nullable=False, default="{}")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=datetime.utcnow)
    block_id = Column(Integer, nullable=True)
    severity = Column(String, nullable=False)  # critical | warning
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    technique = Column(String, nullable=True)  # MITRE ATT&CK for ICS technique id
    ml_score = Column(Float, nullable=True)
