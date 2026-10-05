"""Pydantic schemas for API request/response (garima's modular version)."""
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel


class BlockCreate(BaseModel):
    source: str
    command: str
    entity: str
    params: dict[str, Any] = {}


class TamperRequest(BaseModel):
    offchain_command: str
    offchain_params: dict[str, Any] = {}


class BlockOut(BaseModel):
    id: int
    ts: datetime
    source: str
    command: str
    entity: str
    params: dict[str, Any]
    prev_hash: str
    onchain_hash: str
    preimage: str
    tx_hash: Optional[str] = None
    onchain_index: Optional[int] = None
    anchor_error: Optional[str] = None
    offchain_command: str
    offchain_params: dict[str, Any]
    offchain_hash: str
    tampered: bool

    model_config = {"from_attributes": True}


class VerifyResult(BaseModel):
    chain_length: int
    chain_verified: bool
    mismatches: list[int]


class TelemetryIn(BaseModel):
    source: str = "RTU-07 Reactor"
    entity: str = "REACTOR-01"
    pressure: float
    temp: float
    vibration: float


class TelemetryEval(BaseModel):
    physics_breach: list[str]
    ml_score: float
    is_anomaly: bool


class AnomalyOut(BaseModel):
    id: int
    ts: datetime
    block_id: Optional[int]
    severity: str
    title: str
    description: str
    technique: Optional[str]
    ml_score: Optional[float]

    model_config = {"from_attributes": True}


class ForensicStep(BaseModel):
    block_id: int
    ts: datetime
    title: str
    description: str
    flag: Optional[str] = None  # "tamper" | "root" | None


class ReconstructRequest(BaseModel):
    start_block_id: int


class AttributionOut(BaseModel):
    scores: dict[str, int]
    leader: Optional[str]
    tied_with: list[str] = []


class ReconstructResult(BaseModel):
    steps: list[ForensicStep]
    attribution: AttributionOut


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    hit: bool


class MitreMatrixTacticOut(BaseModel):
    tactic: str
    techniques: list[MitreTechniqueOut]


# Supabase case schemas (preserved from simran's version)
class SaveCaseRequest(BaseModel):
    case_name: str = ""
