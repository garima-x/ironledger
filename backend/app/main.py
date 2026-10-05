"""
IronLedger Main FastAPI App
Merged version: Garima's modular routing + Simran's Supabase persistence
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .db_sql import Base, engine
from .config import settings
from .chain_blockchain import chain_status
from .routers import ledger, telemetry, forensics_router, mitre_router, reports_router, simulate_router

# Import database module for Supabase integration (from simran)
from .database import SupabaseDatabase

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="IronLedger API",
    description="Blockchain-anchored digital forensics & threat intelligence framework for ICS incident response.",
    version="0.1.0",
)

origins = ["*"] if settings.cors_origins.strip() == "*" else [o.strip() for o in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ledger.router, prefix="/api")
app.include_router(telemetry.router, prefix="/api")
app.include_router(forensics_router.router, prefix="/api")
app.include_router(mitre_router.router, prefix="/api")
app.include_router(reports_router.router, prefix="/api")
app.include_router(simulate_router.router, prefix="/api")


@app.get("/api")
def root():
    return {
        "service": "IronLedger API",
        "chain": chain_status(),
    }

# ── Supabase Case Management API (from simran's version) ──────────────────
db = SupabaseDatabase()


@app.post("/api/cases/save")
async def save_forensic_case(req: dict):
    # This acts as a bridge to persist cases to Supabase if configured
    if db.enabled:
        saved = db.save_case(
            case_name=req.get("case_name", "Untitled Case"),
            attack_scenario=req.get("attack_scenario"),
            reconstruction=req.get("reconstruction", {}),
            threat_intel=req.get("threat_intel", {}),
            telemetry_snapshot=req.get("telemetry_snapshot", {}),
        )
        return {"status": "CASE_SAVED", "case": saved}
    return {"status": "CASE_NOT_PERSISTED_DB_OFFLINE", "note": "Supabase not configured."}

@app.get("/api/cases")
async def list_cases():
    cases = db.get_all_cases()
    return {"total": len(cases), "db_connected": db.enabled, "cases": cases}

@app.get("/api/cases/{case_id}")
async def get_case(case_id: int):
    return db.get_case(case_id)

@app.get("/api/db/status")
async def db_status():
    return {"connected": db.enabled}

# ── Serve Frontend ────────────────────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
