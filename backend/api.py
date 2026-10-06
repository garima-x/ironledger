"""
IronLedger - Core FastAPI Server & REST API
Coordinates SCADA simulation, blockchain evidence anchoring, dual-layer anomaly detection,
forensic reconstruction, threat intelligence correlation, and serves the frontend dashboard.
"""

import asyncio
import time
import os
import json
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body, Query, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.simulator import ICSSimulator
from backend.blockchain import BlockchainLedger
from backend.anomaly_detector import AnomalyDetector
from backend.forensics import ForensicReconstructionEngine
from backend.threat_intel import ThreatIntelligenceEngine
from backend.report_generator import ForensicReportGenerator
from backend.database import SupabaseDatabase

app = FastAPI(
    title="IronLedger ICS Forensic Framework",
    description="Blockchain-anchored forensic evidence and MITRE ATT&CK for ICS attribution",
    version="2.1.0"
)

# Configuration
CONFIG_API_KEY = os.environ.get("API_KEY", "")
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ["1", "true", "yes"]

# Initialize Core Services
simulator = ICSSimulator()
ledger = BlockchainLedger()
detector = AnomalyDetector()
forensics = ForensicReconstructionEngine(ledger)
threat_intel = ThreatIntelligenceEngine()
report_gen = ForensicReportGenerator()
db = SupabaseDatabase()


# ── Auth & Demo Dependencies ──────────────────────────────────────────────────

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Optional API Key protection. Active if API_KEY is defined in environment."""
    if CONFIG_API_KEY and x_api_key != CONFIG_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing X-API-Key header.")
    return True


def check_demo_mode():
    """Restricts simulation/tamper routes when DEMO_MODE is disabled in production."""
    if not DEMO_MODE:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Attack/tamper endpoints are disabled when DEMO_MODE=false."
        )
    return True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _anchor_and_persist(event: Dict[str, Any]) -> Dict[str, Any]:
    """Anchor an event on the ledger AND persist both event + block to Supabase if enabled."""
    block = ledger.anchor_event(event)
    db.upsert_event(event)
    db.upsert_block(block)
    return block


# ── Startup: restore persisted session ───────────────────────────────────────

def seed_baseline():
    """Record normal startup commands and anchor them onto the cryptographic chain."""
    cmd1 = simulator.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    _anchor_and_persist(cmd1)

    cmd2 = simulator.execute_command("AUTHORIZED_ENG_01", "SET_VALVE", "VALVE_INLET_01", {"open_percent": 75.0})
    _anchor_and_persist(cmd2)

    cmd3 = simulator.execute_command("SCADA_AUTO_PID", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 15.0})
    _anchor_and_persist(cmd3)


def startup_restore():
    """
    On startup, attempt to reload the previous session's ICS event log from Supabase.
    If the database is empty or not configured, seed a fresh baseline instead.
    """
    persisted = db.load_events()
    if persisted:
        simulator.event_log = persisted
        blocks = db.load_blocks()
        if blocks:
            ledger.chain = [ledger.genesis_block]  # keep genesis
            for blk in blocks:
                if blk.get("block_index", 0) == 0:
                    continue  # skip genesis duplicate
                ledger.chain.append(blk)
            if blocks:
                ledger.latest_sepolia_block = max(
                    b.get("block_number", ledger.latest_sepolia_block) for b in blocks
                )
            ledger._immutable_anchor_mirror = [dict(b) for b in ledger.chain]
        print(f"✅ Restored {len(persisted)} events and {len(ledger.chain)-1} blocks from Supabase.")
    else:
        print("ℹ️  No persisted session found — seeding fresh baseline.")
        seed_baseline()


startup_restore()


# ── Pydantic Models ───────────────────────────────────────────────────────────

class CommandRequest(BaseModel):
    source: str
    command_type: str
    entity_id: str
    parameters: Dict[str, Any] = {}

class AttackRequest(BaseModel):
    scenario: str  # "stuxnet", "triton", "overpressure", "log_tamper"

class TamperRequest(BaseModel):
    event_id: int
    malicious_field: str
    tampered_value: Any

class SaveCaseRequest(BaseModel):
    case_name: Optional[str] = None


# ── REST API Endpoints ────────────────────────────────────────────────────────

@app.get("/api/telemetry")
async def get_telemetry():
    """Returns real-time SCADA telemetry, physical states, anomaly evaluation, and ledger state."""
    snapshot = simulator.update_physics(dt=1.0)
    anomaly_status = detector.evaluate_telemetry(snapshot)
    
    return {
        "telemetry": snapshot,
        "anomaly": anomaly_status,
        "recent_blocks": ledger.get_recent_blocks(limit=10),
        "total_events": len(simulator.event_log),
        "total_blocks": len(ledger.chain),
        "db_connected": db.enabled,
        "blockchain_mode": "LIVE_ETHEREUM_SEPOLIA" if not ledger.is_simulated else "SIMULATED_LOCAL_LEDGER",
        "demo_mode": DEMO_MODE
    }

@app.post("/api/plant/command")
async def send_command(cmd: CommandRequest, _=Depends(verify_api_key)):
    """Dispatches an ICS command and anchors it onto the blockchain ledger."""
    event = simulator.execute_command(
        source=cmd.source,
        command_type=cmd.command_type,
        entity_id=cmd.entity_id,
        parameters=cmd.parameters
    )
    block = _anchor_and_persist(event)
    return {
        "status": "COMMAND_EXECUTED_AND_ANCHORED",
        "event": event,
        "blockchain_anchor": block,
        "persisted_to_supabase": db.enabled,
    }

@app.post("/api/attack/inject")
async def inject_attack(payload: AttackRequest, _=Depends(check_demo_mode), __=Depends(verify_api_key)):
    """Injects a standardized ICS threat scenario (Stuxnet, Triton, Overpressure, Log Tamper)."""
    scenario = payload.scenario
    meta = simulator.inject_attack(scenario)

    if scenario == "triton":
        e1 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True, "authorized": False})
        _anchor_and_persist(e1)
        e2 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 0.0})
        _anchor_and_persist(e2)

    elif scenario == "stuxnet":
        e1 = simulator.execute_command("SCADA_EXPLOIT_PAYLOAD", "SET_RPM", "PUMP_A_01", {"rpm": 3550.0})
        _anchor_and_persist(e1)

    elif scenario == "overpressure":
        e1 = simulator.execute_command("ATTACKER_SSH_TUNNEL", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 0.0})
        _anchor_and_persist(e1)
        e2 = simulator.execute_command("ATTACKER_SSH_TUNNEL", "SET_RPM", "PUMP_A_01", {"rpm": 3600.0})
        _anchor_and_persist(e2)

    elif scenario == "log_tamper":
        e1 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True, "authorized": False})
        _anchor_and_persist(e1)
        # Tamper the in-memory record and Supabase row to simulate off-chain historian modification
        e1["command_type"] = "ROUTINE_DIAGNOSTIC_PING"
        e1["parameters"] = {"test": "ok"}
        e1["source"] = "MAINTENANCE_TECH_03"
        db.tamper_event_field(e1["event_id"], "command_type", "ROUTINE_DIAGNOSTIC_PING")
        db.tamper_event_field(e1["event_id"], "source", "MAINTENANCE_TECH_03")
        db.tamper_event_field(e1["event_id"], "parameters", {"test": "ok"})

    return {
        "status": "ATTACK_INJECTED",
        "scenario": scenario,
        "metadata": meta,
        "snapshot": simulator.get_telemetry_snapshot(),
        "persisted_to_supabase": db.enabled,
    }

@app.post("/api/attack/stop")
async def stop_attack(_=Depends(check_demo_mode), __=Depends(verify_api_key)):
    """Stops attack and resets plant parameters to nominal baseline."""
    simulator.stop_attack()
    reset_event = simulator.execute_command("AUTHORIZED_ENG_01", "RESET_TRIP", "SIS_INTERLOCK_01", {})
    _anchor_and_persist(reset_event)
    return {
        "status": "ATTACK_HALTED_SYSTEM_NORMALIZED",
        "snapshot": simulator.get_telemetry_snapshot(),
    }

@app.post("/api/tamper/simulate")
async def simulate_tamper(req: TamperRequest, _=Depends(check_demo_mode), __=Depends(verify_api_key)):
    """
    Simulates malicious tampering in the local database (both in-memory + Supabase)
    to prove blockchain tamper-detection capabilities.
    """
    for ev in simulator.event_log:
        if ev.get("event_id") == req.event_id:
            original_value = ev.get(req.malicious_field)
            ev[req.malicious_field] = req.tampered_value
            db.tamper_event_field(req.event_id, req.malicious_field, req.tampered_value)
            return {
                "status": "DATABASE_RECORD_TAMPERED",
                "event_id": req.event_id,
                "field": req.malicious_field,
                "original_value": original_value,
                "tampered_value": req.tampered_value,
                "supabase_patched": db.enabled,
                "note": "Off-chain database record altered! Cryptographic hash anchor exposes deviation.",
            }
    
    raise HTTPException(status_code=404, detail=f"Event ID {req.event_id} not found in database.")

@app.get("/api/tamper/audit")
async def audit_integrity():
    """Audits entire off-chain database against on-chain blockchain hashes."""
    result = ledger.audit_entire_chain(simulator.event_log)
    return result

@app.get("/api/forensics/reconstruct")
async def reconstruct_incident():
    """Runs backward-walk forensic reconstruction from anomaly back to root cause entry point."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    recon = forensics.reconstruct_incident(simulator.event_log, anomaly_status)
    return recon

@app.get("/api/threat-intel/correlate")
async def get_threat_intel():
    """Runs MITRE ATT&CK for ICS correlation and attribution scoring."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )
    return intel

@app.get("/api/report/html", response_class=HTMLResponse)
async def get_forensic_report():
    """Generates court-ready HTML forensic incident report with cryptographic validation."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    forensic_data = forensics.reconstruct_incident(simulator.event_log, anomaly_status)
    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )

    html = report_gen.generate_html_report(
        forensic_data=forensic_data,
        threat_intel=intel,
        telemetry_snapshot=snapshot,
        contract_address=ledger.sepolia_contract_address,
        is_simulated=ledger.is_simulated
    )
    return HTMLResponse(content=html)


# ── Forensic Cases API ────────────────────────────────────────────────────────

@app.post("/api/cases/save")
async def save_forensic_case(req: SaveCaseRequest, _=Depends(verify_api_key)):
    """
    Runs a full forensic reconstruction + threat intel correlation and saves the
    result as a named forensic case in Supabase for permanent record-keeping.
    """
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    reconstruction = forensics.reconstruct_incident(simulator.event_log, anomaly_status)
    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )

    active_attack = simulator.active_attack or "baseline"
    auto_name = f"ICS-{active_attack.upper()}-{time.strftime('%Y%m%d-%H%M%S')}"
    case_name = req.case_name.strip() if req.case_name else auto_name

    saved = db.save_case(
        case_name=case_name,
        attack_scenario=simulator.active_attack,
        reconstruction=reconstruction,
        threat_intel=intel,
        telemetry_snapshot=snapshot,
    )

    if saved:
        return {
            "status": "CASE_SAVED",
            "case": saved,
            "reconstruction_summary": {
                "events_analyzed": reconstruction.get("events_analyzed"),
                "tamper_detected": reconstruction.get("tamper_detected"),
                "root_cause": reconstruction.get("root_cause_artifact"),
            },
        }
    else:
        return {
            "status": "CASE_NOT_PERSISTED_DB_OFFLINE",
            "note": "Supabase not configured. Set SUPABASE_URL and SUPABASE_KEY in .env to enable persistence.",
            "reconstruction_summary": {
                "events_analyzed": reconstruction.get("events_analyzed"),
                "tamper_detected": reconstruction.get("tamper_detected"),
                "root_cause": reconstruction.get("root_cause_artifact"),
            },
        }

@app.get("/api/cases")
async def list_cases():
    """Lists all saved forensic investigation cases from Supabase (newest first)."""
    cases = db.get_all_cases()
    return {
        "total": len(cases),
        "db_connected": db.enabled,
        "cases": cases,
    }

@app.get("/api/cases/{case_id}")
async def get_case(case_id: int):
    """Returns the full detail of a single saved forensic case."""
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return case

@app.get("/api/db/status")
async def db_status():
    """Returns the Supabase connection status and table row counts."""
    status = {
        "connected": db.enabled,
        "message": "Supabase connected and operational." if db.enabled
                   else "Supabase not configured — running in memory-only mode. Add SUPABASE_URL and SUPABASE_KEY to .env",
    }
    if db.enabled:
        cases = db.get_all_cases()
        events = db.load_events()
        status["row_counts"] = {
            "ics_events": len(events),
            "forensic_cases": len(cases),
        }
    return status


# ── Serve Frontend ────────────────────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
