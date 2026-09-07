"""
IronLedger - Core FastAPI Server & WebSocket / REST API
Coordinates SCADA simulation, blockchain evidence anchoring, dual-layer anomaly detection,
forensic reconstruction, threat intelligence correlation, and serves the frontend dashboard.
"""

import asyncio
import time
import os
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.simulator import ICSSimulator
from backend.blockchain import BlockchainLedger
from backend.anomaly_detector import AnomalyDetector
from backend.forensics import ForensicReconstructionEngine
from backend.threat_intel import ThreatIntelligenceEngine
from backend.report_generator import ForensicReportGenerator

app = FastAPI(
    title="IronLedger ICS Forensic Framework",
    description="Blockchain-anchored forensic evidence and MITRE ATT&CK for ICS attribution",
    version="1.0.0"
)

# Initialize Core Services
simulator = ICSSimulator()
ledger = BlockchainLedger()
detector = AnomalyDetector()
forensics = ForensicReconstructionEngine(ledger)
threat_intel = ThreatIntelligenceEngine()
report_gen = ForensicReportGenerator()

# Seed Baseline History
def seed_baseline():
    # Record normal startup commands and anchor them
    cmd1 = simulator.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    ledger.anchor_event(cmd1)

    cmd2 = simulator.execute_command("AUTHORIZED_ENG_01", "SET_VALVE", "VALVE_INLET_01", {"open_percent": 75.0})
    ledger.anchor_event(cmd2)

    cmd3 = simulator.execute_command("SCADA_AUTO_PID", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 15.0})
    ledger.anchor_event(cmd3)

seed_baseline()

# Models
class CommandRequest(BaseModel):
    source: str
    command_type: str
    entity_id: str
    parameters: Dict[str, Any] = {}

class AttackRequest(BaseModel):
    scenario: str # "stuxnet", "triton", "overpressure", "log_tamper"

class TamperRequest(BaseModel):
    event_id: int
    malicious_field: str
    tampered_value: Any

# REST API Endpoints

@app.get("/api/telemetry")
async def get_telemetry():
    """Returns real-time SCADA telemetry, physical states, and anomaly evaluation."""
    snapshot = simulator.update_physics(dt=1.0)
    anomaly_status = detector.evaluate_telemetry(snapshot)
    
    return {
        "telemetry": snapshot,
        "anomaly": anomaly_status,
        "recent_blocks": ledger.get_recent_blocks(limit=10),
        "total_events": len(simulator.event_log),
        "total_blocks": len(ledger.chain)
    }

@app.post("/api/plant/command")
async def send_command(cmd: CommandRequest):
    """Dispatches an ICS command and anchors it onto the blockchain ledger."""
    event = simulator.execute_command(
        source=cmd.source,
        command_type=cmd.command_type,
        entity_id=cmd.entity_id,
        parameters=cmd.parameters
    )
    block = ledger.anchor_event(event)
    return {
        "status": "COMMAND_EXECUTED_AND_ANCHORED",
        "event": event,
        "blockchain_anchor": block
    }

@app.post("/api/attack/inject")
async def inject_attack(payload: AttackRequest):
    """Injects a standardized ICS threat scenario (Stuxnet, Triton, Overpressure, Log Tamper)."""
    scenario = payload.scenario
    meta = simulator.inject_attack(scenario)

    # In ICS attacks, rogue commands are dispatched through unauthorized channels
    if scenario == "triton":
        # Adversary disables SIS and closes vent valve
        e1 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True})
        ledger.anchor_event(e1)
        e2 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 0.0})
        ledger.anchor_event(e2)

    elif scenario == "stuxnet":
        # Rapid cycling commands
        e1 = simulator.execute_command("SCADA_EXPLOIT_PAYLOAD", "SET_RPM", "PUMP_A_01", {"rpm": 3550.0})
        ledger.anchor_event(e1)

    elif scenario == "overpressure":
        e1 = simulator.execute_command("ATTACKER_SSH_TUNNEL", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 0.0})
        ledger.anchor_event(e1)
        e2 = simulator.execute_command("ATTACKER_SSH_TUNNEL", "SET_RPM", "PUMP_A_01", {"rpm": 3600.0})
        ledger.anchor_event(e2)

    elif scenario == "log_tamper":
        # First inject malicious command
        e1 = simulator.execute_command("EXPLOIT_PAYLOAD", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True})
        ledger.anchor_event(e1)
        # Then deliberately modify local DB record to hide it!
        e1["command_type"] = "ROUTINE_DIAGNOSTIC_PING"
        e1["parameters"] = {"test": "ok"}
        e1["source"] = "MAINTENANCE_TECH_03"

    return {
        "status": "ATTACK_INJECTED",
        "scenario": scenario,
        "metadata": meta,
        "snapshot": simulator.get_telemetry_snapshot()
    }

@app.post("/api/attack/stop")
async def stop_attack():
    """Stops attack and resets plant parameters to nominal baseline."""
    simulator.stop_attack()
    reset_event = simulator.execute_command("AUTHORIZED_ENG_01", "RESET_TRIP", "SIS_INTERLOCK_01", {})
    ledger.anchor_event(reset_event)
    return {
        "status": "ATTACK_HALTED_SYSTEM_NORMALIZED",
        "snapshot": simulator.get_telemetry_snapshot()
    }

@app.post("/api/tamper/simulate")
async def simulate_tamper(req: TamperRequest):
    """
    Simulates malicious tampering in the local database (e.g. Supabase record alteration)
    to prove blockchain tamper-detection capabilities.
    """
    found = False
    for ev in simulator.event_log:
        if ev.get("event_id") == req.event_id:
            found = True
            original_value = ev.get(req.malicious_field)
            ev[req.malicious_field] = req.tampered_value
            return {
                "status": "DATABASE_RECORD_TAMPERED",
                "event_id": req.event_id,
                "field": req.malicious_field,
                "original_value": original_value,
                "tampered_value": req.tampered_value,
                "note": "Off-chain database record altered! Blockchain hash on Sepolia remains immutable."
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
        contract_address=ledger.sepolia_contract_address
    )
    return HTMLResponse(content=html)

# Serve Frontend static directory
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
