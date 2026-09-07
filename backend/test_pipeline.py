"""
IronLedger - Automated Pipeline & Verification Test Suite
Verifies SCADA physics, ML anomaly detector, blockchain hashing, tamper-detection,
backward-walk forensic reconstruction, and MITRE ATT&CK attribution.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.simulator import ICSSimulator
from backend.blockchain import BlockchainLedger
from backend.anomaly_detector import AnomalyDetector
from backend.forensics import ForensicReconstructionEngine
from backend.threat_intel import ThreatIntelligenceEngine
from backend.report_generator import ForensicReportGenerator

def test_full_pipeline():
    print("========================================")
    print("Testing IronLedger End-to-End Pipeline...")
    print("========================================")

    # 1. Test Simulator
    sim = ICSSimulator()
    t0 = sim.get_telemetry_snapshot()
    assert t0["pump_a"]["rpm"] == 2400.0, "Initial pump RPM incorrect"
    assert t0["sis"]["armed"] == True, "SIS must be armed initially"
    print(" [✓] Simulator initialized nominal state")

    # 2. Test Anomaly Detector on Baseline
    detector = AnomalyDetector()
    eval_norm = detector.evaluate_telemetry(t0)
    assert not eval_norm["is_anomaly"], f"Baseline flagged false positive: {eval_norm}"
    print(f" [✓] Baseline anomaly detection passed (ML score: {eval_norm['ml_anomaly_score']})")

    # 3. Test Blockchain Ledger & Anchoring
    ledger = BlockchainLedger()
    cmd1 = sim.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    b1 = ledger.anchor_event(cmd1)
    assert b1["event_hash"].startswith("0x"), "Invalid event hash format"
    assert len(ledger.chain) == 2, "Ledger must contain genesis + 1 block"
    print(f" [✓] Event anchored onto blockchain: {b1['event_hash'][:16]}... (Block #{b1['block_number']})")

    # 4. Test Attack Injection & Anomaly Detection
    sim.inject_attack("triton")
    # Simulate a few physics ticks
    for _ in range(5):
        sim.update_physics(dt=1.0)
    t_attack = sim.get_telemetry_snapshot()
    eval_attack = detector.evaluate_telemetry(t_attack)
    assert eval_attack["is_anomaly"], "Anomaly detector failed to trigger during attack!"
    assert eval_attack["severity"] in ["CRITICAL", "CATASTROPHIC", "WARNING"], "Unexpected severity"
    print(f" [✓] Triton attack detected: Severity {eval_attack['severity']} (Violations: {len(eval_attack['rule_violations'])})")

    # Anchor attack commands
    cmd_attack = sim.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True})
    ledger.anchor_event(cmd_attack)

    # 5. Test Tamper Detection
    audit_pre = ledger.audit_entire_chain(sim.event_log)
    assert audit_pre["integrity_healthy"], "Chain should be healthy prior to tamper"
    
    # Tamper with local DB record
    sim.event_log[0]["command_type"] = "MALICIOUS_TAMPER_MODIFIED"
    audit_post = ledger.audit_entire_chain(sim.event_log)
    assert not audit_post["integrity_healthy"], "Tamper detection failed to catch altered DB record!"
    assert audit_post["tampered_blocks_found"] == 1, "Expected exactly 1 tampered block"
    print(f" [✓] Blockchain tamper detection verified! Tampered block exposed by hash mismatch.")

    # 6. Test Forensic Reconstruction & Backward Walk
    forensics = ForensicReconstructionEngine(ledger)
    recon = forensics.reconstruct_incident(sim.event_log, eval_attack)
    assert recon["success"], "Reconstruction failed"
    assert recon["tamper_detected"], "Reconstruction must reflect tamper status"
    assert recon["root_cause_artifact"] is not None, "Root cause not identified"
    print(f" [✓] Backward-walk completed: Identified root cause entry [{recon['root_cause_artifact']['source_identity']}]")

    # 7. Test Threat Intel & MITRE ATT&CK for ICS Attribution
    threat_intel = ThreatIntelligenceEngine()
    intel = threat_intel.correlate_incident(sim.event_log, eval_attack, tampered_detected=True)
    assert len(intel["matched_techniques"]) > 0, "No MITRE techniques matched"
    hypothesis = intel["primary_hypothesis"]
    assert hypothesis is not None, "Attribution hypothesis missing"
    print(f" [✓] MITRE ATT&CK ICS correlation: Primary hypothesis '{hypothesis['name']}' with {hypothesis['confidence_score']}% confidence")

    # 8. Test Report Generator
    report_gen = ForensicReportGenerator()
    html = report_gen.generate_html_report(recon, intel, t_attack, ledger.sepolia_contract_address)
    assert "IRON<span>LEDGER</span> FORENSIC REPORT" in html, "Report HTML missing title"
    assert "TAMPER DETECTED" in html, "Report HTML missing tamper banner"
    print(f" [✓] Forensic Report generated successfully ({len(html)} bytes)")

    print("\n========================================")
    print("ALL 8 VERIFICATION TESTS PASSED PERFECTLY!")
    print("========================================")

if __name__ == "__main__":
    test_full_pipeline()
