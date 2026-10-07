import os
import sys
import time
import copy

try:
    import pytest
except ImportError:
    pytest = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.blockchain import BlockchainLedger
from backend.simulator import ICSSimulator
from backend.anomaly_detector import AnomalyDetector
from backend.forensics import ForensicReconstructionEngine
from backend.threat_intel import ThreatIntelligenceEngine


pytest_fixture = pytest.fixture if pytest else (lambda fn: fn)

@pytest_fixture
def ledger():
    return BlockchainLedger()


@pytest_fixture
def simulator():
    sim = ICSSimulator()
    sim.reset_state()
    return sim


@pytest_fixture
def anomaly_detector():
    return AnomalyDetector()


def test_canonical_hashing_determinism(ledger):
    """Verifies that hashing is strictly deterministic regardless of dictionary key ordering."""
    event_a = {
        "event_id": 1,
        "timestamp": 1700000000.1234,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "START",
        "entity_id": "PUMP_A_01",
        "parameters": {"rpm": 2400.0, "mode": "AUTO"},
        "plant_state_snapshot": {"pressure": 5.4, "temp": 68.5}
    }
    event_b = {
        "plant_state_snapshot": {"temp": 68.5, "pressure": 5.4},
        "parameters": {"mode": "AUTO", "rpm": 2400.0},
        "entity_id": "PUMP_A_01",
        "command_type": "START",
        "source": "AUTHORIZED_ENG_01",
        "timestamp": 1700000000.1234,
        "event_id": 1
    }
    prev_hash = ledger.genesis_block["event_hash"]
    hash_a = ledger.compute_event_hash(event_a, prev_hash)
    hash_b = ledger.compute_event_hash(event_b, prev_hash)
    assert hash_a == hash_b
    assert hash_a.startswith("0x")


def test_timestamp_tampering_detection(ledger):
    """Ensures that altering the event timestamp triggers a cryptographic hash mismatch."""
    event = {
        "event_id": 1,
        "timestamp": 1700000000.0,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "START",
        "entity_id": "PUMP_A_01",
        "parameters": {"rpm": 2400.0},
        "plant_state_snapshot": {"pressure": 5.4}
    }
    block = ledger.anchor_event(event)
    
    # Tamper the timestamp in the database event
    tampered_event = copy.deepcopy(event)
    tampered_event["timestamp"] = 1700000500.0  # shifted by 500s

    audit = ledger.audit_entire_chain([tampered_event])
    assert not audit["integrity_healthy"]
    assert audit["tampered_blocks_found"] == 1
    assert audit["audit_details"][0]["reason"] == "HASH_MISMATCH"


def test_snapshot_tampering_detection(ledger):
    """Ensures that altering telemetry state snapshot triggers a hash mismatch."""
    event = {
        "event_id": 1,
        "timestamp": 1700000000.0,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "SET_VALVE",
        "entity_id": "VALVE_VENT_02",
        "parameters": {"open_percent": 15.0},
        "plant_state_snapshot": {"pressure_vessel": {"pressure_bar": 5.4}}
    }
    ledger.anchor_event(event)

    # Tamper the snapshot data in the database
    tampered_event = copy.deepcopy(event)
    tampered_event["plant_state_snapshot"]["pressure_vessel"]["pressure_bar"] = 9.8

    audit = ledger.audit_entire_chain([tampered_event])
    assert not audit["integrity_healthy"]
    assert audit["tampered_blocks_found"] == 1
    assert audit["audit_details"][0]["reason"] == "HASH_MISMATCH"


def test_broken_chain_link_detection(ledger):
    """Verifies that an adversary tampering with previous_hash links is flagged as BROKEN_CHAIN_LINK."""
    e1 = {"event_id": 1, "timestamp": 1700000001.0, "source": "A", "command_type": "C1", "entity_id": "E1"}
    e2 = {"event_id": 2, "timestamp": 1700000002.0, "source": "B", "command_type": "C2", "entity_id": "E2"}
    ledger.anchor_event(e1)
    ledger.anchor_event(e2)

    # Maliciously re-link block 2's previous_hash
    ledger.chain[2]["previous_hash"] = "0x" + "f" * 64

    audit = ledger.audit_entire_chain([e1, e2])
    assert not audit["integrity_healthy"]
    reasons = [d["reason"] for d in audit["audit_details"] if d.get("tampered")]
    assert "BROKEN_CHAIN_LINK" in reasons


def test_unanchored_db_record_detection(ledger):
    """Verifies that extra forged records inserted into the off-chain database are caught."""
    e1 = {"event_id": 1, "timestamp": 1700000001.0, "source": "A", "command_type": "C1", "entity_id": "E1"}
    ledger.anchor_event(e1)

    e_forged = {"event_id": 999, "timestamp": 1700000002.0, "source": "ATTACKER", "command_type": "INJECT", "entity_id": "VALVE"}
    
    audit = ledger.audit_entire_chain([e1, e_forged])
    assert not audit["integrity_healthy"]
    unanchored = [d for d in audit["audit_details"] if d.get("reason") == "UNANCHORED_DB_RECORD"]
    assert len(unanchored) == 1
    assert unanchored[0]["event_id"] == 999


def test_deleted_record_detection(ledger):
    """Verifies that purged/deleted database records are caught."""
    e1 = {"event_id": 1, "timestamp": 1700000001.0, "source": "A", "command_type": "C1", "entity_id": "E1"}
    e2 = {"event_id": 2, "timestamp": 1700000002.0, "source": "B", "command_type": "C2", "entity_id": "E2"}
    ledger.anchor_event(e1)
    ledger.anchor_event(e2)

    # Attacker deletes e1 from database
    audit = ledger.audit_entire_chain([e2])
    assert not audit["integrity_healthy"]
    deleted = [d for d in audit["audit_details"] if d.get("reason") == "AUDIT_RECORD_DELETED_FROM_DB"]
    assert len(deleted) == 1
    assert deleted[0]["event_id"] == 1


def test_forensic_backward_walk_and_policy(ledger, simulator):
    """Verifies evidence-based backward-walk identifying unauthorized policy violations."""
    forensics = ForensicReconstructionEngine(ledger)
    
    # 1. Normal baseline commands
    c1 = simulator.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    ledger.anchor_event(c1)
    c2 = simulator.execute_command("SCADA_AUTO_PID", "SET_VALVE", "VALVE_INLET_01", {"open_percent": 75.0})
    ledger.anchor_event(c2)

    # 2. Rogue command violating policy
    c3 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True, "authorized": False})
    ledger.anchor_event(c3)

    recon = forensics.reconstruct_incident(simulator.event_log)
    assert recon["success"]
    assert recon["events_analyzed"] == 3
    assert recon["root_cause_artifact"]["source_identity"] == "ROGUE_OPERATOR_0x7b"
    assert recon["root_cause_artifact"]["policy_violation"] is True


def test_threat_intel_objective_scoring():
    """Verifies objective technique overlap scoring and attribution ranking."""
    engine = ThreatIntelligenceEngine()
    
    # Command history matching TRITON signature (T0888 Loss of Safety, T0831 Manipulation of Control, T0855 Unauthorized Command)
    history = [
        {"command_type": "OVERRIDE_SIS", "source": "ROGUE_01", "parameters": {"bypass": True}},
        {"command_type": "SET_VALVE", "source": "ROGUE_01", "parameters": {"open_percent": 0.0}}
    ]
    anomaly = {"severity": "CRITICAL"}
    
    intel = engine.correlate_incident(history, anomaly, tampered_detected=False)
    assert len(intel["matched_techniques"]) >= 3
    assert intel["primary_hypothesis"] is not None
    assert intel["primary_hypothesis"]["actor_id"] == "XENOTIME"
    assert intel["primary_hypothesis"]["confidence_score"] > 50.0
    assert "attribution_caveat" in intel


def test_anomaly_detector_physics_and_ml(anomaly_detector, simulator):
    """Verifies physics envelope safety breaches and Isolation Forest scoring."""
    nominal_snap = simulator.get_telemetry_snapshot()
    nominal_eval = anomaly_detector.evaluate_telemetry(nominal_snap)
    assert nominal_eval["severity"] == "NORMAL"
    assert nominal_eval["ml_anomaly_score"] < 0.65

    # Trigger overpressure breach
    simulator.pressure_vessel["pressure_bar"] = 10.5
    breach_snap = simulator.get_telemetry_snapshot()
    breach_eval = anomaly_detector.evaluate_telemetry(breach_snap)
    assert breach_eval["is_anomaly"] is True
    assert breach_eval["severity"] == "CATASTROPHIC"
    assert "PRESSURE_VESSEL_PRESSURE" in breach_eval["flagged_sensors"]


def test_forensic_tamper_parameter_verification():
    """Verifies tamper detection and authentic parameter recovery via block hash validation."""
    import copy
    
    # a) SET_RPM rpm=5000, then tamper DB parameters to {"rpm":2400}
    l_a = BlockchainLedger()
    s_a = ICSSimulator()
    f_a = ForensicReconstructionEngine(l_a)
    c_a = s_a.execute_command("AUTHORIZED_ENG_01", "SET_RPM", "PUMP_A_01", {"rpm": 5000.0})
    l_a.anchor_event(c_a)
    db_ev_a = copy.deepcopy(c_a)
    db_ev_a["parameters"] = {"rpm": 2400.0}

    recon_a = f_a.reconstruct_incident([db_ev_a])
    step_a = recon_a["timeline"][0]
    assert step_a["policy_violation"] is True
    assert step_a["parameters"] == {"rpm": 5000.0}

    # b) STOP with parameters {}, then tamper DB source to "X"
    l_b = BlockchainLedger()
    s_b = ICSSimulator()
    f_b = ForensicReconstructionEngine(l_b)
    c_b = s_b.execute_command("AUTHORIZED_ENG_01", "STOP", "PUMP_A_01", {})
    l_b.anchor_event(c_b)
    db_ev_b = copy.deepcopy(c_b)
    db_ev_b["source"] = "X"

    recon_b = f_b.reconstruct_incident([db_ev_b])
    step_b = recon_b["timeline"][0]
    assert step_b["policy_violation"] is False
    assert step_b["source"] == "AUTHORIZED_ENG_01"

    # c) same as (a) but also edit ledger block["parameters"] to {"rpm":2400}
    l_c = BlockchainLedger()
    s_c = ICSSimulator()
    f_c = ForensicReconstructionEngine(l_c)
    c_c = s_c.execute_command("AUTHORIZED_ENG_01", "SET_RPM", "PUMP_A_01", {"rpm": 5000.0})
    b_c = l_c.anchor_event(c_c)
    b_c["parameters"] = {"rpm": 2400.0}
    db_ev_c = copy.deepcopy(c_c)
    db_ev_c["parameters"] = {"rpm": 2400.0}

    recon_c = f_c.reconstruct_incident([db_ev_c])
    step_c = recon_c["timeline"][0]
    assert step_c["policy_violation"] is True

    # d) tamper the DB timestamp -> policy_violation True
    l_d = BlockchainLedger()
    s_d = ICSSimulator()
    f_d = ForensicReconstructionEngine(l_d)
    c_d = s_d.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    l_d.anchor_event(c_d)
    db_ev_d = copy.deepcopy(c_d)
    db_ev_d["timestamp"] = db_ev_d["timestamp"] + 100.0

    recon_d = f_d.reconstruct_incident([db_ev_d])
    step_d = recon_d["timeline"][0]
    assert step_d["policy_violation"] is True


def test_malformed_db_record_handling():
    """Verifies that audit_entire_chain, reconstruct_incident, and report generation handle malformed DB values gracefully."""
    import copy
    from report_generator import ForensicReportGenerator
    from threat_intel import ThreatIntelligenceEngine

    report_gen = ForensicReportGenerator()
    intel_engine = ThreatIntelligenceEngine()

    tampered_cases = [
        ("timestamp", "abc"),
        ("timestamp", None),
        ("parameters", "abc")
    ]

    for field, val in tampered_cases:
        l = BlockchainLedger()
        s = ICSSimulator()
        f = ForensicReconstructionEngine(l)

        cmd = s.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
        l.anchor_event(cmd)
        
        db_ev = copy.deepcopy(cmd)
        db_ev[field] = val

        # 1. Audit check
        audit = l.audit_entire_chain([db_ev])
        assert not audit["integrity_healthy"], f"Audit failed to detect tamper for {field}={val}"
        assert audit["tampered_blocks_found"] >= 1

        # 2. Reconstruct incident check
        recon = f.reconstruct_incident([db_ev])
        assert recon["success"] is True, f"Reconstruct failed for {field}={val}"
        assert recon["tamper_detected"] is True, f"Reconstruct tamper_detected False for {field}={val}"

        # 3. HTML report generation check
        intel = intel_engine.correlate_incident([], {}, tampered_detected=recon["tamper_detected"])
        html_report = report_gen.generate_html_report(recon, intel, s.get_telemetry_snapshot())
        assert isinstance(html_report, str) and len(html_report) > 0, f"HTML report generation failed for {field}={val}"


def test_tampered_parameters_correlate_and_report_resilience():
    """Verifies that correlate_incident and HTML report generator handle non-dict parameters ('abc', None, [1,2]) without raising exceptions."""
    import copy
    from report_generator import ForensicReportGenerator
    from threat_intel import ThreatIntelligenceEngine

    report_gen = ForensicReportGenerator()
    intel_engine = ThreatIntelligenceEngine()

    invalid_param_values = ["abc", None, [1, 2]]

    for param_val in invalid_param_values:
        l = BlockchainLedger()
        s = ICSSimulator()
        f = ForensicReconstructionEngine(l)

        cmd = s.execute_command("AUTHORIZED_ENG_01", "SET_RPM", "PUMP_A_01", {"rpm": 3000.0})
        l.anchor_event(cmd)

        db_ev = copy.deepcopy(cmd)
        db_ev["parameters"] = param_val

        recon = f.reconstruct_incident([db_ev])

        intel = intel_engine.correlate_incident([db_ev], {}, tampered_detected=recon["tamper_detected"])
        assert isinstance(intel, dict) and "matched_techniques" in intel

        html_report = report_gen.generate_html_report(recon, intel, s.get_telemetry_snapshot())
        assert isinstance(html_report, str) and len(html_report) > 0


if __name__ == "__main__":
    print("=" * 65)
    print(" 🧪 RUNNING IRONLEDGER AUTOMATED TEST SUITE")
    print("=" * 65)

    tests = [
        ("Canonical Hashing Determinism", lambda: test_canonical_hashing_determinism(BlockchainLedger())),
        ("Timestamp Tamper Detection", lambda: test_timestamp_tampering_detection(BlockchainLedger())),
        ("Snapshot State Tamper Detection", lambda: test_snapshot_tampering_detection(BlockchainLedger())),
        ("Broken Chain Link Detection", lambda: test_broken_chain_link_detection(BlockchainLedger())),
        ("Unanchored Record Detection", lambda: test_unanchored_db_record_detection(BlockchainLedger())),
        ("Purged / Deleted Record Detection", lambda: test_deleted_record_detection(BlockchainLedger())),
        ("Policy-Based Backward Walk", lambda: test_forensic_backward_walk_and_policy(BlockchainLedger(), ICSSimulator())),
        ("Threat Intel Objective Scoring", lambda: test_threat_intel_objective_scoring()),
        ("Anomaly Detector Physics & ML", lambda: test_anomaly_detector_physics_and_ml(AnomalyDetector(), ICSSimulator())),
        ("Tamper Parameter Hash Verification", lambda: test_forensic_tamper_parameter_verification()),
        ("Malformed DB Record Handling", lambda: test_malformed_db_record_handling()),
        ("Tampered Parameters Correlation Resilience", lambda: test_tampered_parameters_correlate_and_report_resilience()),
    ]

    passed = 0
    import traceback
    for name, test_fn in tests:
        try:
            test_fn()
            print(f"  ✅ PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  ❌ FAIL: {name} - {e}")
            traceback.print_exc()

    print("=" * 65)
    print(f" Results: {passed}/{len(tests)} tests passed successfully.")
    print("=" * 65)

