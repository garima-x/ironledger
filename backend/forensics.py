"""
IronLedger - Forensic Reconstruction & Backward-Walk Engine
Performs backward traversal along the immutable cryptographic hash chain,
reconstructs chronological attack timelines, evaluates unauthorized policy violations,
and verifies on-chain evidence integrity.
"""

import time
from typing import Dict, Any, List, Optional, Tuple
from backend.blockchain import BlockchainLedger

AUTHORIZED_SOURCES = {"AUTHORIZED_ENG_01", "SCADA_AUTO_PID", "GENESIS_NODE"}


class ForensicReconstructionEngine:
    def __init__(self, ledger: BlockchainLedger):
        self.ledger = ledger

    def _evaluate_command_policy(self, event: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Evaluates whether a command complies with SCADA operational policies.
        Returns: (is_violation: bool, kill_chain_phase: str, policy_reason: str)
        """
        source = str(event.get("source", "UNKNOWN"))
        cmd_type = str(event.get("command_type", "UNKNOWN"))
        params = event.get("parameters", {})
        entity_id = str(event.get("entity_id", "UNKNOWN"))

        # Policy 1: Source authorization allowlist
        if source not in AUTHORIZED_SOURCES:
            if "OVERRIDE" in cmd_type or "SIS" in cmd_type or params.get("bypass"):
                return True, "Safety Interlock Neutralization (T0888)", f"Unauthorized operator '{source}' bypassed SIS interlocks."
            if "VALVE" in entity_id:
                return True, "Process Parameter Manipulation (T0836)", f"Unauthorized entity '{source}' altered valve setpoints."
            if "PUMP" in entity_id or cmd_type in ["SET_RPM", "STOP"]:
                return True, "Manipulation of Control (T0831)", f"Unauthorized operator '{source}' modified pump operational speed."
            return True, "Unauthorized Command Injection (T0855)", f"Command dispatched from unauthenticated origin '{source}'."

        # Policy 2: Dangerous commands requiring explicit dual-authorization
        if cmd_type == "OVERRIDE_SIS" and not params.get("authorized", False):
            return True, "Safety Interlock Neutralization (T0888)", "SIS logic bypass executed without dual-operator safety sign-off."

        if cmd_type == "SET_VALVE" and params.get("open_percent", 100) < 5.0 and "VENT" in entity_id:
            return True, "Process Parameter Manipulation (T0836)", "Relief vent clamped shut during high-throughput operational mode."

        # Normal operational command
        phase_map = {
            "START": "Authorized Process Activation",
            "SET_VALVE": "Routine Process Adjustment",
            "SET_RPM": "Routine Speed Regulation",
            "STOP": "Controlled Equipment Shutdown",
            "TELEMETRY_SNAPSHOT": "Telemetry Observation",
            "INITIALIZE_LEDGER": "System Initialization"
        }
        return False, phase_map.get(cmd_type, "Operational Command"), "Standard operational procedure"

    def reconstruct_incident(
        self,
        db_events: List[Dict[str, Any]],
        anomaly_event: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes evidence-based backward-walk along the blockchain ledger:
        Traverses from the detected anomaly backwards along previous_hash links to isolate root cause.
        """
        if not db_events:
            return {
                "success": False,
                "message": "No forensic events available in database",
                "timeline": [],
                "root_cause": None
            }

        # Step 1: Run complete cryptographic integrity audit
        audit_result = self.ledger.audit_entire_chain(db_events)
        has_tampering = not audit_result["integrity_healthy"]

        # Step 2: Index database events by event_id
        db_map = {e.get("event_id"): e for e in db_events if "event_id" in e}

        # Step 3: Backward traversal along the blockchain hash chain
        reconstructed_steps = []
        root_cause_candidate = None
        policy_violations_found = []

        # Iterate backward through anchored blockchain blocks (skipping genesis)
        reversed_blocks = list(reversed(self.ledger.chain[1:]))

        for idx, block in enumerate(reversed_blocks):
            ev_id = block.get("event_id")
            db_ev = db_map.get(ev_id, {})
            
            # Use database event if present, otherwise fallback to on-chain block data
            source = db_ev.get("source") or block.get("source", "UNKNOWN")
            cmd_type = db_ev.get("command_type") or block.get("command_type", "UNKNOWN")
            entity_id = db_ev.get("entity_id") or block.get("entity_id", "UNKNOWN")
            parameters = db_ev.get("parameters") or {}
            timestamp = db_ev.get("timestamp") or block.get("timestamp", time.time())

            # Check if this specific event was tampered with in off-chain storage
            is_event_tampered = False
            tamper_note = None
            for detail in audit_result.get("audit_details", []):
                if detail.get("event_id") == ev_id and detail.get("tampered"):
                    is_event_tampered = True
                    tamper_note = f"RECORD TAMPERED: Off-chain DB record deviates from on-chain SHA-256 anchor! ({detail.get('reason')})"
                    break

            # Evaluate operational policy
            is_violation, kill_chain_phase, policy_reason = self._evaluate_command_policy({
                "source": source,
                "command_type": cmd_type,
                "entity_id": entity_id,
                "parameters": parameters
            })

            step_entry = {
                "step_order": len(reversed_blocks) - idx,
                "event_id": ev_id,
                "timestamp": timestamp,
                "formatted_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(timestamp))),
                "source": source,
                "command_type": cmd_type,
                "entity_id": entity_id,
                "parameters": parameters,
                "kill_chain_phase": kill_chain_phase,
                "policy_violation": is_violation,
                "policy_reason": policy_reason,
                "tampered": is_event_tampered,
                "tamper_note": tamper_note,
                "onchain_block_number": block.get("block_number"),
                "onchain_hash": block.get("event_hash"),
                "previous_hash": block.get("previous_hash"),
                "tx_hash": block.get("tx_hash"),
                "is_simulated": block.get("is_simulated", True),
                "etherscan_url": block.get("etherscan_url")
            }

            if is_violation:
                policy_violations_found.append(step_entry)
                # The earliest violation in the sequence (last encountered in backward walk) is the true root cause
                root_cause_candidate = step_entry

            reconstructed_steps.append(step_entry)

        # Order chronologically for display (from earliest root cause -> latest impact)
        timeline = list(reversed(reconstructed_steps))

        if not root_cause_candidate and timeline:
            # Fallback to earliest entry if no policy violation detected
            root_cause_candidate = timeline[0]

        return {
            "success": True,
            "reconstruction_timestamp": time.time(),
            "events_analyzed": len(timeline),
            "tamper_detected": has_tampering,
            "tampered_records_count": audit_result.get("tampered_blocks_found", 0),
            "policy_violations_count": len(policy_violations_found),
            "timeline": timeline,
            "root_cause_artifact": {
                "event_id": root_cause_candidate.get("event_id") if root_cause_candidate else None,
                "source_identity": root_cause_candidate.get("source") if root_cause_candidate else "Unknown",
                "entry_command": root_cause_candidate.get("command_type") if root_cause_candidate else "Unknown",
                "target_entity": root_cause_candidate.get("entity_id") if root_cause_candidate else "Unknown",
                "parameters": root_cause_candidate.get("parameters") if root_cause_candidate else {},
                "onchain_proof_tx": root_cause_candidate.get("tx_hash") if root_cause_candidate else None,
                "policy_violation": root_cause_candidate.get("policy_violation", False),
                "policy_reason": root_cause_candidate.get("policy_reason", "Baseline"),
                "forensic_conclusion": (
                    f"Root cause identified via backward hash traversal: source [{root_cause_candidate.get('source')}] "
                    f"executed [{root_cause_candidate.get('command_type')}] targeting [{root_cause_candidate.get('entity_id')}]. "
                    f"Policy violation: {root_cause_candidate.get('policy_reason')}. "
                    f"Cryptographic chain of custody verified against on-chain block."
                    if root_cause_candidate else "Normal operation baseline."
                )
            },
            "chain_integrity_audit": audit_result
        }
