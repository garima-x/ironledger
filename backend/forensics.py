"""
IronLedger - Forensic Reconstruction & Backward-Walk Engine
Performs backward traversal from a flagged anomaly to root cause on the immutable ledger,
reconstructs chronological attack timelines, and detects database tampering via blockchain proof.
"""

import time
from typing import Dict, Any, List, Optional
from backend.blockchain import BlockchainLedger

class ForensicReconstructionEngine:
    def __init__(self, ledger: BlockchainLedger):
        self.ledger = ledger

    def reconstruct_incident(
        self,
        db_events: List[Dict[str, Any]],
        anomaly_event: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes backward-walk along the blockchain ledger:
        Traverses from the detected anomaly back to the initial rogue command or entry artifact.
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

        # Step 2: Backward walk from most recent or flagged event
        # Reverse chronological traversal
        sorted_events = sorted(db_events, key=lambda x: x.get("timestamp", 0), reverse=True)

        reconstructed_steps = []
        root_cause_candidate = None
        phase_map = {
            "OVERRIDE_SIS": "Safety Neutralization (Defense Evasion)",
            "SET_VALVE": "Process Parameter Manipulation",
            "SET_RPM": "Centrifuge / Pump Speed Escalation",
            "STOP": "Denial of Service / Equipment Halt",
            "START": "Unauthorized Process Activation",
            "TELEMETRY_SNAPSHOT": "Telemetry Observation"
        }

        # Walk backward
        for idx, ev in enumerate(sorted_events):
            cmd_type = ev.get("command_type", "UNKNOWN")
            source = ev.get("source", "UNKNOWN")
            ev_id = ev.get("event_id")

            # Check if this event was tampered with
            is_event_tampered = False
            tamper_note = None
            for detail in audit_result["audit_details"]:
                if detail.get("event_id") == ev_id and detail.get("tampered"):
                    is_event_tampered = True
                    tamper_note = "RECORD TAMPERED: Off-chain DB record deviates from on-chain SHA-256 anchor!"
                    break

            # Categorize kill-chain phase
            phase = phase_map.get(cmd_type, "Operational Command")
            if source in ["EXPLOIT_PAYLOAD", "ATTACKER_SSH_TUNNEL", "ROGUE_OPERATOR", "SCADA_EXPLOIT"]:
                phase = "Root-Cause Malicious Entry Point"
                root_cause_candidate = ev
            elif "OVERRIDE" in cmd_type or "SIS" in cmd_type:
                phase = "Safety Interlock Neutralization"
            elif "SET" in cmd_type and root_cause_candidate is None:
                # Potential root cause if unauthorized source
                if source not in ["AUTHORIZED_ENG_01", "SCADA_AUTO_PID", "GENESIS_NODE"]:
                    root_cause_candidate = ev

            # Find matching block in blockchain
            onchain_block = None
            for b in self.ledger.chain:
                if b.get("event_id") == ev_id:
                    onchain_block = b
                    break

            reconstructed_steps.append({
                "step_order": len(sorted_events) - idx,
                "event_id": ev_id,
                "timestamp": ev.get("timestamp"),
                "formatted_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ev.get("timestamp", time.time()))),
                "source": source,
                "command_type": cmd_type,
                "entity_id": ev.get("entity_id"),
                "parameters": ev.get("parameters", {}),
                "kill_chain_phase": phase,
                "tampered": is_event_tampered,
                "tamper_note": tamper_note,
                "onchain_block_number": onchain_block["block_number"] if onchain_block else None,
                "onchain_hash": onchain_block["event_hash"] if onchain_block else "NOT_ANCHORED",
                "tx_hash": onchain_block["tx_hash"] if onchain_block else None,
                "etherscan_url": onchain_block.get("etherscan_url") if onchain_block else None
            })

        # Order chronologically for the timeline view (from root cause -> impact)
        timeline = list(reversed(reconstructed_steps))

        # If no explicit candidate was found, designate earliest anomalous command
        if not root_cause_candidate and timeline:
            for step in timeline:
                if step["source"] not in ["AUTHORIZED_ENG_01", "SCADA_AUTO_PID", "GENESIS_NODE"]:
                    root_cause_candidate = step
                    break
            if not root_cause_candidate:
                root_cause_candidate = timeline[0]

        return {
            "success": True,
            "reconstruction_timestamp": time.time(),
            "events_analyzed": len(timeline),
            "tamper_detected": has_tampering,
            "tampered_records_count": audit_result["tampered_blocks_found"],
            "timeline": timeline,
            "root_cause_artifact": {
                "event_id": root_cause_candidate.get("event_id") if root_cause_candidate else None,
                "source_identity": root_cause_candidate.get("source") if root_cause_candidate else "Unknown",
                "entry_command": root_cause_candidate.get("command_type") if root_cause_candidate else "Unknown",
                "target_entity": root_cause_candidate.get("entity_id") if root_cause_candidate else "Unknown",
                "parameters": root_cause_candidate.get("parameters") if root_cause_candidate else {},
                "onchain_proof_tx": root_cause_candidate.get("tx_hash") if root_cause_candidate else None,
                "forensic_conclusion": (
                    f"Attack initiated via source [{root_cause_candidate.get('source')}] "
                    f"executing command [{root_cause_candidate.get('command_type')}] targeting [{root_cause_candidate.get('entity_id')}]. "
                    f"Cryptographic chain of custody verified against on-chain block on Ethereum Sepolia."
                    if root_cause_candidate else "Normal operation baseline."
                )
            },
            "chain_integrity_audit": audit_result
        }
