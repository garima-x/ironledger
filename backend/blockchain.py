"""
IronLedger - Blockchain Evidence Layer & Cryptographic Anchoring
Provides immutable ledger anchoring, SHA-256 state hashing, Ethereum Sepolia integration,
and cryptographic tamper detection against off-chain databases.
"""

import os
import json
import time
import hashlib
import secrets
from typing import Dict, Any, List, Optional, Tuple

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


def _canonicalize_value(val: Any) -> Any:
    """Recursively cleans and rounds floats to prevent float representation serialization drift."""
    if isinstance(val, float):
        return round(val, 3)
    if isinstance(val, dict):
        return {k: _canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [_canonicalize_value(v) for v in val]
    return val


def _canon(obj: Any) -> str:
    """Produces sorted, deterministic canonical JSON string."""
    cleaned = _canonicalize_value(obj)
    return json.dumps(cleaned, sort_keys=True, separators=(',', ':'))


class BlockchainLedger:
    def __init__(self, sepolia_contract_address: Optional[str] = None):
        self.sepolia_contract_address = (
            sepolia_contract_address
            or os.environ.get("SEPOLIA_CONTRACT_ADDRESS", "0x7a36B3DeE1F03287cCE488f2604245F11dF9d78F")
        )
        self.rpc_url = os.environ.get("SEPOLIA_RPC_URL", "")
        self.private_key = os.environ.get("ANCHOR_PRIVATE_KEY", "")
        
        self.w3: Optional[Any] = None
        self.contract: Optional[Any] = None
        self.account: Optional[Any] = None
        self.is_simulated = True

        self._init_web3()

        self.chain: List[Dict[str, Any]] = []
        self.hash_index: Dict[str, Dict[str, Any]] = {}
        self.latest_sepolia_block = 6849200

        # Deterministic Genesis Block
        genesis_payload = {"genesis_root": "IRONLEDGER_ICS_GENESIS_ROOT_V2"}
        genesis_hash = hashlib.sha256(_canon(genesis_payload).encode('utf-8')).hexdigest()
        self.genesis_block = {
            "block_index": 0,
            "event_id": 0,
            "event_hash": f"0x{genesis_hash}",
            "previous_hash": "0x" + "0" * 64,
            "timestamp": 1700000000,
            "timestamp_ms": 1700000000000,
            "source": "GENESIS_NODE",
            "command_type": "INITIALIZE_LEDGER",
            "entity_id": "SYS_ROOT",
            "tx_hash": "0x" + "0" * 63 + "1",
            "block_number": self.latest_sepolia_block,
            "recorded_by": "0x0000000000000000000000000000000000000000",
            "status": "CONFIRMED_ON_CHAIN" if not self.is_simulated else "SIMULATED_LOCAL_CHAIN",
            "is_simulated": self.is_simulated
        }
        self.chain.append(self.genesis_block)
        self.hash_index[self.genesis_block["event_hash"]] = self.genesis_block

    def _init_web3(self):
        """Initializes Web3 connection if RPC URL and private key are supplied."""
        if WEB3_AVAILABLE and self.rpc_url and self.private_key and self.sepolia_contract_address:
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                if self.w3.is_connected():
                    self.account = self.w3.eth.account.from_key(self.private_key)
                    abi_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "contracts", "IronLedgerABI.json")
                    if os.path.exists(abi_path):
                        with open(abi_path, "r") as f:
                            abi = json.load(f)
                        self.contract = self.w3.eth.contract(
                            address=Web3.to_checksum_address(self.sepolia_contract_address),
                            abi=abi
                        )
                        self.is_simulated = False
                        print(f"🔗 Connected to Ethereum Sepolia via Web3. Wallet: {self.account.address}")
            except Exception as e:
                print(f"⚠️  Web3 Sepolia connection fallback to simulation mode: {e}")
                self.is_simulated = True
        else:
            self.is_simulated = True

    def compute_event_hash(self, event: Dict[str, Any], previous_hash: str) -> str:
        """
        Computes deterministic SHA-256 cryptographic digest of an ICS event covering:
        event_id, timestamp_ms, source, command_type, entity_id, parameters, snapshot_sha256, and previous_hash.
        """
        raw_ts = float(event.get("timestamp", time.time()))
        ts_ms = int(raw_ts * 1000)
        
        snap = event.get("plant_state_snapshot", {})
        snap_hash = hashlib.sha256(_canon(snap).encode('utf-8')).hexdigest()

        payload = {
            "event_id": int(event.get("event_id", 0)),
            "timestamp_ms": ts_ms,
            "source": str(event.get("source", "")),
            "command_type": str(event.get("command_type", "")),
            "entity_id": str(event.get("entity_id", "")),
            "parameters": event.get("parameters", {}),
            "snapshot_sha256": snap_hash,
            "previous_hash": previous_hash
        }
        raw_hash = hashlib.sha256(_canon(payload).encode('utf-8')).hexdigest()
        return f"0x{raw_hash}"

    def anchor_event(self, event: Dict[str, Any], signer_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Anchors an ICS event onto the immutable blockchain ledger.
        Broadcasts to Ethereum Sepolia if Web3 is configured, or generates cryptographic proof locally.
        """
        prev_block = self.chain[-1]
        prev_hash = prev_block["event_hash"]
        
        event_hash = self.compute_event_hash(event, prev_hash)
        ts_sec = float(event.get("timestamp", time.time()))
        ts_ms = int(ts_sec * 1000)

        tx_hash = None
        block_num = None
        status = "SIMULATED_LOCAL_CHAIN"
        recorded_by = signer_address or (self.account.address if self.account else "0x2C4e08287F4b8f04c64391F0317eDeF1778cD630")

        # Attempt on-chain broadcast if real Web3 is active
        if not self.is_simulated and self.w3 and self.contract and self.account:
            try:
                event_hash_bytes = bytes.fromhex(event_hash[2:])
                prev_hash_bytes = bytes.fromhex(prev_hash[2:])
                tx = self.contract.functions.recordEvent(
                    event_hash_bytes,
                    prev_hash_bytes,
                    str(event.get("source", "")),
                    str(event.get("command_type", "")),
                    str(event.get("entity_id", ""))
                ).build_transaction({
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address),
                    "gas": 200000,
                    "maxFeePerGas": self.w3.eth.gas_price * 2,
                    "maxPriorityFeePerGas": self.w3.to_wei(2, 'gwei'),
                    "chainId": 11155111  # Sepolia Chain ID
                })
                signed = self.account.sign_transaction(tx)
                raw_tx = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction", None)
                tx_sent = self.w3.eth.send_raw_transaction(raw_tx)
                tx_hash = tx_sent.hex()
                status = "PENDING_ON_CHAIN"
                # Wait for receipt in non-blocking / short timeout or record hash
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_sent, timeout=30)
                block_num = receipt.blockNumber
                status = "CONFIRMED_ON_CHAIN"
            except Exception as e:
                print(f"⚠️ Live on-chain transaction failed: {e}. Falling back to cryptographic simulation.")
                tx_hash = f"0x{secrets.token_hex(32)}"
                self.latest_sepolia_block += 1
                block_num = self.latest_sepolia_block
                status = "SIMULATED_LOCAL_CHAIN"
        else:
            self.latest_sepolia_block += 1
            tx_hash = f"0x{secrets.token_hex(32)}"
            block_num = self.latest_sepolia_block
            status = "SIMULATED_LOCAL_CHAIN"

        block = {
            "block_index": len(self.chain),
            "event_id": int(event.get("event_id", len(self.chain))),
            "event_hash": event_hash,
            "previous_hash": prev_hash,
            "timestamp": int(ts_sec),
            "timestamp_ms": ts_ms,
            "source": str(event.get("source", "UNKNOWN")),
            "command_type": str(event.get("command_type", "TELEMETRY_SNAPSHOT")),
            "entity_id": str(event.get("entity_id", "PLANT")),
            "tx_hash": tx_hash,
            "block_number": block_num,
            "recorded_by": recorded_by,
            "status": status,
            "is_simulated": self.is_simulated,
            "etherscan_url": f"https://sepolia.etherscan.io/tx/{tx_hash}"
        }

        self.chain.append(block)
        self.hash_index[event_hash] = block
        return block

    def verify_event_integrity(self, db_event: Dict[str, Any], block_index: int) -> Dict[str, Any]:
        """
        Cross-examines database record against on-chain block.
        Recomputes hash against previous block's hash.
        """
        if block_index < 0 or block_index >= len(self.chain):
            return {
                "verified": False,
                "tampered": True,
                "reason": "BLOCK_NOT_FOUND",
                "error": f"Block index {block_index} outside blockchain bounds"
            }

        immutable_block = self.chain[block_index]
        prev_hash = immutable_block["previous_hash"]
        computed_hash = self.compute_event_hash(db_event, prev_hash)
        expected_hash = immutable_block["event_hash"]

        is_valid = (computed_hash.lower() == expected_hash.lower())
        
        return {
            "verified": is_valid,
            "tampered": not is_valid,
            "block_index": block_index,
            "event_id": db_event.get("event_id"),
            "immutable_onchain_hash": expected_hash,
            "computed_db_hash": computed_hash,
            "tx_hash": immutable_block["tx_hash"],
            "block_number": immutable_block["block_number"],
            "timestamp": immutable_block["timestamp"],
            "verdict": "VERIFIED_AUTHENTIC" if is_valid else "TAMPER_DETECTED_HASH_MISMATCH"
        }

    def audit_entire_chain(self, db_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Audits all off-chain events against the on-chain immutable hash history.
        Verifies previous_hash linkage across every block and flags unanchored records or deletions.
        """
        db_map = {e.get("event_id"): e for e in db_events if "event_id" in e}
        findings = []
        prev = self.genesis_block["event_hash"]

        for blk in self.chain[1:]:
            blk_idx = blk.get("block_index")
            ev_id = blk.get("event_id")

            # 1. Verify previous_hash link against the actual previous on-chain block's hash
            if blk.get("previous_hash") != prev:
                findings.append({
                    "block_index": blk_idx,
                    "event_id": ev_id,
                    "tampered": True,
                    "reason": "BROKEN_CHAIN_LINK",
                    "immutable_onchain_hash": blk.get("event_hash"),
                    "computed_db_hash": "CHAIN_BROKEN",
                    "verdict": "TAMPER_DETECTED_BROKEN_CHAIN_LINK"
                })

            # 2. Check if the database record was purged/deleted
            ev = db_map.get(ev_id)
            if ev is None:
                findings.append({
                    "block_index": blk_idx,
                    "event_id": ev_id,
                    "tampered": True,
                    "reason": "AUDIT_RECORD_DELETED_FROM_DB",
                    "immutable_onchain_hash": blk.get("event_hash"),
                    "computed_db_hash": "RECORD_PURGED",
                    "verdict": "TAMPER_DETECTED_RECORD_DELETED"
                })
            else:
                # 3. Recompute hash using the true prev hash
                computed = self.compute_event_hash(ev, prev)
                expected = blk.get("event_hash", "")
                if computed.lower() != expected.lower():
                    findings.append({
                        "block_index": blk_idx,
                        "event_id": ev_id,
                        "tampered": True,
                        "reason": "HASH_MISMATCH",
                        "immutable_onchain_hash": expected,
                        "computed_db_hash": computed,
                        "tx_hash": blk.get("tx_hash"),
                        "block_number": blk.get("block_number"),
                        "verdict": "TAMPER_DETECTED_HASH_MISMATCH"
                    })
                else:
                    findings.append({
                        "verified": True,
                        "tampered": False,
                        "block_index": blk_idx,
                        "event_id": ev_id,
                        "immutable_onchain_hash": expected,
                        "computed_db_hash": computed,
                        "tx_hash": blk.get("tx_hash"),
                        "block_number": blk.get("block_number"),
                        "timestamp": blk.get("timestamp"),
                        "verdict": "VERIFIED_AUTHENTIC"
                    })

            prev = blk.get("event_hash")

        # 4. Check for forged / unanchored events inserted directly into DB
        anchored_ids = {b.get("event_id") for b in self.chain[1:]}
        for unanchored_id in set(db_map.keys()) - anchored_ids:
            if unanchored_id is not None:
                findings.append({
                    "block_index": None,
                    "event_id": unanchored_id,
                    "tampered": True,
                    "reason": "UNANCHORED_DB_RECORD",
                    "immutable_onchain_hash": "NOT_ON_CHAIN",
                    "computed_db_hash": "FORGED_INSERT",
                    "verdict": "TAMPER_DETECTED_UNANCHORED_RECORD"
                })

        tampered_count = sum(1 for f in findings if f.get("tampered"))
        return {
            "total_blocks_checked": len(self.chain) - 1,
            "tampered_blocks_found": tampered_count,
            "integrity_healthy": (tampered_count == 0),
            "audit_details": findings
        }

    def get_recent_blocks(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.chain[-limit:]))
