"""
IronLedger - Blockchain Evidence Layer & Cryptographic Anchoring
Provides immutable ledger anchoring, SHA-256 state hashing, Ethereum Sepolia integration,
and cryptographic tamper detection against off-chain databases and modified local chains.
"""

import os
import json
import time
import hashlib
import secrets
import threading
from queue import Queue
from typing import Dict, Any, List, Optional, Tuple

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


def _canonicalize_value(val: Any) -> Any:
    """Recursively cleans and rounds numbers to floats to prevent int/float serialization drift."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (float, int)):
        return round(float(val), 3)
    if isinstance(val, dict):
        return {k: _canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [_canonicalize_value(v) for v in val]
    return val


def _canon(obj: Any) -> str:
    """Produces sorted, deterministic canonical JSON string."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


GENESIS_PAYLOAD = {"genesis_root": "IRONLEDGER_ICS_GENESIS_ROOT_V2"}
GENESIS_HASH = "0x" + hashlib.sha256(_canon(GENESIS_PAYLOAD).encode('utf-8')).hexdigest()


class BlockchainLedger:
    def __init__(self, sepolia_contract_address: Optional[str] = None):
        self.sepolia_contract_address = (
            sepolia_contract_address
            or os.environ.get("SEPOLIA_CONTRACT_ADDRESS", "").strip()
        )
        self.rpc_url = os.environ.get("SEPOLIA_RPC_URL", "").strip()
        self.private_key = os.environ.get("ANCHOR_PRIVATE_KEY", "").strip()
        
        self.w3: Optional[Any] = None
        self.contract: Optional[Any] = None
        self.account: Optional[Any] = None
        self.is_simulated = True

        self.chain: List[Dict[str, Any]] = []
        self.hash_index: Dict[str, Dict[str, Any]] = {}
        
        # Tamper-isolated anchor mirror to detect local in-memory chain rebuilds
        self._immutable_anchor_mirror: List[Dict[str, Any]] = []

        # Cache for smart contract on-chain evidence
        self._onchain_hashes_cache = None
        self._onchain_cache_time = 0.0

        self._tx_queue: Queue = Queue()
        self._queue_worker_running = False
        self.on_block_updated = None

        self._init_web3()

        # Deterministic Genesis Block
        self.genesis_block = {
            "block_index": 0,
            "event_id": 0,
            "event_hash": GENESIS_HASH,
            "previous_hash": "0x" + "0" * 64,
            "timestamp": 1700000000,
            "timestamp_ms": 1700000000000,
            "source": "GENESIS_NODE",
            "command_type": "INITIALIZE_LEDGER",
            "entity_id": "SYS_ROOT",
            "tx_hash": None,
            "block_number": None,
            "recorded_by": "0x0000000000000000000000000000000000000000",
            "status": "CONFIRMED_ON_CHAIN" if not self.is_simulated else "SIMULATED_LOCAL_CHAIN",
            "is_simulated": self.is_simulated,
            "etherscan_url": None
        }
        self.chain.append(self.genesis_block)
        self.hash_index[self.genesis_block["event_hash"]] = self.genesis_block
        self._immutable_anchor_mirror.append(dict(self.genesis_block))

    def _init_web3(self):
        """Initializes Web3 connection and starts non-blocking background queue worker."""
        if WEB3_AVAILABLE and self.rpc_url and self.private_key and self.sepolia_contract_address:
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                if self.w3.is_connected():
                    self.account = self.w3.eth.account.from_key(self.private_key)
                    abi_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "contracts", "EvidenceChainABI.json")
                    if os.path.exists(abi_path):
                        with open(abi_path, "r") as f:
                            abi = json.load(f)
                        self.contract = self.w3.eth.contract(
                            address=Web3.to_checksum_address(self.sepolia_contract_address),
                            abi=abi
                        )
                        self.is_simulated = False
                        self._start_queue_worker()
                        print(f"🔗 Connected to Ethereum Sepolia via Web3. Wallet: {self.account.address}")
            except Exception as e:
                print(f"⚠️  Web3 Sepolia connection fallback to simulation mode: {e}")
                self.is_simulated = True
        else:
            self.is_simulated = True

    def _start_queue_worker(self):
        """Starts background worker thread for non-blocking Ethereum transaction broadcasts."""
        if not self._queue_worker_running:
            self._queue_worker_running = True
            worker = threading.Thread(target=self._process_tx_queue, daemon=True)
            worker.start()

    def _process_tx_queue(self):
        """Background worker loop broadcasting transactions to Sepolia without freezing HTTP API."""
        while self._queue_worker_running:
            try:
                task = self._tx_queue.get(timeout=1.0)
            except Exception:
                continue

            block_ref = task.get("block_ref")
            event = task.get("event")
            event_hash = block_ref["event_hash"]
            prev_hash = block_ref["previous_hash"]

            try:
                # EvidenceChain.addEvidence(string _caseId, string _evidenceHash, string _description)
                # _caseId      → entity_id  (e.g. "PLANT", "REACTOR-1")
                # _evidenceHash → SHA-256 hex string of the ICS event
                # _description  → "<command_type> | <source>" for human-readable audit trail
                case_id = str(event.get("entity_id", "IRONLEDGER"))
                description = f"{event.get('command_type', 'EVENT')} | {event.get('source', 'UNKNOWN')}"

                # Fetch pending nonce to avoid collision
                nonce = self.w3.eth.get_transaction_count(self.account.address, 'pending')

                base_fee = self.w3.eth.get_block('latest').get('baseFeePerGas', self.w3.to_wei(1, 'gwei'))
                priority_fee = self.w3.to_wei(2, 'gwei')
                max_fee = base_fee * 2 + priority_fee

                func_call = self.contract.functions.addEvidence(case_id, event_hash, description)
                try:
                    estimated_gas = func_call.estimate_gas({"from": self.account.address})
                    gas_limit = int(estimated_gas * 1.25)
                except Exception:
                    gas_limit = 1500000

                tx = func_call.build_transaction({
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": gas_limit,
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": priority_fee,
                    "chainId": 11155111
                })
                signed = self.account.sign_transaction(tx)
                raw_tx = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction", None)
                tx_sent = self.w3.eth.send_raw_transaction(raw_tx)
                tx_hash_hex = tx_sent.hex()

                block_ref["tx_hash"] = tx_hash_hex
                block_ref["etherscan_url"] = f"https://sepolia.etherscan.io/tx/{tx_hash_hex}"
                block_ref["status"] = "PENDING_CONFIRMATION"

                # Wait for receipt asynchronously in worker
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_sent, timeout=120)
                if receipt.status == 1:
                    block_ref["block_number"] = receipt.blockNumber
                    block_ref["status"] = "CONFIRMED_ON_CHAIN"
                    self._onchain_hashes_cache = None
                else:
                    block_ref["status"] = "REVERTED_ON_CHAIN"
            except Exception as exc:
                print(f"⚠️ On-chain broadcast failed for block #{block_ref.get('block_index')}: {exc}")
                block_ref["status"] = "FAILED_ON_CHAIN"
                block_ref["tx_hash"] = None
                block_ref["etherscan_url"] = None

            if self.on_block_updated:
                self.on_block_updated(block_ref)

            self._tx_queue.task_done()

    def compute_event_hash(self, event: Dict[str, Any], previous_hash: str) -> str:
        """
        Computes deterministic SHA-256 cryptographic digest of an ICS event covering:
        event_id, timestamp_ms, source, command_type, entity_id, parameters, snapshot_sha256, and previous_hash.
        """
        raw_ts = float(event.get("timestamp", time.time()))
        ts_ms = int(raw_ts * 1000)
        
        snap = event.get("plant_state_snapshot", {})
        snap_canon = _canonicalize_value(snap)
        snap_hash = hashlib.sha256(_canon(snap_canon).encode('utf-8')).hexdigest()

        payload = {
            "event_id": int(event.get("event_id", 0)),
            "timestamp_ms": ts_ms,
            "source": str(event.get("source", "")),
            "command_type": str(event.get("command_type", "")),
            "entity_id": str(event.get("entity_id", "")),
            "parameters": _canonicalize_value(event.get("parameters", {})),
            "snapshot_sha256": snap_hash,
            "previous_hash": previous_hash
        }
        raw_hash = hashlib.sha256(_canon(payload).encode('utf-8')).hexdigest()
        return f"0x{raw_hash}"

    def anchor_event(self, event: Dict[str, Any], signer_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Anchors an ICS event onto the immutable blockchain ledger.
        In live mode: queues transaction to Sepolia without blocking API.
        In simulated mode: generates cryptographic hash chain with transparent simulation labeling.
        """
        prev_block = self.chain[-1]
        prev_hash = prev_block["event_hash"]
        
        event_hash = self.compute_event_hash(event, prev_hash)
        ts_sec = float(event.get("timestamp", time.time()))
        ts_ms = int(ts_sec * 1000)

        recorded_by = signer_address or (self.account.address if self.account else "0x0000000000000000000000000000000000000000")

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
            "parameters": event.get("parameters", {}),
            "tx_hash": None,
            "block_number": None,
            "recorded_by": recorded_by,
            "status": "QUEUED_ON_CHAIN" if not self.is_simulated else "SIMULATED_LOCAL_CHAIN",
            "is_simulated": self.is_simulated,
            "etherscan_url": None
        }

        self.chain.append(block)
        self.hash_index[event_hash] = block
        self._immutable_anchor_mirror.append(dict(block))

        # If live Web3 is active, queue for background on-chain broadcast
        if not self.is_simulated and self.contract and self.account:
            self._tx_queue.put({"block_ref": block, "event": event})

        return block

    def verify_against_contract(self) -> Dict[str, Any]:
        """
        Read-back verification directly querying the deployed Smart Contract on Sepolia.
        Fetches all on-chain hashes once and caches them for 30s to minimize RPC calls.
        For every local block with status CONFIRMED_ON_CHAIN (or non-genesis block on chain),
        checks that its hash is in the on-chain set, flagging any missing or mismatched hashes.
        """
        if self.is_simulated or not self.contract or not self.w3:
            return {
                "contract_connected": False,
                "mode": "SIMULATION",
                "verified": False,
                "note": "On-chain verification unavailable: Running in local cryptographic simulation mode."
            }

        try:
            now = time.time()
            # Fetch on-chain hashes once and cache for 30s to avoid repeated RPC round-trips
            if (
                self._onchain_hashes_cache is None
                or (now - self._onchain_cache_time) > 30.0
            ):
                total_onchain = self.contract.functions.evidenceCount().call()
                onchain_hashes = set()
                onchain_by_index = {}
                for i in range(1, total_onchain + 1):
                    ev_data = self.contract.functions.getEvidence(i).call()
                    # ev_data: (evidenceId, caseId, evidenceHash, description, uploadedBy, timestamp)
                    h = str(ev_data[2]).strip().lower()
                    onchain_hashes.add(h)
                    onchain_by_index[i] = h

                self._onchain_hashes_cache = {
                    "total": total_onchain,
                    "hashes": onchain_hashes,
                    "by_index": onchain_by_index
                }
                self._onchain_cache_time = now

            cached = self._onchain_hashes_cache
            total_onchain = cached["total"]
            onchain_hashes = cached["hashes"]

            discrepancies = []

            # Check every local block with status CONFIRMED_ON_CHAIN
            for blk in self.chain[1:]:
                blk_idx = blk.get("block_index")
                status = blk.get("status")
                local_h = blk.get("event_hash", "").strip().lower()

                if status == "CONFIRMED_ON_CHAIN" or blk.get("tx_hash"):
                    if local_h not in onchain_hashes:
                        discrepancies.append({
                            "block_index": blk_idx,
                            "event_id": blk.get("event_id"),
                            "local_hash": local_h,
                            "onchain_hash": "MISSING_FROM_SMART_CONTRACT",
                            "reason": "CONFIRMED_BLOCK_NOT_FOUND_ON_CHAIN"
                        })

            return {
                "contract_connected": True,
                "mode": "LIVE_SEPOLIA",
                "total_onchain_events": total_onchain,
                "verified": len(discrepancies) == 0,
                "discrepancies": discrepancies
            }
        except Exception as e:
            return {
                "contract_connected": False,
                "mode": "LIVE_SEPOLIA_ERROR",
                "error": str(e),
                "verified": False
            }

    def audit_entire_chain(self, db_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Audits all off-chain events against the immutable hash history.
        Carries true previous hash forward, compares against immutable anchor mirror
        (detecting forged chain rebuilds), and reads back from smart contract if live.
        """
        db_map = {e.get("event_id"): e for e in db_events if "event_id" in e}
        findings = []
        prev = self.genesis_block["event_hash"]

        # 1. Check against the immutable anchor mirror to detect in-memory chain rebuilds
        for idx in range(1, max(len(self.chain), len(self._immutable_anchor_mirror))):
            if idx >= len(self._immutable_anchor_mirror):
                findings.append({
                    "block_index": idx,
                    "event_id": self.chain[idx].get("event_id") if idx < len(self.chain) else None,
                    "tampered": True,
                    "reason": "FORGED_CHAIN_EXTENSION",
                    "verdict": "TAMPER_DETECTED_FORGED_BLOCK"
                })
            elif idx >= len(self.chain):
                findings.append({
                    "block_index": idx,
                    "event_id": self._immutable_anchor_mirror[idx].get("event_id"),
                    "tampered": True,
                    "reason": "CHAIN_TRUNCATION_DETECTED",
                    "verdict": "TAMPER_DETECTED_TRUNCATED_CHAIN"
                })
            else:
                curr_blk = self.chain[idx]
                mirror_blk = self._immutable_anchor_mirror[idx]
                if curr_blk.get("event_hash") != mirror_blk.get("event_hash"):
                    findings.append({
                        "block_index": idx,
                        "event_id": curr_blk.get("event_id"),
                        "tampered": True,
                        "reason": "LOCAL_CHAIN_REBUILT_HASH_MISMATCH",
                        "immutable_onchain_hash": mirror_blk.get("event_hash"),
                        "computed_db_hash": curr_blk.get("event_hash"),
                        "verdict": "TAMPER_DETECTED_CHAIN_REWRITE"
                    })

        # 2. Audit off-chain database records against chain
        for blk in self.chain[1:]:
            blk_idx = blk.get("block_index")
            ev_id = blk.get("event_id")

            # Verify previous_hash link
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

            # Check if database record was deleted
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
                # Recompute hash using true prev hash
                try:
                    computed = self.compute_event_hash(ev, prev)
                except (ValueError, TypeError, KeyError):
                    findings.append({
                        "block_index": blk_idx,
                        "event_id": ev_id,
                        "tampered": True,
                        "reason": "MALFORMED_RECORD",
                        "immutable_onchain_hash": blk.get("event_hash", ""),
                        "computed_db_hash": "MALFORMED_RECORD",
                        "tx_hash": blk.get("tx_hash"),
                        "block_number": blk.get("block_number"),
                        "verdict": "TAMPER_DETECTED_MALFORMED_RECORD"
                    })
                    prev = blk.get("event_hash")
                    continue

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

        # 3. Check for forged / unanchored events inserted into DB
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

        # 4. Smart contract read-back check (if Web3 is active)
        contract_status = self.verify_against_contract()
        if contract_status.get("contract_connected") and not contract_status.get("verified"):
            for disc in contract_status.get("discrepancies", []):
                findings.append({
                    "block_index": disc.get("event_id"),
                    "event_id": disc.get("event_id"),
                    "tampered": True,
                    "reason": "ONCHAIN_SMART_CONTRACT_MISMATCH",
                    "immutable_onchain_hash": disc.get("onchain_hash"),
                    "computed_db_hash": disc.get("local_hash"),
                    "verdict": "TAMPER_DETECTED_ONCHAIN_DISCREPANCY"
                })

        tampered_count = sum(1 for f in findings if f.get("tampered"))
        return {
            "total_blocks_checked": len(self.chain) - 1,
            "tampered_blocks_found": tampered_count,
            "integrity_healthy": (tampered_count == 0),
            "contract_verification": contract_status,
            "audit_details": findings
        }

    def get_recent_blocks(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.chain[-limit:]))
