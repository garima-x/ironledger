"""
Forensic reconstruction (garima's modular version with attribution-update
tied-leader surfacing).
"""
import json
from sqlalchemy.orm import Session

from . import models
from .hashing import compute_hash
from .threat_intel import score_attribution


def recompute_offchain_hash(block: models.LedgerBlock) -> str:
    offchain_params = json.loads(block.offchain_params_json)
    _, hash_hex = compute_hash(
        block.source, block.offchain_command, block.entity,
        offchain_params, block.prev_hash
    )
    return hash_hex


def is_tampered(block: models.LedgerBlock) -> bool:
    return recompute_offchain_hash(block) != block.onchain_hash


def backward_walk(db: Session, start_block_id: int) -> list[dict]:
    """
    Walks the chain backwards from start_block_id via prevHash pointers until
    the genesis block, then returns the path in chronological (forward) order.
    Root-cause is flagged at the earliest anomaly-associated block.
    """
    blocks_by_hash = {b.onchain_hash: b for b in db.query(models.LedgerBlock).all()}
    current = db.query(models.LedgerBlock).filter(models.LedgerBlock.id == start_block_id).first()
    if current is None:
        return []

    path = [current]
    seen_ids = {current.id}
    node = current
    while node.prev_hash != "0" * 64:
        parent = blocks_by_hash.get(node.prev_hash)
        if parent is None or parent.id in seen_ids:
            break
        path.append(parent)
        seen_ids.add(parent.id)
        node = parent
    path.reverse()

    anomalous_block_ids = {
        r[0]
        for r in db.query(models.Anomaly.block_id)
        .filter(models.Anomaly.block_id.isnot(None))
        .distinct()
    }
    root_id = next((b.id for b in path if b.id in anomalous_block_ids), path[0].id)

    steps = []
    for b in path:
        tampered = is_tampered(b)
        is_root = b.id == root_id
        flag = "tamper" if tampered else ("root" if is_root else None)
        steps.append({
            "block_id": b.id,
            "ts": b.ts,
            "title": f"{b.command} → {b.entity}",
            "description": _describe(b, tampered, is_root),
            "flag": flag,
        })
    return steps


def _describe(block: models.LedgerBlock, tampered: bool, is_root: bool) -> str:
    if is_root:
        return "Root-cause entry point identified by backward traversal from the incident trigger."
    if tampered:
        return (
            "On-chain hash proves the original command; the off-chain historian "
            "record was later rewritten and no longer reproduces that hash."
        )
    return f"{block.entity} — {block.params_json}"


def compute_mitre_hits(db: Session) -> set[str]:
    rows = (
        db.query(models.Anomaly.technique)
        .filter(models.Anomaly.technique.isnot(None))
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


def attribution(db: Session) -> tuple[dict, str | None, list[str]]:
    hits = compute_mitre_hits(db)
    scores, leader, tied_with = score_attribution(hits)
    return scores, leader, tied_with
