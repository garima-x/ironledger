"""Ledger router — block creation, listing, tamper simulation, chain verify."""
import json
import threading
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db_sql import get_db
from ..hashing import compute_hash, GENESIS_HASH
from ..chain_blockchain import anchor_on_chain
from ..forensics import recompute_offchain_hash, is_tampered

router = APIRouter(prefix="/ledger", tags=["ledger"])

# Prevents concurrent requests from forking the hash-chain
_chain_lock = threading.Lock()


def _latest_hash(db: Session) -> str:
    last = db.query(models.LedgerBlock).order_by(models.LedgerBlock.id.desc()).first()
    return last.onchain_hash if last else GENESIS_HASH


def create_block(db: Session, source: str, command: str, entity: str, params: dict) -> models.LedgerBlock:
    with _chain_lock:
        prev_hash = _latest_hash(db)
        preimage, hash_hex = compute_hash(source, command, entity, params, prev_hash)
        tx_hash, onchain_index, anchor_error = anchor_on_chain(hash_hex, prev_hash)

        block = models.LedgerBlock(
            source=source, command=command, entity=entity,
            params_json=json.dumps(params),
            prev_hash=prev_hash, onchain_hash=hash_hex, preimage=preimage,
            tx_hash=tx_hash, onchain_index=onchain_index, anchor_error=anchor_error,
            offchain_command=command, offchain_params_json=json.dumps(params),
        )
        db.add(block)
        db.commit()
        db.refresh(block)
        return block


def to_out(block: models.LedgerBlock) -> schemas.BlockOut:
    offchain_hash = recompute_offchain_hash(block)
    return schemas.BlockOut(
        id=block.id, ts=block.ts, source=block.source, command=block.command, entity=block.entity,
        params=json.loads(block.params_json), prev_hash=block.prev_hash, onchain_hash=block.onchain_hash,
        preimage=block.preimage, tx_hash=block.tx_hash, onchain_index=block.onchain_index,
        anchor_error=block.anchor_error, offchain_command=block.offchain_command,
        offchain_params=json.loads(block.offchain_params_json), offchain_hash=offchain_hash,
        tampered=(offchain_hash != block.onchain_hash),
    )


@router.post("/blocks", response_model=schemas.BlockOut)
def post_block(payload: schemas.BlockCreate, db: Session = Depends(get_db)):
    block = create_block(db, payload.source, payload.command, payload.entity, payload.params)
    return to_out(block)


@router.get("/blocks", response_model=list[schemas.BlockOut])
def list_blocks(db: Session = Depends(get_db)):
    blocks = db.query(models.LedgerBlock).order_by(models.LedgerBlock.id).all()
    return [to_out(b) for b in blocks]


@router.get("/blocks/{block_id}", response_model=schemas.BlockOut)
def get_block(block_id: int, db: Session = Depends(get_db)):
    block = db.query(models.LedgerBlock).filter(models.LedgerBlock.id == block_id).first()
    if not block:
        raise HTTPException(404, "Block not found")
    return to_out(block)


@router.post("/blocks/{block_id}/tamper", response_model=schemas.BlockOut)
def tamper_block(block_id: int, payload: schemas.TamperRequest, db: Session = Depends(get_db)):
    """Simulates an attacker rewriting the off-chain historian record.
    The on-chain hash remains immutable — this is what makes the mismatch detectable."""
    block = db.query(models.LedgerBlock).filter(models.LedgerBlock.id == block_id).first()
    if not block:
        raise HTTPException(404, "Block not found")
    block.offchain_command = payload.offchain_command
    block.offchain_params_json = json.dumps(payload.offchain_params)
    db.commit()
    db.refresh(block)
    return to_out(block)


@router.get("/verify", response_model=schemas.VerifyResult)
def verify_chain(db: Session = Depends(get_db)):
    """Checks per-block tamper AND chain-continuity (prevHash linkage).
    Chain forks from concurrent block creation are caught by (2), not (1)."""
    blocks = db.query(models.LedgerBlock).order_by(models.LedgerBlock.id).all()
    tampered = [b.id for b in blocks if is_tampered(b)]

    broken_links = []
    for i in range(1, len(blocks)):
        if blocks[i].prev_hash != blocks[i - 1].onchain_hash:
            broken_links.append(blocks[i].id)

    mismatches = sorted(set(tampered) | set(broken_links))
    return schemas.VerifyResult(chain_length=len(blocks), chain_verified=not mismatches, mismatches=mismatches)
