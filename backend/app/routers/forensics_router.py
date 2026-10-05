"""Forensic reconstruction and attribution router (with tied-leader support)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import schemas
from ..db_sql import get_db
from ..forensics import backward_walk, attribution

router = APIRouter(prefix="/forensics", tags=["forensics"])


@router.post("/reconstruct", response_model=schemas.ReconstructResult)
def reconstruct(payload: schemas.ReconstructRequest, db: Session = Depends(get_db)):
    steps = backward_walk(db, payload.start_block_id)
    scores, leader, tied_with = attribution(db)
    return schemas.ReconstructResult(
        steps=[schemas.ForensicStep(**s) for s in steps],
        attribution=schemas.AttributionOut(scores=scores, leader=leader, tied_with=tied_with),
    )


@router.get("/attribution", response_model=schemas.AttributionOut)
def get_attribution(db: Session = Depends(get_db)):
    scores, leader, tied_with = attribution(db)
    return schemas.AttributionOut(scores=scores, leader=leader, tied_with=tied_with)
