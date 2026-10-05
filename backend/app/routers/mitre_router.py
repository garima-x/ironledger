"""MITRE ATT&CK for ICS router — technique list and full matrix."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import schemas
from ..db_sql import get_db
from ..forensics import compute_mitre_hits
from ..threat_intel import MITRE_TECHNIQUES
from ..mitre_matrix import FULL_ICS_MATRIX, is_hit

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/techniques", response_model=list[schemas.MitreTechniqueOut])
def list_techniques(db: Session = Depends(get_db)):
    hits = compute_mitre_hits(db)
    return [
        schemas.MitreTechniqueOut(id=t["id"], name=t["name"], tactic=t["tactic"], hit=t["id"] in hits)
        for t in MITRE_TECHNIQUES
    ]


@router.get("/matrix", response_model=list[schemas.MitreMatrixTacticOut])
def full_matrix(db: Session = Depends(get_db)):
    """Returns the complete ATT&CK for ICS matrix (all 12 tactics, 79 techniques)
    with each technique tagged hit=True if observed in current session."""
    hits = compute_mitre_hits(db)
    result = []
    for tactic, techniques in FULL_ICS_MATRIX:
        result.append(schemas.MitreMatrixTacticOut(
            tactic=tactic,
            techniques=[
                schemas.MitreTechniqueOut(id=tid, name=tname, tactic=tactic, hit=is_hit(tid, hits))
                for tid, tname in techniques
            ],
        ))
    return result
