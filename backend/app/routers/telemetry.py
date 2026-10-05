"""Telemetry evaluation and anomaly listing router."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db_sql import get_db
from ..anomaly import evaluate

router = APIRouter(tags=["anomaly"])


@router.post("/telemetry/evaluate", response_model=schemas.TelemetryEval)
def evaluate_telemetry(payload: schemas.TelemetryIn):
    result = evaluate(payload.pressure, payload.temp, payload.vibration)
    return schemas.TelemetryEval(**result)


@router.get("/anomalies", response_model=list[schemas.AnomalyOut])
def list_anomalies(db: Session = Depends(get_db)):
    rows = db.query(models.Anomaly).order_by(models.Anomaly.id).all()
    return rows
