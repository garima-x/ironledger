"""ICS simulation routing (garima's version)."""
import random
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..db_sql import get_db
from .ledger import create_block
from ..forensics import backward_walk, attribution

router = APIRouter(prefix="/simulate", tags=["simulate"])

_sim = {"act": 0, "root_block_id": None, "valve_block_id": None, "alarm_block_id": None}


def _act1(db: Session):
    sources = ["PLC-04 Pump Skid", "RTU-07 Reactor", "HMI-02 Control Room"]
    for i in range(12):
        pressure = round(6 + random.random() * 0.6, 2)
        temp = round(69 + random.random() * 4, 1)
        vibration = round(2 + random.random() * 0.5, 2)
        create_block(db, sources[i % len(sources)], "TELEMETRY_REPORT", "REACTOR-01",
                     {"pressure": pressure, "temp": temp, "vibration": vibration})


def _add_anomaly(db, block_id, severity, title, desc, technique=None, ml_score=None):
    db.add(models.Anomaly(block_id=block_id, severity=severity, title=title,
                           description=desc, technique=technique, ml_score=ml_score))
    db.commit()


def _act2(db: Session):
    interlock_block = create_block(db, "RTU-07 Reactor", "DISABLE_INTERLOCK", "SIS-TRICONEX-1",
                                    {"reason": "diagnostic override", "authorized": False})
    _sim["root_block_id"] = interlock_block.id
    _add_anomaly(db, interlock_block.id, "critical", "Safety interlock disabled without authorization",
                 "SIS-TRICONEX-1 interlock bypassed via unauthorized command message.", "T0855")
    _add_anomaly(db, interlock_block.id, "critical", "Unauthorized manipulation of SIS control logic",
                 "Command pattern matches direct manipulation of safety control, not a diagnostic routine.", "T0831")

    valve_block = create_block(db, "PLC-12 Vent Skid", "SET_VALVE", "VENT-RELIEF-VALVE",
                                {"position": "CLOSED", "override": True})
    _sim["valve_block_id"] = valve_block.id
    _add_anomaly(db, valve_block.id, "critical", "Vent relief valve forced closed",
                 "Parameter override clamps the relief valve shut during active pressurization.", "T0836")

    last_block = valve_block
    for i in range(5):
        pressure = round(9.6 + i * 0.3 + random.random() * 0.2, 2)
        temp = round(96 + i * 1.4 + random.random(), 1)
        vibration = round(5.6 + i * 0.15, 2)
        last_block = create_block(db, "RTU-07 Reactor", "TELEMETRY_REPORT", "REACTOR-01",
                                   {"pressure": pressure, "temp": temp, "vibration": vibration})
    from ..anomaly import evaluate
    ev = evaluate(pressure, temp, vibration)
    _add_anomaly(db, last_block.id, "critical", "Physics envelope breach — overpressure & overtemperature",
                 f"Pressure {pressure} bar / temp {temp} °C exceed hard safety thresholds.", None)
    _add_anomaly(db, last_block.id, "critical", "Isolation Forest flags multivariate outlier",
                 f"ML anomaly score {ev['ml_score']} — telemetry pattern deviates from learned baseline.",
                 None, ml_score=ev["ml_score"])

    alarm_block = create_block(db, "HMI-02 Control Room", "SUPPRESS_ALARM", "ALARM-PANEL-3",
                                {"channel": "HIGH-PRESSURE", "duration_min": 30})
    _sim["alarm_block_id"] = alarm_block.id
    _add_anomaly(db, alarm_block.id, "warning", "Operator alarm suppressed on high-pressure channel",
                 "Alarm panel visibility disabled for 30 minutes during active excursion.", "T0815")


def _act3(db: Session):
    valve_id = _sim["valve_block_id"]
    block = db.query(models.LedgerBlock).filter(models.LedgerBlock.id == valve_id).first()
    import json
    block.offchain_command = "HEARTBEAT_PING"
    block.offchain_params_json = json.dumps({"status": "benign maintenance ping"})
    db.commit()
    _add_anomaly(db, valve_id, "critical", f"Hash mismatch on block #{valve_id}",
                 "Off-chain historian record was rewritten to disguise the valve-closure command as a routine "
                 "heartbeat — recomputed hash no longer matches the on-chain anchor.", "T0879")
    _add_anomaly(db, valve_id, "warning", "Historian schema reconnaissance inferred",
                 "The tamper method implies prior discovery of the historian's record schema.", "T0888")


def _act4(db: Session):
    return backward_walk(db, _sim["alarm_block_id"])


@router.post("/act/{n}")
def run_act(n: int, db: Session = Depends(get_db)):
    if n < 1 or n > 4:
        raise HTTPException(400, "Act must be between 1 and 4")
    runners = {1: _act1, 2: _act2, 3: _act3, 4: _act4}
    result = None
    for step in range(_sim["act"] + 1, n + 1):
        result = runners[step](db)
    _sim["act"] = max(_sim["act"], n)

    response = {"act": _sim["act"]}
    if n == 4:
        scores, leader, tied_with = attribution(db)
        response["forensics"] = result
        response["attribution"] = {"scores": scores, "leader": leader, "tied_with": tied_with}
    return response


@router.post("/reset")
def reset(db: Session = Depends(get_db)):
    db.query(models.Anomaly).delete()
    db.query(models.LedgerBlock).delete()
    db.commit()
    _sim.update({"act": 0, "root_block_id": None, "valve_block_id": None, "alarm_block_id": None})
    return {"status": "reset"}


@router.get("/state")
def get_state():
    return _sim
