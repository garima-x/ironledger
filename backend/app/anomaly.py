"""
Dual-layer anomaly detection (garima's clean version):
  1. Hard physics envelopes (pressure / temp / vibration / SIS valve consistency)
  2. scikit-learn IsolationForest trained on nominal baseline
"""
import numpy as np
from sklearn.ensemble import IsolationForest

# ── Physics thresholds ────────────────────────────────────────────────────────
THRESHOLDS = {
    "pressure":  (3.0, 9.5),   # bar
    "temp":      (40.0, 95.0), # °C
    "vibration": (0.5, 5.5),   # mm/s
}

# ── IsolationForest — trained once at module load on synthetic normal data ────
_rng = np.random.default_rng(42)
_normal = np.column_stack([
    _rng.normal(6.0, 0.5,  800),   # pressure
    _rng.normal(70.0, 3.0, 800),   # temp
    _rng.normal(2.3, 0.4,  800),   # vibration
])
_model = IsolationForest(contamination=0.05, random_state=42)
_model.fit(_normal)


def evaluate(pressure: float, temp: float, vibration: float) -> dict:
    """
    Returns:
      physics_breach: list of parameter names that exceed safe limits
      ml_score:       IsolationForest decision score (lower = more anomalous)
      is_anomaly:     True when either layer fires
    """
    breaches = []
    for name, (lo, hi) in THRESHOLDS.items():
        val = {"pressure": pressure, "temp": temp, "vibration": vibration}[name]
        if not (lo <= val <= hi):
            breaches.append(name)

    sample = np.array([[pressure, temp, vibration]])
    score = float(_model.decision_function(sample)[0])
    ml_anomaly = _model.predict(sample)[0] == -1

    return {
        "physics_breach": breaches,
        "ml_score": round(score, 4),
        "is_anomaly": bool(breaches or ml_anomaly),
    }
