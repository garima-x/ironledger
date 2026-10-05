"""
IronLedger - Dual-Layer ICS Anomaly Detection Engine
Combines physics safety envelopes (deterministic rule-based thresholds)
with an unsupervised Machine Learning model (Isolation Forest) for multi-variate drift detection.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List, Tuple

class AnomalyDetector:
    def __init__(self):
        self.ml_model = IsolationForest(
            n_estimators=100,
            contamination=0.03,
            random_state=42
        )
        self.is_trained = False
        self._train_baseline_model()

    def _generate_normal_baseline(self, num_samples: int = 1500) -> np.ndarray:
        """Generates synthetic baseline telemetry reflecting normal SCADA operation."""
        np.random.seed(42)
        # Features: [pump_rpm, vibration, flow_rate, pressure_bar, temp_celsius, vent_valve_pct]
        rpm = np.random.normal(2400.0, 75.0, num_samples)
        rpm = np.clip(rpm, 2100.0, 2700.0)

        vib = 1.6 + (rpm / 2400.0) * 0.4 + np.random.normal(0, 0.15, num_samples)
        vib = np.clip(vib, 1.1, 2.5)

        flow = (rpm / 2400.0) * 85.0 * 0.75 + np.random.normal(0, 1.5, num_samples)
        flow = np.clip(flow, 55.0, 95.0)

        pressure = 5.2 + np.random.normal(0, 0.4, num_samples)
        pressure = np.clip(pressure, 3.8, 7.0)

        temp = 68.0 + (pressure - 5.0) * 3.0 + np.random.normal(0, 1.2, num_samples)
        temp = np.clip(temp, 58.0, 78.0)

        vent = np.random.normal(15.0, 2.0, num_samples)
        vent = np.clip(vent, 10.0, 25.0)

        X = np.column_stack([rpm, vib, flow, pressure, temp, vent])
        return X

    def _train_baseline_model(self):
        """Fits the Isolation Forest on the nominal operation envelope."""
        X_train = self._generate_normal_baseline()
        self.ml_model.fit(X_train)
        self.is_trained = True

    def extract_features(self, snapshot: Dict[str, Any]) -> np.ndarray:
        """Extracts numerical vector for ML inference."""
        pump_a = snapshot.get("pump_a", {})
        vessel = snapshot.get("pressure_vessel", {})
        valve_vent = snapshot.get("valve_vent", {})

        rpm = float(pump_a.get("rpm", 2400.0))
        vib = float(pump_a.get("vibration", 1.8))
        flow = float(pump_a.get("flow_rate", 85.0))
        pressure = float(vessel.get("pressure_bar", 5.4))
        temp = float(vessel.get("temp_celsius", 68.5))
        vent = float(valve_vent.get("open_percent", 15.0))

        return np.array([[rpm, vib, flow, pressure, temp, vent]])

    def evaluate_telemetry(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs dual-layer anomaly detection:
        1. Physics envelope checks
        2. Isolation Forest score
        """
        pump_a = snapshot.get("pump_a", {})
        vessel = snapshot.get("pressure_vessel", {})
        valve_vent = snapshot.get("valve_vent", {})
        sis = snapshot.get("sis", {})

        rule_violations = []
        flagged_sensors = []
        severity = "NORMAL"

        # 1. Physics Envelope Threshold Rules
        pressure = vessel.get("pressure_bar", 5.4)
        if pressure >= 10.0:
            rule_violations.append(f"CRITICAL: Vessel pressure at {pressure} bar exceeds rupture envelope (>=10 bar)")
            flagged_sensors.append("PRESSURE_VESSEL_PRESSURE")
            severity = "CATASTROPHIC"
        elif pressure >= 8.0:
            rule_violations.append(f"WARNING: Vessel pressure elevated at {pressure} bar (Safe max: 8.0 bar)")
            flagged_sensors.append("PRESSURE_VESSEL_PRESSURE")
            if severity == "NORMAL": severity = "WARNING"

        temp = vessel.get("temp_celsius", 68.5)
        if temp >= 95.0:
            rule_violations.append(f"CRITICAL: Vessel temperature at {temp} °C exceeds thermal runaway threshold (>=95 °C)")
            flagged_sensors.append("VESSEL_TEMPERATURE")
            severity = "CATASTROPHIC"
        elif temp >= 85.0:
            rule_violations.append(f"WARNING: Vessel temperature high at {temp} °C (Safe max: 85.0 °C)")
            flagged_sensors.append("VESSEL_TEMPERATURE")
            if severity == "NORMAL": severity = "WARNING"

        rpm = pump_a.get("rpm", 2400.0)
        if rpm >= 3400.0:
            rule_violations.append(f"CRITICAL: Pump RPM {rpm:.1f} exceeding mechanical safety redline (3400 RPM)")
            flagged_sensors.append("PUMP_A_RPM")
            if severity not in ["CATASTROPHIC"]: severity = "CRITICAL"
        elif rpm >= 3000.0:
            rule_violations.append(f"WARNING: Pump RPM elevated at {rpm:.1f} (Safe max: 3000 RPM)")
            flagged_sensors.append("PUMP_A_RPM")
            if severity == "NORMAL": severity = "WARNING"

        vibration = pump_a.get("vibration", 1.8)
        if vibration >= 5.5:
            rule_violations.append(f"CRITICAL: Rotor vibration {vibration} mm/s indicates severe mechanical resonance")
            flagged_sensors.append("PUMP_A_VIBRATION")
            if severity not in ["CATASTROPHIC"]: severity = "CRITICAL"

        # Contradictory Physical States
        vent_pct = valve_vent.get("open_percent", 15.0)
        if vent_pct < 2.0 and rpm > 3200.0:
            rule_violations.append("CONTRADICTION: Relief vent fully closed during maximum pump throughput!")
            flagged_sensors.append("VALVE_VENT_POSITION")
            if severity == "NORMAL": severity = "WARNING"

        if sis.get("bypass_active", False):
            rule_violations.append("SECURITY ALERT: Safety Instrumented System (SIS) logic bypass engaged!")
            flagged_sensors.append("SIS_INTERLOCK")
            severity = "CRITICAL"

        # 2. Machine Learning Layer (Isolation Forest)
        features = self.extract_features(snapshot)
        raw_score = self.ml_model.decision_function(features)[0] # higher = more normal, lower/negative = anomalous
        # Normalize score into [0.0 = completely nominal, 1.0 = highly anomalous]
        # In sklearn, decision_function ~ 0.15 is normal, < 0.0 is anomalous
        normalized_anomaly = float(np.clip(0.5 - (raw_score * 2.0), 0.0, 1.0))
        ml_prediction = self.ml_model.predict(features)[0] # -1 for anomaly, 1 for normal

        is_ml_anomaly = (ml_prediction == -1 or normalized_anomaly >= 0.65)
        if is_ml_anomaly and not rule_violations:
            rule_violations.append(f"ML ADVISORY: Multivariate telemetry drift detected by Isolation Forest (score: {normalized_anomaly:.2f})")
            if severity == "NORMAL": severity = "WARNING"

        is_anomaly = len(rule_violations) > 0 or is_ml_anomaly

        return {
            "is_anomaly": is_anomaly,
            "severity": severity,
            "rule_violations": rule_violations,
            "flagged_sensors": list(set(flagged_sensors)),
            "ml_anomaly_score": round(normalized_anomaly, 3),
            "ml_prediction": "ANOMALY" if is_ml_anomaly else "NORMAL"
        }
