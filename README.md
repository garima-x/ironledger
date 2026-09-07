# 🛡️ IronLedger - Blockchain-Anchored ICS Digital Forensics & Attribution Framework

IronLedger solves a fundamental vulnerability in Industrial Control Systems (ICS / SCADA): when an adversary breaches an operational technology network, they can easily tamper with, forge, or delete local audit logs, blinding forensic investigators.

IronLedger anchors all sensor states, setpoint modifications, and control messages onto an immutable blockchain ledger (Ethereum Sepolia). When anomalous behavior is flagged by our dual-layer detection engine (Physics Envelopes + ML Isolation Forest), IronLedger traverses the ledger backwards, reconstructs the authentic timeline, exposes any database tampering, and correlates signatures with the MITRE ATT&CK for ICS matrix to generate attribution hypotheses.

---

## 🚀 Quickstart

```bash
cd /Users/simrankumari/.gemini/antigravity-ide/scratch/ironledger
python3 run.py
```
Open **http://localhost:8080** in your browser.

---

## 🏗️ Architecture & Modules

1. **ICS Simulation Layer (`backend/simulator.py`)**:
   - High-fidelity physical simulation of centrifugal pumps, pressurized reactors, inlet/vent control valves, and a Triconex Safety Instrumented System (SIS).
   - Pre-configured attack injection: Triton/HatMan (SIS defeat), Stuxnet (frequency cycling), Industroyer2 (overpressure), and Log Tampering.

2. **Blockchain Evidence Layer (`contracts/IronLedger.sol`, `backend/blockchain.py`)**:
   - Solidity 0.8.20 smart contract for Sepolia testnet and Remix IDE.
   - Computes deterministic SHA-256 state hashes: `H(source, command, entity, params, prevHash)`.
   - Tamper-detection engine: compares off-chain database metadata against on-chain hashes.

3. **Dual-Layer Anomaly Detection (`backend/anomaly_detector.py`)**:
   - Hard physics thresholds (vessel pressure > 9.5 bar, temperature > 95 °C, rotor vibration > 5.5 mm/s, contradictory valve closures).
   - Machine Learning: scikit-learn `IsolationForest` trained on baseline normal operational telemetry.

4. **Forensic Reconstruction & MITRE ATT&CK for ICS (`backend/forensics.py`, `backend/threat_intel.py`)**:
   - Backward-walk algorithm traversing ledger backwards from anomaly to pinpoint root-cause entry commands.
   - MITRE ATT&CK for ICS technique mapping (`T0855`, `T0836`, `T0831`, `T0888`, `T0879`, `T0815`).
   - Threat actor attribution scoring (Xenotime, Sandworm, Equation Group, Volt Typhoon).

5. **Court-Ready Report Generator (`backend/report_generator.py`)**:
   - Generates compliant, printable HTML/PDF forensic reports with cryptographic chain-of-custody.

---

## 🎬 Live 3-Act Demo Walkthrough

1. **Act 1: Normal Baseline**
   - Click `Act 1 (Normal Baseline)`: SCADA plant operates smoothly within safe green envelopes; every command is hashed and anchored.
2. **Act 2: Attack Injection (Triton / HatMan)**
   - Click `Act 2 (Attack Injection)`: SIS interlock bypass is engaged, vent relief valve is clamped shut, temperature and pressure spike into critical alarm states, and Isolation Forest ML score surges.
3. **Act 3: Log Tampering & Blockchain Proof**
   - Click `Act 3 (Log Tamper & Blockchain Proof)`: Attacker alters local database records to fake a benign maintenance ping. IronLedger immediately triggers a cryptographic hash mismatch alert!
4. **Act 4: Reconstruct Timeline & Generate Report**
   - Click `Act 4 (Reconstruct Timeline)`: The backward-walk algorithm reconstructs the chronological progression, pinpoints the root-cause entry account, attributes the incident to **Xenotime**, and opens the court-admissible forensic report.
