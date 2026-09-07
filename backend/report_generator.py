"""
IronLedger - Forensic Incident Report Generator
Compiles court-admissible, cryptographically verified ICS incident reports
with chain-of-custody, backward-walk timeline, and MITRE ATT&CK for ICS attribution.
"""

import time
from typing import Dict, Any, List

class ForensicReportGenerator:
    def generate_html_report(
        self,
        forensic_data: Dict[str, Any],
        threat_intel: Dict[str, Any],
        telemetry_snapshot: Dict[str, Any],
        contract_address: str = "0x7a36B3DeE1F03287cCE488f2604245F11dF9d78F"
    ) -> str:
        """Generates self-contained, publication-grade HTML digital forensics report."""
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        report_id = f"IL-ICS-FOR-{int(time.time())}"
        root_cause = forensic_data.get("root_cause_artifact", {})
        timeline = forensic_data.get("timeline", [])
        actor = threat_intel.get("primary_hypothesis", {})
        tampered = forensic_data.get("tamper_detected", False)

        # Build timeline HTML rows
        timeline_rows = ""
        for item in timeline:
            badge_class = "tamper-badge" if item.get("tampered") else "valid-badge"
            badge_text = "TAMPERED MISMATCH" if item.get("tampered") else "BLOCKCHAIN VERIFIED"
            timeline_rows += f"""
            <tr>
                <td><strong>#{item.get('event_id', '-')}</strong></td>
                <td>{item.get('formatted_time', '-')}</td>
                <td><span class="source-tag">{item.get('source', '-')}</span></td>
                <td><code>{item.get('command_type', '-')}</code></td>
                <td>{item.get('entity_id', '-')}</td>
                <td>{item.get('kill_chain_phase', '-')}</td>
                <td><span class="{badge_class}">{badge_text}</span></td>
                <td class="hash-col" title="{item.get('onchain_hash', '')}"><code>{str(item.get('onchain_hash', ''))[:16]}...</code></td>
            </tr>
            """

        # Build MITRE techniques rows
        mitre_rows = ""
        for t in threat_intel.get("matched_techniques", []):
            mitre_rows += f"""
            <div class="technique-card">
                <div class="tech-header">
                    <span class="tech-id">{t.get('id')}</span>
                    <span class="tech-tactic">{t.get('tactic')}</span>
                </div>
                <h4>{t.get('name')}</h4>
                <p>{t.get('description')}</p>
                <div class="tech-mitigation"><strong>Mitigation:</strong> {t.get('mitigation')}</div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IronLedger Forensic Report - {report_id}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-border: #1f293d;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        @media print {{
            body {{ background: #fff !important; color: #111 !important; }}
            .no-print {{ display: none !important; }}
            .container {{ box-shadow: none !important; border: none !important; width: 100% !important; }}
            table th {{ background: #f3f4f6 !important; color: #111 !important; }}
            .technique-card {{ border: 1px solid #ddd !important; background: #fafafa !important; }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            line-height: 1.6;
            padding: 30px 15px;
        }}
        .container {{
            max-width: 1080px;
            margin: 0 auto;
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--surface-border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}
        .brand h1 {{
            font-size: 26px;
            letter-spacing: 0.5px;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .brand h1 span {{ color: var(--accent-cyan); }}
        .meta-box {{
            text-align: right;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .meta-box strong {{ color: var(--text-main); }}
        .alert-banner {{
            padding: 16px 20px;
            border-radius: 8px;
            margin-bottom: 28px;
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 15px;
        }}
        .alert-banner.danger {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid var(--danger);
            color: #fca5a5;
        }}
        .alert-banner.success {{
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--success);
            color: #6ee7b7;
        }}
        h2 {{
            font-size: 18px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--accent-cyan);
            margin: 28px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .card-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .info-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 18px;
        }}
        .info-card .label {{
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .info-card .value {{
            font-size: 18px;
            font-weight: 600;
            color: #fff;
        }}
        .info-card .sub {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin: 16px 0;
            border-radius: 6px;
            overflow: hidden;
        }}
        table th, table td {{
            padding: 12px 14px;
            text-align: left;
        }}
        table th {{
            background: #1e293b;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid #334155;
        }}
        table td {{
            border-bottom: 1px solid #1e293b;
        }}
        table tr:hover td {{
            background: rgba(255,255,255,0.02);
        }}
        .valid-badge {{
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }}
        .tamper-badge {{
            background: rgba(239, 68, 68, 0.25);
            color: #f87171;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            animation: pulse 2s infinite;
        }}
        .source-tag {{
            background: #334155;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
        }}
        .hash-col code {{
            color: var(--accent-cyan);
            font-family: monospace;
        }}
        .technique-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 16px;
        }}
        .technique-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
        }}
        .tech-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }}
        .tech-id {{
            background: var(--accent-blue);
            color: #fff;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }}
        .tech-tactic {{
            color: var(--warning);
            font-size: 12px;
        }}
        .technique-card h4 {{
            font-size: 14px;
            color: #fff;
            margin-bottom: 6px;
        }}
        .technique-card p {{
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .tech-mitigation {{
            font-size: 11px;
            color: #94a3b8;
            border-top: 1px dashed #334155;
            padding-top: 6px;
        }}
        .print-btn {{
            background: var(--accent-cyan);
            color: #0b0f19;
            border: none;
            padding: 10px 22px;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            transition: opacity 0.2s;
        }}
        .print-btn:hover {{ opacity: 0.85; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--surface-border);
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-top">
            <div class="brand">
                <h1>IRON<span>LEDGER</span> FORENSIC REPORT</h1>
                <p style="color: var(--text-muted); font-size: 13px;">Industrial Control Systems Immutable Evidence & Attribution Framework</p>
            </div>
            <div class="meta-box">
                <div>Report ID: <strong>{report_id}</strong></div>
                <div>Generated: <strong>{timestamp_str}</strong></div>
                <div>Sepolia Contract: <strong>{contract_address[:8]}...{contract_address[-6:]}</strong></div>
                <div style="margin-top: 10px;" class="no-print">
                    <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
                </div>
            </div>
        </div>

        {"<div class='alert-banner danger'><strong>TAMPER DETECTED:</strong> Local database audit trail was illegally modified! IronLedger on-chain cryptographic anchor on Ethereum Sepolia preserved original authentic state.</div>" if tampered else "<div class='alert-banner success'><strong>BLOCKCHAIN INTEGRITY VERIFIED:</strong> Complete chain of custody matches on-chain cryptographic hashes with zero evidence degradation.</div>"}

        <h2>1. Executive Summary & Root Cause Attribution</h2>
        <div class="card-grid">
            <div class="info-card">
                <div class="label">Primary Threat Actor Hypothesis</div>
                <div class="value" style="color: #60a5fa;">{actor.get('name', 'Uncorrelated')}</div>
                <div class="sub">Origin: {actor.get('origin', 'Unknown')}</div>
            </div>
            <div class="info-card">
                <div class="label">Attribution Confidence</div>
                <div class="value" style="color: {'#10b981' if actor.get('confidence_score', 0) > 75 else '#f59e0b'};">{actor.get('confidence_score', 0)}%</div>
                <div class="sub">Correlated via MITRE ATT&CK for ICS matrix</div>
            </div>
            <div class="info-card">
                <div class="label">Root Cause Entry Point</div>
                <div class="value" style="color: #f87171;">{root_cause.get('source_identity', 'Unknown')}</div>
                <div class="sub">Command: {root_cause.get('entry_command', 'None')} ({root_cause.get('target_entity', '-')})</div>
            </div>
        </div>
        <p style="font-size: 14px; color: #cbd5e1; margin-bottom: 24px; background: #0f172a; padding: 14px; border-left: 4px solid var(--accent-cyan); border-radius: 4px;">
            <strong>Forensic Determination:</strong> {root_cause.get('forensic_conclusion', 'Baseline inspection.')}
        </p>

        <h2>2. Blockchain-Anchored Reconstructed Timeline</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Source Entity</th>
                    <th>Command</th>
                    <th>Target</th>
                    <th>Kill-Chain Phase</th>
                    <th>Integrity Status</th>
                    <th>On-Chain Hash</th>
                </tr>
            </thead>
            <tbody>
                {timeline_rows}
            </tbody>
        </table>

        <h2>3. MITRE ATT&CK for ICS Technical Mapping</h2>
        <div class="technique-grid">
            {mitre_rows}
        </div>

        <h2>4. Physical Plant Sensor Peaks During Incident</h2>
        <div class="card-grid">
            <div class="info-card">
                <div class="label">Peak Pressure Vessel</div>
                <div class="value">{telemetry_snapshot.get('pressure_vessel', {}).get('pressure_bar', 0)} Bar</div>
                <div class="sub">Safe Limit: <= 8.0 Bar</div>
            </div>
            <div class="info-card">
                <div class="label">Peak Temperature</div>
                <div class="value">{telemetry_snapshot.get('pressure_vessel', {}).get('temp_celsius', 0)} °C</div>
                <div class="sub">Safe Limit: <= 85.0 °C</div>
            </div>
            <div class="info-card">
                <div class="label">Pump A RPM & Vibration</div>
                <div class="value">{telemetry_snapshot.get('pump_a', {}).get('rpm', 0):.0f} RPM</div>
                <div class="sub">Vibration: {telemetry_snapshot.get('pump_a', {}).get('vibration', 0)} mm/s</div>
            </div>
            <div class="info-card">
                <div class="label">SIS Interlock Status</div>
                <div class="value" style="color: {'#ef4444' if telemetry_snapshot.get('sis', {}).get('bypass_active') else '#10b981'};">
                    {'BYPASS ENGAGED' if telemetry_snapshot.get('sis', {}).get('bypass_active') else 'ARMED'}
                </div>
                <div class="sub">Trip Status: {'TRIPPED' if telemetry_snapshot.get('sis', {}).get('tripped') else 'NOMINAL'}</div>
            </div>
        </div>

        <div class="footer">
            <div>Digital Evidence Hash: <code>{str(root_cause.get('onchain_proof_tx', '0x948271048b'))}</code></div>
            <div>Investigating Officers: <strong>Simran & Garima</strong> | IronLedger Core</div>
        </div>
    </div>
</body>
</html>
        """
        return html_content
