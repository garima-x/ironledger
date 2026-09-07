/**
 * IronLedger - Industrial Cyber Defense Command Center Logic
 * Handles real-time SCADA telemetry, SVG animations, attack triggers,
 * blockchain evidence streaming, tamper detection, and forensic reconstruction.
 */

let state = {
    pollingInterval: null,
    lastSnapshot: null,
    isTamperedDemo: false,
    walletConnected: true,
    activeScenario: null
};

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    startTelemetryPolling();
    fetchBlockchainBlocks();
});

// Telemetry Polling Loop
function startTelemetryPolling() {
    updateDashboard();
    state.pollingInterval = setInterval(updateDashboard, 1200);
}

async function updateDashboard() {
    try {
        const res = await fetch("/api/telemetry");
        if (!res.ok) return;
        const data = await res.json();
        state.lastSnapshot = data;

        renderSCADASchematic(data.telemetry);
        renderInstrumentGauges(data.telemetry);
        renderAnomalyEngine(data.anomaly);
        renderRecentBlocks(data.recent_blocks);
    } catch (err) {
        console.warn("Telemetry polling error:", err);
    }
}

// 1. Render SCADA Synoptic SVG
function renderSCADASchematic(telemetry) {
    if (!telemetry) return;
    const { pump_a, valve_inlet, valve_vent, pressure_vessel, sis } = telemetry;

    // Pump A Dynamics & Impeller
    const impeller = document.getElementById("pump-impeller");
    const rpmText = document.getElementById("svg-pump-rpm-txt");
    if (rpmText) rpmText.textContent = `${Math.round(pump_a.rpm)} RPM`;

    if (impeller) {
        if (pump_a.state === "RUNNING" && pump_a.rpm > 100) {
            const duration = Math.max(0.2, 1.6 - (pump_a.rpm / 3600));
            impeller.style.animation = `spinImpeller ${duration}s linear infinite`;
        } else {
            impeller.style.animation = "none";
        }
    }

    // Pipes Flow Animations
    const flowInlet = document.getElementById("flow-inlet");
    const flowMid = document.getElementById("flow-mid");
    const flowVent = document.getElementById("flow-vent");
    const flowOutlet = document.getElementById("flow-outlet");

    const isFlowing = pump_a.state === "RUNNING" && pump_a.rpm > 200;
    [flowInlet, flowMid, flowOutlet].forEach(pipe => {
        if (pipe) pipe.style.display = isFlowing ? "block" : "none";
    });

    if (flowVent) {
        flowVent.style.display = (valve_vent.open_percent > 2.0 && pressure_vessel.pressure_bar > 2.0) ? "block" : "none";
    }

    // Vessel Readings & Fluid
    const txtPressure = document.getElementById("svg-vessel-pressure");
    const txtTemp = document.getElementById("svg-vessel-temp");
    const vesselBorder = document.getElementById("vessel-border");
    const vesselFluid = document.getElementById("vessel-fluid");

    if (txtPressure) txtPressure.textContent = `${pressure_vessel.pressure_bar.toFixed(1)} Bar`;
    if (txtTemp) txtTemp.textContent = `${pressure_vessel.temp_celsius.toFixed(1)} °C`;

    // Visual Stress Alert on Vessel
    if (vesselBorder && vesselFluid) {
        if (pressure_vessel.pressure_bar >= 9.5 || pressure_vessel.temp_celsius >= 95.0) {
            vesselBorder.setAttribute("stroke", "#ef4444");
            vesselBorder.setAttribute("stroke-width", "3.5");
            vesselFluid.setAttribute("fill", "rgba(239, 68, 68, 0.4)");
        } else if (pressure_vessel.pressure_bar >= 8.0 || pressure_vessel.temp_celsius >= 85.0) {
            vesselBorder.setAttribute("stroke", "#f59e0b");
            vesselBorder.setAttribute("stroke-width", "2.5");
            vesselFluid.setAttribute("fill", "rgba(245, 158, 11, 0.3)");
        } else {
            vesselBorder.setAttribute("stroke", "#38bdf8");
            vesselBorder.setAttribute("stroke-width", "2.5");
            vesselFluid.setAttribute("fill", "rgba(6, 182, 212, 0.25)");
        }
    }

    // Vent Valve Position
    const ventLabel = document.getElementById("svg-vent-label");
    const ventCirc = document.getElementById("vent-circ");
    const ventPolyL = document.getElementById("vent-poly-l");
    const ventPolyR = document.getElementById("vent-poly-r");
    if (ventLabel) ventLabel.textContent = `VENT-02 (${Math.round(valve_vent.open_percent)}%)`;

    const ventColor = valve_vent.open_percent < 5.0 ? "#ef4444" : "#10b981";
    if (ventCirc) ventCirc.setAttribute("fill", ventColor);
    if (ventPolyL) ventPolyL.setAttribute("fill", ventColor);
    if (ventPolyR) ventPolyR.setAttribute("fill", ventColor);

    // SIS Interlock
    const sisLed = document.getElementById("sis-led");
    const sisTitle = document.getElementById("sis-title");
    const sisBorder = document.getElementById("sis-border");
    if (sis.bypass_active) {
        if (sisLed) sisLed.setAttribute("fill", "#ef4444");
        if (sisTitle) sisTitle.textContent = "SIS INTERLOCK (BYPASS ENGAGED)";
        if (sisBorder) sisBorder.setAttribute("stroke", "#ef4444");
    } else if (sis.tripped) {
        if (sisLed) sisLed.setAttribute("fill", "#f59e0b");
        if (sisTitle) sisTitle.textContent = "SIS INTERLOCK (TRIPPED)";
        if (sisBorder) sisBorder.setAttribute("stroke", "#f59e0b");
    } else {
        if (sisLed) sisLed.setAttribute("fill", "#10b981");
        if (sisTitle) sisTitle.textContent = "SIS INTERLOCK (ARMED)";
        if (sisBorder) sisBorder.setAttribute("stroke", "#334155");
    }

    // Top Status Badge
    const plantBadge = document.getElementById("plant-status-badge");
    if (plantBadge) {
        if (telemetry.active_attack) {
            plantBadge.className = "status-badge alarm";
            plantBadge.textContent = `UNDER ATTACK: ${telemetry.active_attack.toUpperCase()}`;
        } else if (sis.bypass_active || pressure_vessel.pressure_bar > 8.0) {
            plantBadge.className = "status-badge alarm";
            plantBadge.textContent = "SAFETY THRESHOLD BREACH";
        } else {
            plantBadge.className = "status-badge nominal";
            plantBadge.textContent = "NOMINAL OPERATION";
        }
    }
}

// 2. Render Digital Gauges
function renderInstrumentGauges(telemetry) {
    if (!telemetry) return;
    const { pump_a, pressure_vessel } = telemetry;

    // Pressure
    const pVal = pressure_vessel.pressure_bar;
    document.getElementById("val-pressure").textContent = pVal.toFixed(2);
    const pPct = Math.min(100, (pVal / 12.0) * 100);
    const barP = document.getElementById("bar-pressure");
    const cardP = document.getElementById("card-pressure");
    barP.style.width = `${pPct}%`;
    cardP.className = "metric-card" + (pVal >= 9.5 ? " critical" : pVal >= 8.0 ? " warning" : "");

    // Temperature
    const tVal = pressure_vessel.temp_celsius;
    document.getElementById("val-temp").textContent = tVal.toFixed(1);
    const tPct = Math.min(100, ((tVal - 20.0) / 100.0) * 100);
    const barT = document.getElementById("bar-temp");
    const cardT = document.getElementById("card-temp");
    barT.style.width = `${tPct}%`;
    cardT.className = "metric-card" + (tVal >= 95.0 ? " critical" : tVal >= 85.0 ? " warning" : "");

    // RPM
    const rVal = pump_a.rpm;
    document.getElementById("val-rpm").textContent = Math.round(rVal);
    const rPct = Math.min(100, (rVal / 3600.0) * 100);
    const barR = document.getElementById("bar-rpm");
    const cardR = document.getElementById("card-rpm");
    barR.style.width = `${rPct}%`;
    cardR.className = "metric-card" + (rVal >= 3400.0 ? " critical" : rVal >= 3000.0 ? " warning" : "");

    // Vibration
    const vVal = pump_a.vibration;
    document.getElementById("val-vibration").textContent = vVal.toFixed(2);
    const vPct = Math.min(100, (vVal / 8.0) * 100);
    const barV = document.getElementById("bar-vibration");
    const cardV = document.getElementById("card-vibration");
    barV.style.width = `${vPct}%`;
    cardV.className = "metric-card" + (vVal >= 5.5 ? " critical" : vVal >= 3.0 ? " warning" : "");
}

// 3. Render Anomaly Engine
function renderAnomalyEngine(anomaly) {
    if (!anomaly) return;

    // Badge
    const badge = document.getElementById("anomaly-badge");
    if (anomaly.is_anomaly) {
        badge.className = "badge-pill alarm";
        badge.textContent = `ALERT (${anomaly.severity})`;
    } else {
        badge.className = "badge-pill normal";
        badge.textContent = "PASS";
    }

    // ML Score
    const mlScore = anomaly.ml_anomaly_score;
    const mlScoreText = document.getElementById("ml-score-text");
    const mlBar = document.getElementById("ml-bar-indicator");
    
    let statusLabel = mlScore >= 0.65 ? "(Drift Anomaly!)" : mlScore >= 0.45 ? "(Elevated)" : "(Normal)";
    mlScoreText.textContent = `${mlScore.toFixed(2)} ${statusLabel}`;
    mlScoreText.style.color = mlScore >= 0.65 ? "#ef4444" : mlScore >= 0.45 ? "#f59e0b" : "#38bdf8";
    mlBar.style.width = `${Math.min(100, mlScore * 100)}%`;

    // Rule Violations Box
    const box = document.getElementById("violations-box");
    if (anomaly.rule_violations && anomaly.rule_violations.length > 0) {
        box.innerHTML = anomaly.rule_violations.map(v => `<div class="violation-item">${v}</div>`).join("");
    } else {
        box.innerHTML = `<div class="empty-state">No physics threshold violations detected. Process envelope is secure.</div>`;
    }
}

// 4. Render Recent Blockchain Blocks
function renderRecentBlocks(blocks) {
    if (!blocks) return;
    const tbody = document.getElementById("blocks-tbody");
    if (!tbody) return;

    tbody.innerHTML = blocks.map(b => {
        const hashDisplay = b.event_hash ? `${b.event_hash.slice(0, 10)}...${b.event_hash.slice(-6)}` : "N/A";
        const txDisplay = b.tx_hash ? `${b.tx_hash.slice(0, 8)}...` : "Confirmed";
        const dateStr = new Date(b.timestamp * 1000).toLocaleTimeString();

        return `
        <tr id="block-row-${b.block_index}">
            <td class="block-tag">#${b.block_number}</td>
            <td><strong>#${b.event_id}</strong></td>
            <td>${dateStr}</td>
            <td><code>${b.command_type}</code></td>
            <td><span style="color:#94a3b8">${b.source}</span></td>
            <td><a href="${b.etherscan_url || '#'}" target="_blank" class="hash-link" title="${b.event_hash}">${hashDisplay}</a></td>
            <td><span class="status-chip anchored">ANCHORED</span></td>
        </tr>
        `;
    }).join("");
}

async function fetchBlockchainBlocks() {
    try {
        const res = await fetch("/api/telemetry");
        const data = await res.json();
        renderRecentBlocks(data.recent_blocks);
    } catch (e) {}
}

// 5. Attack Scenario Triggers
async function triggerAttack(scenario) {
    state.activeScenario = scenario;
    try {
        const res = await fetch("/api/attack/inject", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario })
        });
        const data = await res.json();
        console.log("Attack injected:", data);
        updateDashboard();
    } catch (err) {
        console.error("Failed to inject attack:", err);
    }
}

async function resetToNominal() {
    try {
        await fetch("/api/attack/stop", { method: "POST" });
        const banner = document.getElementById("tamper-banner");
        if (banner) banner.classList.add("hidden");
        updateDashboard();
    } catch (err) {
        console.error("Failed to reset:", err);
    }
}

// 6. Tamper Simulation & Blockchain Verification
async function simulateDatabaseTamper() {
    try {
        // Pick an event from database to tamper with
        const res = await fetch("/api/tamper/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                event_id: 1,
                malicious_field: "command_type",
                tampered_value: "BENIGN_MAINTENANCE_PING"
            })
        });
        const data = await res.json();
        
        const banner = document.getElementById("tamper-banner");
        banner.className = "tamper-banner";
        banner.innerHTML = `
            <div>
                <strong>SIMULATED OFF-CHAIN LOG TAMPER:</strong> Event #${data.event_id} command_type altered to <code>${data.tampered_value}</code> in off-chain DB!
            </div>
            <button class="audit-btn" onclick="runIntegrityAudit()">Audit Against Blockchain</button>
        `;
        banner.classList.remove("hidden");
    } catch (err) {
        console.error("Tamper simulation failed:", err);
    }
}

async function runIntegrityAudit() {
    try {
        const res = await fetch("/api/tamper/audit");
        const audit = await res.json();
        const banner = document.getElementById("tamper-banner");

        if (!audit.integrity_healthy) {
            const tamperedBlock = audit.audit_details.find(d => d.tampered);
            banner.className = "tamper-banner";
            banner.innerHTML = `
                <div>
                    <strong>CRITICAL TAMPER DETECTED:</strong> On-chain hash <code>${tamperedBlock.immutable_onchain_hash.slice(0, 16)}...</code> does NOT match computed DB hash <code>${tamperedBlock.computed_db_hash.slice(0, 16)}...</code>! Tampering exposed by IronLedger!
                </div>
            `;
            banner.classList.remove("hidden");

            // Highlight the row in the table
            const row = document.getElementById(`block-row-${tamperedBlock.block_index}`);
            if (row) {
                row.style.background = "rgba(239, 68, 68, 0.25)";
                row.querySelector(".status-chip").className = "status-chip tampered";
                row.querySelector(".status-chip").textContent = "TAMPER DETECTED";
            }
        } else {
            banner.className = "tamper-banner";
            banner.style.borderColor = "var(--accent-emerald)";
            banner.style.color = "#34d399";
            banner.innerHTML = `<div><strong>ALL BLOCKS VERIFIED:</strong> 100% cryptographic match between off-chain database and Ethereum Sepolia anchors.</div>`;
            banner.classList.remove("hidden");
        }
    } catch (err) {
        console.error("Audit error:", err);
    }
}

// 7. Forensic Reconstruction & MITRE ATT&CK Attribution
async function runForensicReconstruction() {
    try {
        const [reconRes, intelRes] = await Promise.all([
            fetch("/api/forensics/reconstruct"),
            fetch("/api/threat-intel/correlate")
        ]);

        const recon = await reconRes.json();
        const intel = await intelRes.json();

        // Render Threat Actor Attribution Card
        const hypothesis = intel.primary_hypothesis;
        if (hypothesis) {
            document.getElementById("attr-actor-name").textContent = hypothesis.name;
            document.getElementById("attr-actor-origin").textContent = `Origin: ${hypothesis.origin} | Sector Targets: ${hypothesis.target_sectors.join(", ")}`;
            document.getElementById("attr-score-badge").textContent = `${hypothesis.confidence_score}% Match`;
            document.getElementById("attr-summary").textContent = intel.correlation_summary;
        }

        // Render Reconstructed Timeline Steps
        const container = document.getElementById("timeline-steps");
        if (recon.timeline && recon.timeline.length > 0) {
            container.innerHTML = recon.timeline.map((step, idx) => {
                const isRoot = (recon.root_cause_artifact && step.event_id === recon.root_cause_artifact.event_id);
                const isTampered = step.tampered;
                let cardClass = "step-card" + (isRoot ? " root-cause" : "") + (isTampered ? " tampered" : "");

                return `
                <div class="${cardClass}">
                    <div class="step-left">
                        <span class="step-phase">${isRoot ? "🚨 [ROOT CAUSE ENTRY] " : ""}${step.kill_chain_phase}</span>
                        <span class="step-cmd">${step.source} &rarr; ${step.command_type} (${step.entity_id})</span>
                    </div>
                    <div class="step-right">
                        <div>${step.formatted_time}</div>
                        <div style="font-family: monospace; color: var(--accent-cyan);">${step.onchain_hash ? step.onchain_hash.slice(0, 12) + '...' : ''}</div>
                    </div>
                </div>
                `;
            }).join("");
        }
    } catch (err) {
        console.error("Forensic reconstruction failed:", err);
    }
}

// 8. 3-Act Demo Controller
async function runDemoAct(actNumber) {
    if (actNumber === 1) {
        // Normal Baseline
        await resetToNominal();
        alert("Act 1: SCADA Plant operating in nominal baseline envelope. Commands are anchored to Sepolia ledger.");
    } else if (actNumber === 2) {
        // Triton Attack
        await triggerAttack("triton");
        setTimeout(async () => {
            await updateDashboard();
        }, 800);
    } else if (actNumber === 3) {
        // Tamper Simulation
        await simulateDatabaseTamper();
        setTimeout(async () => {
            await runIntegrityAudit();
        }, 500);
    }
}

// 9. Modal Report Handler
function openReportModal() {
    const modal = document.getElementById("report-modal");
    const iframe = document.getElementById("report-iframe");
    iframe.src = "/api/report/html";
    modal.classList.remove("hidden");
}

function closeReportModal() {
    document.getElementById("report-modal").classList.add("hidden");
}

function openReportInNewTab() {
    window.open("/api/report/html", "_blank");
}

function toggleMetaMask() {
    state.walletConnected = !state.walletConnected;
    const btnText = document.getElementById("wallet-text");
    if (state.walletConnected) {
        btnText.textContent = "MetaMask: Connected (Sepolia)";
    } else {
        btnText.textContent = "Connect MetaMask";
    }
}
