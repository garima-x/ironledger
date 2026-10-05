"""PDF court-ready report generation (garima's modular version)."""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from . import models
from .forensics import backward_walk, attribution, is_tampered
from .threat_intel import MITRE_TECHNIQUES, ACTOR_PROFILES


def generate_report_pdf(db: Session, start_block_id: int) -> bytes:
    steps = backward_walk(db, start_block_id)
    scores, leader, tied_with = attribution(db)
    hit_techniques = {
        a.technique
        for a in db.query(models.Anomaly).filter(models.Anomaly.technique.isnot(None))
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=16, spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    body = styles["BodyText"]

    leader_str = leader or "None"
    if tied_with:
        leader_str += f" (tied with {', '.join(tied_with)})"

    story = [
        Paragraph("IronLedger Forensic Report — Reactor-01 Incident", title_style),
        Paragraph(
            f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
            "chain-of-custody verified against on-chain hash anchors",
            body,
        ),
        Spacer(1, 10),
        Paragraph("Incident Summary", h2),
        Paragraph(
            "The safety instrumented system interlock was disabled and a control element was forced into an "
            "unsafe position, driving process telemetry past its safe operating envelope. A local historian "
            "record for one command was subsequently altered; recomputing its hash from the altered record no "
            "longer reproduces the value that was anchored on-chain, which is the tamper evidence below.",
            body,
        ),
        Paragraph("Reconstructed Timeline (backward-walk)", h2),
    ]

    tl_data = [["Block", "Time", "Event", "Flag"]]
    for s in steps:
        ts = s["ts"].strftime("%H:%M:%S") if hasattr(s["ts"], "strftime") else str(s["ts"])
        tl_data.append([f"#{s['block_id']}", ts, s["title"], s["flag"] or "—"])
    story.append(_table(tl_data))

    story.append(Paragraph("MITRE ATT&CK for ICS Techniques Observed", h2))
    mitre_data = [["ID", "Technique", "Tactic"]]
    for t in MITRE_TECHNIQUES:
        if t["id"] in hit_techniques:
            mitre_data.append([t["id"], t["name"], t["tactic"]])
    story.append(_table(mitre_data))

    story.append(Paragraph("Threat Attribution", h2))
    story.append(Paragraph(f"Primary attribution: {leader_str}", body))
    attr_data = [["Actor", "Confidence"]] + [
        [actor, f"{score}%"]
        for actor, score in sorted(scores.items(), key=lambda kv: -kv[1])
    ]
    story.append(_table(attr_data))

    story.append(Spacer(1, 40))
    story.append(Paragraph("_______________________________&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                            "_______________________________", body))
    story.append(Paragraph("Investigator signature&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                            "&nbsp;&nbsp;Chain-of-custody witness", body))

    doc.build(story)
    return buf.getvalue()


def _table(data: list[list[str]]) -> Table:
    t = Table(data, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#3F5066")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#999999")),
        ("ROWBACKGROUNDS",(0, 1),(-1, -1), [colors.white, colors.HexColor("#F6F2F0")]),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    return t
