"""PDF report router."""
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db_sql import get_db
from ..reports import generate_report_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{start_block_id}.pdf")
def get_report(start_block_id: int, db: Session = Depends(get_db)):
    pdf_bytes = generate_report_pdf(db, start_block_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=ironledger-report.pdf"},
    )
