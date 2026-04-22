from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from parser import extract_findings, extract_metadata
from llm import analyze_full
from generate_pdf import generate_pdf_from_markdown

app = FastAPI(title="Vulnerability Report API")


def safe_name(value: str) -> str:
    value = value or "report"
    value = re.sub(r"[^\w\-]+", "_", value)
    return value[:100]


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    try:
        content = await file.read()
        data = json.loads(content.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Fichier JSON invalide")

    try:
        metadata = extract_metadata(data)
        findings = extract_findings(data)
        report = analyze_full(findings, metadata, top_n=0)

        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        scan_id = safe_name(metadata.get("scan_id") or file.filename or "report")
        md_path = reports_dir / f"{scan_id}.md"

        md_path.write_text(report, encoding="utf-8")

        _, pdf_path = generate_pdf_from_markdown(md_path)

        target_url = metadata.get("target_url") or "rapport"
        host = urlparse(target_url).netloc or target_url
        host = re.sub(r"^www\.", "", host)
        host = re.sub(r"[^\w\-]+", "_", host)

        download_name = f"rapport_{host}.pdf"

        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=download_name,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur pipeline: {str(e)}")