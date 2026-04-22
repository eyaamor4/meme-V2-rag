from fastapi import FastAPI, UploadFile, File, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.openapi.utils import get_openapi
import json
import re
import os
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
from typing import List

from parser import extract_findings, extract_metadata
from llm import analyze_full
from generate_pdf import generate_pdf_from_markdown

load_dotenv()

API_KEY = os.getenv("CYBERSCAN_API_KEY")

app = FastAPI(title="Vulnerability Report API")


def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key missing")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


def safe_name(value: str) -> str:
    value = value or "report"
    value = re.sub(r"[^\w\-]+", "_", value)
    return value[:100]


def build_pdf_from_json_data(data: dict, original_filename: str = "report.json") -> tuple[Path, str]:
    metadata = extract_metadata(data)
    findings = extract_findings(data)
    report = analyze_full(findings, metadata, top_n=0)

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    base_name = safe_name(metadata.get("scan_id") or Path(original_filename).stem or "report")
    unique_id = uuid.uuid4().hex[:8]

    md_path = reports_dir / f"{base_name}_{unique_id}.md"
    md_path.write_text(report, encoding="utf-8")

    _, pdf_path = generate_pdf_from_markdown(md_path)

    target_url = metadata.get("target_url") or "rapport"
    host = urlparse(target_url).netloc or target_url
    host = re.sub(r"^www\.", "", host)
    host = re.sub(r"[^\w\-]+", "_", host)

    download_name = f"rapport_{host}_{unique_id}.pdf"
    return pdf_path, download_name


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    x_api_key: str = Header(None)
):
    verify_api_key(x_api_key)

    try:
        content = await file.read()
        data = json.loads(content.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Fichier JSON invalide")

    try:
        pdf_path, download_name = build_pdf_from_json_data(data, file.filename or "report.json")
        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=download_name,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur pipeline: {str(e)}")


@app.post("/analyze-multi")
async def analyze_multi(
    x_api_key: str = Header(None),
    files: List[UploadFile] = File(...),
):
    verify_api_key(x_api_key)

    if not files:
        raise HTTPException(status_code=400, detail="Aucun fichier fourni")

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    zip_id = uuid.uuid4().hex[:8]
    zip_path = reports_dir / f"rapports_pdf_{zip_id}.zip"

    generated_files = []

    try:
        for file in files:
            try:
                content = await file.read()
                data = json.loads(content.decode("utf-8"))
            except Exception:
                raise HTTPException(
                    status_code=400,
                    detail=f"Fichier JSON invalide : {file.filename}"
                )

            pdf_path, download_name = build_pdf_from_json_data(
                data,
                file.filename or "report.json"
            )
            generated_files.append((pdf_path, download_name))

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for pdf_path, download_name in generated_files:
                zipf.write(pdf_path, arcname=download_name)

        return FileResponse(
            path=str(zip_path),
            media_type="application/zip",
            filename=f"rapports_pdf_{zip_id}.zip",
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur pipeline: {str(e)}")


# ✅ Patch du schéma OpenAPI — force Swagger à afficher "Choose File" pour /analyze-multi
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version="1.0.0",
        routes=app.routes,
    )

    # Force le bon schéma binaire pour les fichiers multiples
    schema["paths"]["/analyze-multi"]["post"]["requestBody"] = {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "files": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "format": "binary"  # ← clé : force Swagger à afficher un vrai input file
                            }
                        }
                    },
                    "required": ["files"]
                }
            }
        }
    }

    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi