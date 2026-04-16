from fastapi import FastAPI, UploadFile, File, HTTPException
import json
from parser import extract_findings, extract_metadata
from llm import analyze_full

app = FastAPI(title="Vulnerability Report API")


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur pipeline: {str(e)}")

    return {
        "status": "success",
        "scan_id": metadata.get("scan_id"),
        "target_url": metadata.get("target_url"),
        "report": report,
    }