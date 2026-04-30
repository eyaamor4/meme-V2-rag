import json
import os
import re
import time
from typing import Any, Dict, Optional

import requests

NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd_cve(cve_id: str, api_key: Optional[str] = None, timeout: int = 30) -> Optional[Dict[str, Any]]:
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    }

    if api_key:
        headers["apiKey"] = api_key.strip()

    cve_id = extract_cve_id(cve_id) or cve_id.strip().upper()

    url = f"{NVD_CVE_ENDPOINT}?cveId={cve_id}"

    try:
        r = requests.get(url, headers=headers, timeout=timeout)

        if r.status_code != 200:
            print(f"[NVD] HTTP {r.status_code} for {cve_id}")
            print(f"[NVD] URL: {url}")
            print(f"[NVD] Response: {r.text[:300]}")
            return None

        data = r.json()
        vulns = data.get("vulnerabilities") or []

        if not vulns:
            print(f"[NVD] No vulnerability found for {cve_id}")
            return None

        return vulns[0]

    except Exception as e:
        print(f"[NVD] ERROR for {cve_id}: {e}")
        return None

def _pick_desc(descs: Any) -> Optional[str]:
    if not isinstance(descs, list):
        return None
    for d in descs:
        if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
            return d["value"]
    for d in descs:
        if isinstance(d, dict) and d.get("value"):
            return d["value"]
    return None


def extract_cve_id(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"\bCVE-\d{4}-\d{4,}\b", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def parse_nvd_fields(nvd_vuln_obj: Dict[str, Any]) -> Dict[str, Any]:
    cve = (nvd_vuln_obj or {}).get("cve") or {}

    desc = _pick_desc(cve.get("descriptions") or [])

    cwe_id = None
    weaknesses = cve.get("weaknesses") or []
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for d in (w.get("description") or []):
            if isinstance(d, dict) and (d.get("value") or "").startswith("CWE-"):
                cwe_id = d.get("value")
                break
        if cwe_id:
            break

    cvss_score = None
    cvss_severity = None
    cvss_version = None

    metrics = cve.get("metrics") or {}

    if isinstance(metrics.get("cvssMetricV31"), list) and metrics["cvssMetricV31"]:
        data = metrics["cvssMetricV31"][0].get("cvssData") or {}
        cvss_score = data.get("baseScore")
        cvss_severity = data.get("baseSeverity")
        cvss_version = "3.1"

    elif isinstance(metrics.get("cvssMetricV30"), list) and metrics["cvssMetricV30"]:
        data = metrics["cvssMetricV30"][0].get("cvssData") or {}
        cvss_score = data.get("baseScore")
        cvss_severity = data.get("baseSeverity")
        cvss_version = "3.0"

    elif isinstance(metrics.get("cvssMetricV2"), list) and metrics["cvssMetricV2"]:
        item = metrics["cvssMetricV2"][0]
        data = item.get("cvssData") or {}
        cvss_score = data.get("baseScore")
        cvss_severity = item.get("baseSeverity")
        cvss_version = "2.0"

    refs = []
    for r in (cve.get("references") or []):
        if isinstance(r, dict) and r.get("url"):
            refs.append(r["url"])
    refs = refs[:8]

    return {
        "description": desc,
        "cwe": cwe_id,
        "cvss": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_version": cvss_version,
        "reference": ", ".join(refs) if refs else None,
    }


def enrich_cves(findings: list, api_key: Optional[str] = None, sleep_sec: float = 1.2) -> None:
    cache_dir = ".cache_nvd"
    os.makedirs(cache_dir, exist_ok=True)

    for f in findings:
        title = str(f.get("title") or "")
        cve_id = extract_cve_id(title)

        if not cve_id:
            continue

        cache_path = os.path.join(cache_dir, f"{cve_id}.json")
        nvd_obj = None

        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as fh:
                    nvd_obj = json.load(fh)
            except Exception:
                nvd_obj = None

        if nvd_obj is None:
            nvd_obj = fetch_nvd_cve(cve_id, api_key=api_key)
            if nvd_obj:
                try:
                    with open(cache_path, "w", encoding="utf-8") as fh:
                        json.dump(nvd_obj, fh, ensure_ascii=False, indent=2)
                except Exception:
                    pass
            time.sleep(sleep_sec)

        if not nvd_obj:
            continue

        fields = parse_nvd_fields(nvd_obj)

        for k in ("description", "cwe", "cvss", "cvss_severity", "cvss_version", "reference"):
            current = f.get(k)
            if current in (None, "", "Non fourni", "N/A", "unknown", "Unknown"):
                if fields.get(k) is not None:
                    f[k] = fields[k]