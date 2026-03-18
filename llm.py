import json
import requests
from typing import Any, Dict, List
import os
import re

from prompts import REPORT_PROMPT
from parser import normalize_severity
from nvd import enrich_cves
from owasp import map_owasp
from rag_vector import retrieve_knowledge

MODEL_NAME = "llama3.1:latest"


def ollama_run(prompt: str) -> str:
    print("Taille du prompt:", len(prompt))

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": True,
                "options": {
                    "num_predict": 4096,
                    "num_ctx": 32768,
                    "temperature": 0,
                }
            },
            timeout=(10, 3600),
            stream=True,
        )
        response.raise_for_status()

        out_parts = []
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            data = json.loads(line)
            if "response" in data:
                out_parts.append(data["response"])
            if data.get("done"):
                break

        out = "".join(out_parts).strip()

    except Exception as e:
        return f"⚠️ ERREUR OLLAMA: {str(e)}"

    if not out:
        return "⚠️ ERREUR: sortie Ollama vide."

    with open("debug_output.txt", "w", encoding="utf-8") as f:
        f.write(out)

    return out


def _compact_evidence(ev: Any, max_items: int = 6, max_chars: int = 260) -> str:
    if ev is None:
        return "Non fourni"

    if isinstance(ev, list):
        parts = [str(x) for x in ev if x is not None]
        if len(parts) > max_items:
            shown = parts[:max_items]
            s = ", ".join(shown) + f" (+{len(parts)-max_items} autres)"
        else:
            s = ", ".join(parts)
    else:
        s = str(ev)

    s = " ".join(s.split())
    if len(s) > max_chars:
        s = s[:max_chars] + "…"
    return s


def _compact_target(f: Dict[str, Any]) -> str:
    return str(f.get("url") or f.get("host") or "")


def _norm(s: Any) -> str:
    s = "" if s is None else str(s)
    s = s.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _conf_rank(conf: Any) -> int:
    c = _norm(conf)
    return {"high": 3, "medium": 2, "low": 1}.get(c, 0)


def _prio_rank(p: Any) -> int:
    return {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}.get(str(p), 9)


def _sev_rank(sev: Any) -> int:
    s = _norm(sev)
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(s, 0)


def compute_priority(f: Dict[str, Any]) -> str:
    sev = normalize_severity(f.get("severity"))
    conf = str(f.get("confidence") or "").strip().lower()
    cvss = f.get("cvss")

    score = 0

    if sev == "critical":
        score += 90
    elif sev == "high":
        score += 70
    elif sev == "medium":
        score += 50
    elif sev == "low":
        score += 30
    else:
        score += 10

    if conf == "high":
        score += 15
    elif conf == "medium":
        score += 8

    if isinstance(cvss, (int, float)):
        score += min(int(cvss), 10)
    else:
        try:
            score += min(int(float(cvss)), 10)
        except Exception:
            pass

    if score >= 90:
        return "P1"
    if score >= 75:
        return "P2"
    if score >= 55:
        return "P3"
    if score >= 35:
        return "P4"
    return "P5"


def _as_list_unique(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        vals = [str(v).strip() for v in x if v is not None and str(v).strip()]
    else:
        vals = [str(x).strip()] if str(x).strip() else []

    out = []
    for v in vals:
        if v not in out:
            out.append(v)
    return out


def _fingerprint(f: Dict[str, Any]) -> str:
    src = _norm(f.get("source"))
    title = _norm(f.get("title"))
    cwe = f.get("cwe") or (f.get("raw", {}).get("cweid") if isinstance(f.get("raw"), dict) else None)

    alert_ref = f.get("alertRef") or (f.get("raw", {}).get("alertRef") if isinstance(f.get("raw"), dict) else None)
    if src == "zap" and alert_ref:
        return f"zap:{alert_ref}"

    if cwe:
        return f"cwe:{_norm(cwe)}:{title}"

    return f"title:{title}"


def dedupe_merge_across_scanners(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        key = _fingerprint(f)
        if key not in merged:
            merged[key] = {
                **f,
                "sources": sorted({str(f.get("source") or "")}),
                "param": _as_list_unique(f.get("param")),
                "targets": _as_list_unique(f.get("url") or f.get("host")),
                "evidences": _as_list_unique(f.get("evidence")),
            }
            continue

        m = merged[key]

        m["sources"] = sorted(set(m.get("sources", [])) | {str(f.get("source") or "")})
        m["param"] = list(dict.fromkeys(m.get("param", []) + _as_list_unique(f.get("param"))))
        m["targets"] = list(dict.fromkeys(m.get("targets", []) + _as_list_unique(f.get("url") or f.get("host"))))
        m["evidences"] = list(dict.fromkeys(m.get("evidences", []) + _as_list_unique(f.get("evidence"))))

        if _sev_rank(f.get("severity")) > _sev_rank(m.get("severity")):
            m["severity"] = f.get("severity")

        if _prio_rank(f.get("priority")) < _prio_rank(m.get("priority")):
            m["priority"] = f.get("priority")

        if _conf_rank(f.get("confidence")) > _conf_rank(m.get("confidence")):
            m["confidence"] = f.get("confidence")

        for field in ["description", "solution", "reference", "risk", "cwe", "cvss"]:
            if not m.get(field) and f.get(field):
                m[field] = f.get(field)

    out = []
    for m in merged.values():
        m["param"] = ", ".join(m.get("param", [])) if isinstance(m.get("param"), list) else (m.get("param") or "")
        targets = m.get("targets", [])
        m["targets"] = targets
        m["url"] = targets[0] if targets else (m.get("url") or "")
        m["evidence"] = ", ".join(m.get("evidences", [])) if m.get("evidences") else (m.get("evidence") or "")
        out.append(m)

    return out


def needs_rag(title: str, description: str = "") -> bool:
    text = f"{title or ''} {description or ''}".lower()

    keywords = [
        "csp",
        "content security policy",
        "cross-domain",
        "cors",
        "integrity",
        "sri",
        "clickjacking",
        "x-frame-options",
        "frame-ancestors",
        "cookie",
        "httponly",
        "samesite",
        "secure flag",
        "strict-transport-security",
        "hsts",
        "mime",
        "tls",
        "cipher",
        "cve",
    ]
    return any(k in text for k in keywords)


def compress_rag_context(rag_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not rag_docs:
        return {}

    best = rag_docs[0]
    return {
        "recommendation": best.get("recommendation", "Non fourni"),
        "verification": best.get("verification", "Non fourni"),
    }


def _make_llm_row(f: Dict[str, Any]) -> Dict[str, Any]:
    description = f.get("description") or "Non fourni"

    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title

    source = str(f.get("source") or "").strip().lower()
    shown_title = display_title if source == "cve" and display_title != raw_title else display_title

    owasp_category = map_owasp(
        title=shown_title,
        description=description if description != "Non fourni" else "",
        cwe=f.get("cwe"),
    )

    rag_context = {}
    if needs_rag(shown_title, description):
        rag_docs = retrieve_knowledge(
            title=shown_title,
            description=description,
            owasp=owasp_category,
            top_k=1,
        )
        rag_context = compress_rag_context(rag_docs)

    row = {
        "title": shown_title,
        "description": description,
        "evidence": _compact_evidence(f.get("evidence") or f.get("param")),
        "reference": f.get("reference") or f.get("cve_link") or "Non fourni",
        "owasp_category": owasp_category,
        "rag_context": rag_context,
    }

    

    return row


def _make_annexe_row(f: Dict[str, Any]) -> Dict[str, Any]:
    sev = normalize_severity(f.get("severity"))
    description = f.get("description") or "Non fourni"

    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title

    source = str(f.get("source") or "").strip().lower()
    shown_title = display_title if source == "cve" and display_title != raw_title else display_title

    row = {
        "title": shown_title,
        "severity": sev,
        "priority": f.get("priority", "Non fourni"),
        "risk": f.get("risk", "Non fourni"),
        "confidence": f.get("confidence", "Non fourni"),
        "source": f.get("source", "Non fourni"),
        "kind": f.get("kind", "Non fourni"),
        "target": _compact_target(f),
        "description": description,
        "evidence": _compact_evidence(f.get("evidence") or f.get("param")),
        "reference": f.get("reference") or f.get("cve_link") or "Non fourni",
        "owasp_category": map_owasp(
            title=shown_title,
            description=description if description != "Non fourni" else "",
            cwe=f.get("cwe"),
        ),
        "alertRef": f.get("alertRef") or "",
    }

    cvss = f.get("cvss")
    if cvss not in (None, "", "Non fourni"):
        row["cvss"] = cvss

    return row


def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
    return sorted(findings, key=lambda f: (order.get(f.get("priority", "P5"), 9), f.get("title") or ""))


def compute_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = normalize_severity(f.get("severity"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_annexe_table(all_compact: List[Dict[str, Any]]) -> str:
    headers = ["Priorité", "Type", "Severity", "Risk", "Confidence", "Source", "Titre", "Cible", "Preuve", "alertRef"]
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for f in all_compact:
        row = [
            str(f.get("priority", "Non fourni")),
            str(f.get("kind", "Non fourni")),
            str(f.get("severity", "Non fourni")),
            str(f.get("risk", "Non fourni")),
            str(f.get("confidence", "Non fourni")),
            str(f.get("source", "Non fourni")),
            str(f.get("title", "Non fourni")),
            str(f.get("target", "Non fourni")),
            str(f.get("evidence", "Non fourni")),
            str(f.get("alertRef", "")),
        ]
        row = [c.replace("\n", " ").replace("|", "\\|") for c in row]
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)

def strip_llm_cvss_lines(report_text: str) -> str:
    cleaned_lines = []
    for line in report_text.splitlines():
        if re.match(r"^\s*[\*\-]?\s*Score CVSS\s*:", line, flags=re.IGNORECASE):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def inject_cvss_in_section_b(report_text: str, top_findings: List[Dict[str, Any]]) -> str:
    lines = report_text.splitlines()
    output = []

    title_pattern = re.compile(r"^(\s*\d+\.\s*\*\*)(.+?)(\*\*)\s*$")
    finding_index = 0

    for line in lines:
        output.append(line)

        m = title_pattern.match(line)
        if m and finding_index < len(top_findings):
            f = top_findings[finding_index]
            cvss = f.get("cvss")

            if cvss not in (None, "", "Non fourni"):
                indent = re.match(r"^(\s*)", line).group(1)
                output.append(f"{indent}* Score CVSS : {cvss}")

            finding_index += 1

    return "\n".join(output)

def _is_conf_ok_for_section_b(f: Dict[str, Any]) -> bool:
    source = str(f.get("source") or "").strip().lower()
    if source in {"cve", "nuclei", "cms_scan"}:
        return True
    c = str(f.get("confidence") or "").strip().lower()
    return c in {"high", "medium"}


def analyze_full(findings: List[Dict[str, Any]], metadata: Dict[str, Any], top_n: int = 15) -> str:
    findings = dedupe_merge_across_scanners(findings)

    nvd_key = os.getenv("NVD_API_KEY")
    if not nvd_key:
        print("⚠️ NVD_API_KEY non trouvée dans le fichier .env")

    enrich_cves(findings, api_key=nvd_key, sleep_sec=1.2)

    for f in findings:
        f["priority"] = compute_priority(f)

    findings = sort_findings(findings)
    computed_counts = compute_summary(findings)

    # Construire séparément les données pour l'annexe et pour le LLM
    annexe_rows_by_id: Dict[int, Dict[str, Any]] = {}
    llm_rows_by_id: Dict[int, Dict[str, Any]] = {}

    for f in findings:
        annexe_rows_by_id[id(f)] = _make_annexe_row(f)
        llm_rows_by_id[id(f)] = _make_llm_row(f)

    all_annexe_rows = [annexe_rows_by_id[id(f)] for f in findings]
    annexe_md = build_annexe_table(all_annexe_rows)

    prioritized = [f for f in findings if str(f.get("priority")) in {"P1", "P2", "P3"}]
    prioritized = [f for f in prioritized if _is_conf_ok_for_section_b(f)]

    if top_n is None or int(top_n) <= 0:
        top_findings = prioritized
    else:
        top_findings = prioritized[: int(top_n)]

    top_llm_rows = [llm_rows_by_id[id(f)] for f in top_findings]

    prompt = REPORT_PROMPT.format(
        scan_id=metadata.get("scan_id") or "Non fourni",
        target_url=metadata.get("target_url") or "Non fourni",
        cms=metadata.get("cms") or "Non fourni",
        mode=metadata.get("mode") or "Non fourni",
        risk_level=metadata.get("risk_level") or "Non fourni",
        total_vulnerabilities=metadata.get("total_vulnerabilities")
        if metadata.get("total_vulnerabilities") is not None else "Non fourni",
        created_at=metadata.get("created_at") or "Non fourni",
        scan_time_sec=metadata.get("scan_time_sec")
        if metadata.get("scan_time_sec") is not None else "Non fourni",
        severity_counts=json.dumps(metadata.get("severity_counts") or {}, ensure_ascii=False),
        computed_severity_counts=json.dumps(computed_counts, ensure_ascii=False),
        total_findings_extraits=len(findings),
        top_findings_json=json.dumps(top_llm_rows, ensure_ascii=False, indent=2),
        nb_prioritaires=len(top_findings),
    )

    with open("debug_prompt.txt", "w", encoding="utf-8") as f:
        f.write(prompt)
    print("Prompt sauvegardé dans debug_prompt.txt")

    narrative = ollama_run(prompt)
    narrative = strip_llm_cvss_lines(narrative)
    narrative = inject_cvss_in_section_b(narrative, top_findings)

    final_report = (
        narrative.strip()
        + "\n\n"
        + "## Annexe - Liste complète des findings (générée par Python)\n\n"
        + annexe_md
        + "\n"
    )
    return final_report