import json
import requests
from typing import Any, Dict, List
import os
import re

from prompts import REPORT_PROMPT
from parser import classify_finding_kind, normalize_severity
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
                    "num_predict":9000,
                    "num_ctx":  12288, 
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
    
    # ✅ AJOUT 1 : Vérifier la confirmation de la version
    matched_version = f.get("matched_version") 
    
    # Si c'est une CVE non confirmée, on applique une pénalité forte
    # On commence par calculer la priorité normale
    base_score = 0
    if sev == "critical": base_score += 90
    elif sev == "high": base_score += 70
    elif sev == "medium": base_score += 50
    elif sev == "low": base_score += 30
    else: base_score += 10
    
    if conf == "high": base_score += 15
    elif conf == "medium": base_score += 8
    
    if isinstance(cvss, (int, float)):
        base_score += min(int(cvss), 10)

    # Déterminer la priorité initiale
    prio_base = "P5"
    if base_score >= 90: prio_base = "P1"
    elif base_score >= 75: prio_base = "P2"
    elif base_score >= 55: prio_base = "P3"
    elif base_score >= 35: prio_base = "P4"

    # 🛑 PÉNALITÉ FORT SI NON CONFIRMÉE (matched_version=false)
    # Cela transforme un P2 en P4 (High non confirmé)
    if matched_version is False:
        # On descend d'un palier minimum
        if prio_base in {"P1", "P2"}:
            prio_base = "P4" 
        elif prio_base == "P3":
            prio_base = "P4" 

    return prio_base


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
    display_title = _norm(f.get("display_title"))
    cve_id = _norm(f.get("cve_id"))

    raw = f.get("raw") if isinstance(f.get("raw"), dict) else {}
    raw_cve_id = _norm(raw.get("cve_id") or raw.get("cve"))
    raw_cwe = raw.get("cweid")

    cwe = f.get("cwe") or raw_cwe
    alert_ref = f.get("alertRef") or raw.get("alertRef")

    # 1) priorité absolue au CVE ID
    if cve_id:
        return f"cve:{cve_id}"
    if raw_cve_id:
        return f"cve:{raw_cve_id}"

    # 2) ZAP
    if src == "zap" and alert_ref:
        return f"zap:{_norm(alert_ref)}"

    # 3) fallback CWE + titre
    if cwe:
        return f"cwe:{_norm(cwe)}:{display_title or title}"

    # 4) fallback titre
    return f"title:{display_title or title}"


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

def _llm_item_key(row: Dict[str, Any]) -> str:
    # ← AJOUT : vérifier cve_id en premier
    cve_id = str(row.get("cve_id") or "").strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return cve_id

    ref = row.get("reference")
    title = row.get("title")

    ref_text = ""
    if isinstance(ref, list):
        ref_text = " ".join(str(x) for x in ref if x)
    else:
        ref_text = str(ref or "")

    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", ref_text, flags=re.IGNORECASE)
    if m:
        return m.group(0).upper()

    m2 = re.search(r"\bCVE-\d{4}-\d{4,7}\b", str(title or ""), flags=re.IGNORECASE)
    if m2:
        return m2.group(0).upper()

    return _norm(title)


def dedupe_llm_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Supprime les doublons juste avant l'envoi au prompt.
    """
    seen = set()
    unique = []

    for row in rows:
        key = _llm_item_key(row)
        if not key:
            key = _norm(json.dumps(row, ensure_ascii=False, sort_keys=True))

        if key in seen:
            continue

        seen.add(key)
        unique.append(row)

    return unique

def needs_rag(title: str, description: str = "") -> bool:
    text = f"{title or ''} {description or ''}".lower()

    keywords = [
        "csp",
        "content security policy",
        "clickjacking",
        "x-frame-options",
        "frame-ancestors",
        "integrity",
        "sri",
        "cve-",
        "sql injection",
        "xss",
        "cross-site scripting",
        "csrf",
        "cross-site request forgery",
        "open redirect",
        "reflected file download",
        "rest views",
        "organic groups",
        "webform",
        "views svg animation",
        "hsts",
        "strict-transport-security",
        "cookie",
        "cors",
        "cross-domain",
    ]
    return any(k in text for k in keywords)


# ─── CORRECTION 1 : compress_rag_context moins restrictif ────────────────────
def compress_rag_context(rag_docs):
    """
    Extrait le contexte RAG utile depuis les documents récupérés.
    Limites augmentées pour réduire la troncature des recommandations.
    """
    if not rag_docs:
        return {}

    selected_titles = []
    technical_actions = []
    verification_steps = []

    # On itère sur les 2 premiers docs (au lieu de 1)
    for doc in rag_docs[:2]:
        title = str(doc.get("title") or "").strip()
        if title and title not in selected_titles:
            selected_titles.append(title)

        for x in doc.get("technical_actions", []) or []:
            x = str(x).strip()
            if x and x not in technical_actions:
                technical_actions.append(x)

        for x in doc.get("verification_steps", []) or []:
            x = str(x).strip()
            if x and x not in verification_steps:
                verification_steps.append(x)

    return {
        "selected_rag_titles": selected_titles[:2],
        "technical_actions": technical_actions[:5],       # était [:3]
        "verification_steps": verification_steps[:3],     # était [:2]
    }


def _drop_empty_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in d.items():
        if v in (None, "", [], {}):
            continue
        out[k] = v
    return out


# ─── CORRECTION 2 : _make_llm_row passe cve_id + top_k/min_score assouplis ──
def _make_llm_row(f: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    description = f.get("description") or "Non fourni"
    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title
    source = str(f.get("source") or "").strip().lower()
    shown_title = raw_title if source == "cve" else display_title
    cve_id = f.get("cve_id") or (raw_title if raw_title.upper().startswith("CVE-") else None)

    owasp_category = map_owasp(
        title=shown_title,
        description=description if description != "Non fourni" else "",
        cwe=f.get("cwe"),
        cve_id=cve_id,
    )

    rag_context = {}
    if needs_rag(shown_title, description):
        rag_docs = retrieve_knowledge(
            title=shown_title,
            description=description,
            owasp=owasp_category,
            cwe=str(f.get("cwe") or ""),
            technology=str(metadata.get("cms") or f.get("source") or ""),
            component=str(f.get("param") or f.get("kind") or ""),
            reference=str(f.get("reference") or ""),
            top_k=1,          
            min_score=0.80,   
        )
        if rag_docs:
            rag_context = _drop_empty_fields(compress_rag_context(rag_docs))
    
    ref = f.get("reference") or f.get("cve_link") or "Non fourni"
    if ref and "\n" in str(ref):
        urls = [u.strip() for u in str(ref).split("\n") if u.strip()]
        ref = urls 
    
    
    
    row = {
        "title": shown_title,
        "cve_id": cve_id or "—",
        "description": description,
       
        "reference": ref,
        "owasp_category": owasp_category,
        "rag_context": rag_context,
        "cms_version": metadata.get("cms_version") or "—",
        "plugin_version": f.get("plugin_version") or "—",
        "matched_version": str(f.get("matched_version") or ""), 
    }
    return row

# ─── CORRECTION 4 : _make_annexe_row passe aussi cve_id ─────────────────────
def _make_annexe_row(f: Dict[str, Any]) -> Dict[str, Any]:
    sev = normalize_severity(f.get("severity"))
    description = f.get("description") or "Non fourni"

    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title

    source = str(f.get("source") or "").strip().lower()
    shown_title = display_title if source == "cve" and display_title != raw_title else display_title

    # CORRECTION 4 : passer cve_id pour activer CVE_OWASP_OVERRIDE dans l'annexe aussi
    cve_id = f.get("cve_id") or (raw_title if raw_title.upper().startswith("CVE-") else None)
    ref_a = f.get("reference") or f.get("cve_link") or "Non fourni"
    if ref_a and "\n" in str(ref_a):
        ref_a = str(ref_a).split("\n")[0].strip()
    row = {
        "title": shown_title,

        "severity": sev,
        "priority": f.get("priority", "Non fourni"),
        "risk": f.get("risk") or "—",
        "confidence": f.get("confidence") or "—",
        "source": f.get("source", "Non fourni"),
        "kind": f.get("kind", "Non fourni"),
        "target": _compact_target(f),
        "description": description,
        "evidence": _compact_evidence(f.get("evidence") or f.get("param")),
        "reference": ref_a, 
        "owasp_category": map_owasp(
            title=shown_title,
            description=description if description != "Non fourni" else "",
            cwe=f.get("cwe"),
            cve_id=cve_id,
        ),
        "alertRef": f.get("alertRef") or "",
        "note": f.get("note") or "—",
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
    headers = ["Priorité", "Type", "Severity", "Risk", "Confidence", "Titre", "Cible", "Preuve", "alertRef", "Note"]
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for f in all_compact:
        row = [
            str(f.get("priority", "—")),
            str(f.get("kind", "—")),
            str(f.get("severity", "—")),
            str(f.get("risk") or "—"),
            str(f.get("confidence") or "—"),
            str(f.get("title") or "—"),
            str(f.get("target") or "—"),
            str(f.get("evidence") or "—"),
            str(f.get("alertRef") or ""),
            str(f.get("note") or ""),
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
    injected = set()  # ← tracker les findings déjà injectés

    for line in lines:
        output.append(line)

        for f in top_findings:
            cvss = f.get("cvss")
            if cvss in (None, "", "Non fourni"):
                continue

            title = f.get("title") or ""
            finding_id = id(f)  # identifiant unique du finding

            if finding_id in injected:
                continue  # ← déjà injecté → ignorer

            if title and title in line:
                indent = re.match(r"^(\s*)", line).group(1)
                output.append(f"{indent}* Score CVSS : {cvss}")
                injected.add(finding_id)  # ← marquer comme injecté
                break

    return "\n".join(output)
def inject_param_in_section_b(
    report_text: str,
    top_findings: List[Dict[str, Any]]
) -> str:
    """
    Injecte le champ 'param' juste après le titre de chaque
    vulnérabilité dans la Section B, après génération LLM.
    """
    lines = report_text.splitlines()
    output = []
    injected = set()

    for line in lines:
        output.append(line)

        for f in top_findings:
            param = f.get("param")

            # Ignorer si param vide ou non significatif
            if not param or str(param).strip() in ("—", "", "Non fourni"):
                continue

            title = f.get("title") or ""
            finding_id = id(f)

            # Déjà injecté → skip
            if finding_id in injected:
                continue

            # Chercher le titre dans la ligne courante
            if title and title in line:
                indent = re.match(r"^(\s*)", line).group(1)
                output.append(
                    f"{indent}* **Paramètre/Ressource affecté(e) :** `{param}`"
                )
                injected.add(finding_id)
                break

    return "\n".join(output)

def extract_section_b(report_text: str) -> str:
    m = re.search(
        r"(\*\*B\s*-\s*Vulnérabilités Prioritaires\*\*.*?)(?=\n\*\*C\s*-\s*Plan de remédiation\*\*|\Z)",
        report_text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return m.group(1).strip() if m else ""


def split_section_b_items(section_b: str) -> List[str]:
    lines = section_b.splitlines()
    items = []
    current = []

    for line in lines:
        if re.match(r"^\s*\d+\.\s+\*\*.*\*\*", line):
            if current:
                items.append("\n".join(current).strip())
            current = [line]
        else:
            if current:
                current.append(line)

    if current:
        items.append("\n".join(current).strip())

    return items


def _dedup_key_from_llm_item(item: str) -> str:
    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", item, flags=re.IGNORECASE)
    if m:
        return m.group(0).upper()

    title_match = re.search(r"^\s*\d+\.\s+\*\*(.*?)\*\*", item, flags=re.MULTILINE)
    if title_match:
        return _norm(title_match.group(1))

    return _norm(item)


def dedupe_section_b(report_text: str) -> str:
    section_b = extract_section_b(report_text)
    if not section_b:
        return report_text

    items = split_section_b_items(section_b)

    seen = set()
    unique_items = []

    for item in items:
        key = _dedup_key_from_llm_item(item)
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)

    if not unique_items:
        return report_text

    header_match = re.match(r"^\*\*B\s*-\s*Vulnérabilités Prioritaires\*\*", section_b, flags=re.IGNORECASE)
    header = header_match.group(0) if header_match else "**B - Vulnérabilités Prioritaires**"

    rebuilt = [header, ""]
    for i, item in enumerate(unique_items, start=1):
        item = re.sub(r"^\s*\d+\.\s+", f"{i}. ", item, count=1)
        rebuilt.append(item)

    new_section_b = "\n".join(rebuilt).strip()
    return report_text.replace(section_b, new_section_b, 1)

def _is_conf_ok_for_section_b(f: Dict[str, Any]) -> bool:
    source = str(f.get("source") or "").strip().lower()
    if source in {"cve", "nuclei", "cms_scan"}:
        return True
    c = str(f.get("confidence") or "").strip().lower()
    return c in {"high", "medium"}

def compute_risk_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    weights = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 0}
    total = sum(
        weights.get(normalize_severity(f.get("severity")), 0)
        for f in findings
        if f.get("priority") in {"P1", "P2", "P3"}
    )
    score = min(total, 100)
    if score >= 70:
        level = "CRITIQUE"
    elif score >= 50:
        level = "ÉLEVÉ"
    elif score >= 30:
        level = "MODÉRÉ"
    else:
        level = "FAIBLE"
    return {"score": score, "level": level}
def analyze_full(findings: List[Dict[str, Any]], metadata: Dict[str, Any], top_n: int = 15) -> str:
    """
    Génère un rapport complet.

    LOGIQUE :
    1. Dédupliquer TOUS les findings
    2. Enrichir TOUS les findings (CVE, priorité)
    3. Séparer les CVE non confirmées (Annexe A)
    4. Définir une base unique du rapport principal (reportable_vulns/reportable_info)
    5. Filtrer la Section B sur cette base
    6. Générer le rapport + annexes
    """

    # ============================================================
    # ÉTAPE 1 : DÉDUPLICATION
    # ============================================================
    findings = dedupe_merge_across_scanners(findings)

    print("\n" + "=" * 80)
    print("DEBUG : Après déduplication")
    print("=" * 80)
    print(f"Total findings dédupliqués : {len(findings)}")
    csrf_count = len([f for f in findings if "csrf" in str(f.get("title", "")).lower()])
    print(f"Findings CSRF : {csrf_count}")
    print("=" * 80 + "\n")

    # ============================================================
    # ÉTAPE 2 : ENRICHISSEMENT
    # ============================================================
    nvd_key = os.getenv("NVD_API_KEY")
    if nvd_key:
        enrich_cves(findings, api_key=nvd_key, sleep_sec=1.2)

    for f in findings:
        f["priority"] = compute_priority(f)

    findings = sort_findings(findings)

    # ============================================================
    # ÉTAPE 3 : SÉPARATION matched_version
    # ============================================================
    unconfirmed_cves: List[Dict[str, Any]] = []
    other_findings: List[Dict[str, Any]] = []

    for f in findings:
        source = str(f.get("source") or "").lower()
        matched_version = f.get("matched_version")

        if source == "cve" and matched_version is False:
            unconfirmed_cves.append(f)
        else:
            other_findings.append(f)

    # ============================================================
    # ÉTAPE 4 : BASE OFFICIELLE DU RAPPORT PRINCIPAL
    # ============================================================
    # Ce que le client voit comme vulnérabilités "retenues"
    reportable_vulns = [
        f for f in other_findings
        if normalize_severity(f.get("severity")) != "info"
    ]

    reportable_info = [
        f for f in other_findings
        if normalize_severity(f.get("severity")) == "info"
    ]

    # ============================================================
    # ÉTAPE 5 : COMPTAGES
    # ============================================================
    computed_counts = compute_summary(reportable_vulns)

    # Garde ton mapping actuel si tu veux rester aligné au risk_level fourni
    risk_level_raw = (metadata.get("risk_level") or "medium").lower()
    risk_level_map = {
        "critical": "CRITIQUE",
        "high": "ÉLEVÉ",
        "medium": "MODÉRÉ",
        "low": "FAIBLE",
    }
    risk_data = {
        "score": "—",
        "level": risk_level_map.get(risk_level_raw, "MODÉRÉ"),
    }

    # Si tu veux plus tard un vrai recalcul métier, remplace le bloc ci-dessus par :
    # risk_data = compute_risk_score(reportable_vulns)

    # ============================================================
    # ÉTAPE 6 : FILTRAGE POUR SECTION B
    # ============================================================
    prioritized_for_section_b = [
        f for f in reportable_vulns
        if str(f.get("priority")) in {"P1", "P2", "P3"}
    ]

    prioritized_for_section_b = [
        f for f in prioritized_for_section_b
        if _is_conf_ok_for_section_b(f)
    ]

    print("\n" + "=" * 80)
    print("DEBUG : Section B (filtrée)")
    print("=" * 80)
    print(f"Total prioritaires (P1/P2/P3) dans le rapport principal : {len([f for f in reportable_vulns if str(f.get('priority')) in {'P1', 'P2', 'P3'}])}")
    print(f"Après filtre confidence : {len(prioritized_for_section_b)}")
    csrf_in_section_b = len([f for f in prioritized_for_section_b if "csrf" in str(f.get("title", "")).lower()])
    print(f"CSRF dans Section B : {csrf_in_section_b}")
    print("=" * 80 + "\n")

    if top_n is None or int(top_n) <= 0:
        top_findings = prioritized_for_section_b
    else:
        top_findings = prioritized_for_section_b[:int(top_n)]

    # ============================================================
    # ÉTAPE 7 : CRÉATION DES ROWS
    # ============================================================
    llm_rows_by_id: Dict[int, Dict[str, Any]] = {}
    annexe_rows_by_id: Dict[int, Dict[str, Any]] = {}
    annexe_unconfirmed_rows_by_id: Dict[int, Dict[str, Any]] = {}

    for f in top_findings:
        llm_rows_by_id[id(f)] = _make_llm_row(f, metadata)

    for f in unconfirmed_cves:
        annexe_unconfirmed_rows_by_id[id(f)] = _make_annexe_row(f)

    for f in other_findings:
        annexe_rows_by_id[id(f)] = _make_annexe_row(f)

    print("\n" + "=" * 80)
    print("DEBUG : Annexe")
    print("=" * 80)
    print(f"Total findings dans l'annexe complète : {len(annexe_rows_by_id)}")
    print(f"Total CVE non confirmées (annexe A) : {len(annexe_unconfirmed_rows_by_id)}")
    print("=" * 80 + "\n")

    top_llm_rows = [llm_rows_by_id[id(f)] for f in top_findings]
    top_llm_rows = dedupe_llm_rows(top_llm_rows)

    annexe_unconfirmed_rows = [annexe_unconfirmed_rows_by_id[id(f)] for f in unconfirmed_cves]
    annexe_unconfirmed_md = build_annexe_table(annexe_unconfirmed_rows)

    all_annexe_rows = [annexe_rows_by_id[id(f)] for f in other_findings]
    annexe_md = build_annexe_table(all_annexe_rows)

    # ============================================================
    # ÉTAPE 8 : GÉNÉRATION DU PROMPT
    # ============================================================
    prompt = REPORT_PROMPT.format(
        scan_id=metadata.get("scan_id") or "Non fourni",
        target_url=metadata.get("target_url") or "Non fourni",
        cms=metadata.get("cms") or "Non fourni",
        cms_version=metadata.get("cms_version") or "Non fourni",
        mode=metadata.get("mode") or "Non fourni",
        risk_level=metadata.get("risk_level") or "Non fourni",
        total_vulnerabilities=len(reportable_vulns),
        created_at=metadata.get("created_at") or "Non fourni",
        scan_time_sec=metadata.get("scan_time_sec") if metadata.get("scan_time_sec") is not None else "Non fourni",
        severity_counts=json.dumps(metadata.get("severity_counts") or {}, ensure_ascii=False),
        computed_severity_counts=json.dumps(computed_counts, ensure_ascii=False),
        total_findings_extraits=len(reportable_vulns),
        top_findings_json=json.dumps(top_llm_rows, ensure_ascii=False, indent=2),
        nb_prioritaires=len(top_llm_rows),
        risk_score=risk_data["score"],
        risk_level_computed=risk_data["level"],
    )

    with open("debug_prompt.txt", "w", encoding="utf-8") as f:
        f.write(prompt)
    print("Prompt sauvegardé dans debug_prompt.txt")

    # ============================================================
    # ÉTAPE 9 : GÉNÉRATION DU RAPPORT
    # ============================================================
    narrative = ollama_run(prompt)
    narrative = strip_llm_cvss_lines(narrative)
    narrative = dedupe_section_b(narrative)
    narrative = inject_cvss_in_section_b(narrative, top_findings)
    narrative = inject_param_in_section_b(narrative, top_findings)
    narrative = dedupe_section_b(narrative)

    # ============================================================
    # ÉTAPE 10 : TABLEAU DE SYNTHÈSE
    # ============================================================
    sev = computed_counts

    summary_table = f"""
## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | {sev.get('low', 0)} | {len(reportable_info)} |

**Éléments techniques listés en annexe :** {len(findings)} | **Vulnérabilités retenues dans le rapport :** {len(reportable_vulns)} | **Prioritaires (section B) :** {len(top_llm_rows)}
"""

    # ============================================================
    # ÉTAPE 11 : RAPPORT FINAL
    # ============================================================
    final_report = (
        narrative.strip()
        + "\n\n"
        + summary_table
        + "\n\n"
        + "## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)\n\n"
        + annexe_unconfirmed_md
        + "\n\n"
        + "## Annexe B - Liste complète des findings dédupliqués (TOUS)\n\n"
        + annexe_md
        + "\n"
    )

    return final_report