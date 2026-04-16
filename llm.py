
import json
import re
import os
import time
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# ✅ Groq SDK
from groq import Groq

from prompts import REPORT_PROMPT
from parser import classify_finding_kind, get_owasp_from_source_tags, normalize_severity
from nvd import enrich_cves
from owasp import map_owasp
from rag_vector import retrieve_knowledge

# ============================================================
#  CONFIG GROQ
#  Modèles disponibles :
#    - "llama-3.3-70b-versatile"  → meilleure qualité (recommandé)
#    - "llama-3.1-8b-instant"     → plus rapide, moins bon
# ============================================================
MODEL_NAME = "llama-3.3-70b-versatile"

# Limites free tier Groq :
# - 6000 tokens/minute
# - 30 requêtes/minute
# - 14400 requêtes/jour
GROQ_MAX_TOKENS = 6000   # max output tokens par appel


# ============================================================
#  CLIENT GROQ — initialisé une seule fois
# ============================================================
def _get_groq_client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError(
            "⚠️ GROQ_API_KEY non définie.\n"
            "1. Va sur https://console.groq.com → API Keys → Create API Key\n"
            "2. Dans PowerShell : $env:GROQ_API_KEY = 'gsk_...ta_clé...'\n"
            "   Ou dans .env : GROQ_API_KEY=gsk_...ta_clé..."
        )
    return Groq(api_key=api_key)


# ============================================================
#  GROQ RUN — remplace ollama_run
# ============================================================
def ollama_run(prompt: str) -> str:
    """
    Appel Groq API — interface identique à l'ancien ollama_run
    pour ne rien casser dans analyze_full.
    """
    print(f"Taille du prompt: {len(prompt)} chars (~{len(prompt)//4} tokens)")

    client = _get_groq_client()

    try:
        start = time.time()

        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": "Tu es un consultant senior en cybersécurité. Réponds UNIQUEMENT en français.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0,
            max_tokens=GROQ_MAX_TOKENS,
            stream=False,
        )

        elapsed = time.time() - start
        out = completion.choices[0].message.content or ""

        # Stats
        usage = completion.usage
        print(
            f"✅ Groq terminé en {elapsed:.2f}s | "
            f"Tokens prompt: {usage.prompt_tokens} | "
            f"Tokens générés: {usage.completion_tokens} | "
            f"Total: {usage.total_tokens}"
        )

    except Exception as e:
        error_msg = str(e)

        # Rate limit → attendre et réessayer une fois
        if "rate_limit" in error_msg.lower() or "429" in error_msg:
            print("⚠️ Rate limit Groq atteint — attente 60s puis réessai...")
            time.sleep(60)
            return ollama_run(prompt)

        return f"⚠️ ERREUR GROQ: {error_msg}"

    if not out:
        return "⚠️ ERREUR: sortie Groq vide."

    with open("debug_output.txt", "w", encoding="utf-8") as f:
        f.write(out)

    return out.strip()


# ============================================================
#  PARALLÉLISATION — Préparation des données (RAG + OWASP)
# ============================================================

def _prepare_single_finding(args: tuple) -> tuple:
    idx, f, metadata = args

    description = f.get("description") or "Non fourni"
    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title
    source = str(f.get("source") or "").strip().lower()
    shown_title = raw_title if source == "cve" else display_title
    cve_id = f.get("cve_id") or (raw_title if raw_title.upper().startswith("CVE-") else None)

    raw_module = f.get("module_name")
    if isinstance(raw_module, list):
        module_name_value = ", ".join(str(x).strip() for x in raw_module if str(x).strip())
    else:
        module_name_value = str(raw_module or "").strip() or "Non fourni"

    source_owasp = get_owasp_from_source_tags(f)

    mapped_owasp = map_owasp(
        title=shown_title,
        description=description if description != "Non fourni" else "",
        cwe=f.get("cwe"),
        cve_id=cve_id,
    )

    # ✅ fallback OWASP si map_owasp ne trouve rien
    if mapped_owasp == "Non fourni":
        cwe_name = str(f.get("cwe_name") or "").lower()
        raw = f.get("raw") if isinstance(f.get("raw"), dict) else {}
        cwe_name_raw = str(raw.get("cwe_name") or "").lower()
        combined = f"{cwe_name} {cwe_name_raw} {description.lower()} {shown_title.lower()}"

        if "sql" in combined or "injection" in combined:
            mapped_owasp = "A03:2021 - Injection"
        elif "xss" in combined or "cross-site scripting" in combined or "cross site scripting" in combined:
            mapped_owasp = "A03:2021 - Injection"
        elif "csrf" in combined or "cross-site request forgery" in combined:
            mapped_owasp = "A01:2021 - Broken Access Control"
        elif "access control" in combined or "authorization" in combined or "forceful browsing" in combined:
            mapped_owasp = "A01:2021 - Broken Access Control"
        elif "redirect" in combined:
            mapped_owasp = "A01:2021 - Broken Access Control"
        elif "integrity" in combined:
            mapped_owasp = "A08:2021 - Software and Data Integrity Failures"

    owasp_category = mapped_owasp if mapped_owasp != "Non fourni" else (source_owasp or "Non fourni")

    rag_context = {}
    if needs_rag(shown_title, description):
        try:
            rag_docs = retrieve_knowledge(
                title=shown_title,
                description=description,
                owasp=owasp_category,
                cwe=str(f.get("cwe") or ""),
                technology=str(metadata.get("cms") or f.get("source") or ""),
                component=module_name_value if module_name_value != "Non fourni" else str(f.get("param") or f.get("kind") or ""),
                reference=str(f.get("reference") or ""),
                top_k=3,
                min_score=0.80,
            )

            is_confirmed_cve = (source == "cve" and f.get("matched_version") is True)
            module_name_for_filter = module_name_value.lower() if module_name_value != "Non fourni" else ""

            if is_confirmed_cve and rag_docs:
                filtered = []
                for doc in rag_docs:
                    text_blob = json.dumps(doc, ensure_ascii=False).lower()

                    if cve_id and cve_id.lower() in text_blob:
                        filtered.append(doc)
                        continue

                    if module_name_for_filter and module_name_for_filter in text_blob:
                        filtered.append(doc)
                        continue

                rag_docs = filtered[:1]

            if rag_docs:
                rag_context = _drop_empty_fields(compress_rag_context(rag_docs[:1]))

        except Exception as e:
            print(f"⚠️ RAG erreur pour '{shown_title}': {e}")

    ref = f.get("reference") or f.get("cve_link") or "Non fourni"
    if ref and "\n" in str(ref):
        urls = [u.strip() for u in str(ref).split("\n") if u.strip()]
        ref = urls

    row = {
        "title": shown_title,
        "description": description,
        "reference": ref,
        "owasp_category": owasp_category,
        "rag_context": rag_context,
        "source": f.get("source") or "Non fourni",
        "module_name": module_name_value,
        "matched_version": f.get("matched_version"),
        "matched_module": f.get("matched_module"),
        "note": f.get("note") or "—",
        "severity": f.get("severity") or "Non fourni",
        "priority": f.get("priority") or "P5",
        "risk": f.get("risk") or "—",
        "confidence": f.get("confidence") or "—",
        "param": f.get("param") or "",
        "alertRef": f.get("alertRef") or "",
        "cwe": f.get("cwe") or "",
        "cve_id": cve_id or "",
        "published": f.get("published") or "",
    }

    # ✅ Délai basé sur la sévérité réelle
    if source == "cve" and f.get("matched_version") is True:
        sev = normalize_severity(f.get("severity"))
        if sev in {"critical"}:
            remediation_delay = "sous 24h"
        elif sev in {"high"}:
            remediation_delay = "7 jours"
        elif sev == "medium":
            remediation_delay = "30 jours"
        else:
            remediation_delay = "60 jours"

        if module_name_value != "Non fourni":
            row["forced_recommendation"] = (
                f"Version confirmée comme vulnérable — correction requise sous {remediation_delay}. "
                f"Mettre à jour ou corriger le composant {module_name_value} selon le correctif fournisseur."
            )
        else:
            row["forced_recommendation"] = (
                f"Version confirmée comme vulnérable — correction requise sous {remediation_delay}. "
                "Mettre à jour le composant affecté selon le correctif fournisseur."
            )
        row["remediation_delay"] = remediation_delay

    cvss = f.get("cvss")
    if cvss not in (None, "", "Non fourni"):
        row["cvss"] = cvss

    return idx, row


def make_llm_rows_parallel(
    top_findings: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    max_workers: int = 6,
) -> List[Dict[str, Any]]:
    args_list = [(idx, f, metadata) for idx, f in enumerate(top_findings)]
    results = [None] * len(top_findings)

    print(f"\n⚡ Préparation parallèle de {len(top_findings)} findings (RAG + OWASP)...")
    start = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_prepare_single_finding, args): args[0]
            for args in args_list
        }
        for future in as_completed(futures):
            idx, row = future.result()
            results[idx] = row

    print(f"⚡ Préparation terminée en {time.time() - start:.2f}s")
    return results


# ============================================================
#  FONCTIONS UTILITAIRES
# ============================================================

def _compact_evidence(ev: Any, max_items: int = 6, max_chars: int = 6000) -> str:
    if ev is None:
        return "Non fourni"
    if isinstance(ev, list):
        parts = [str(x) for x in ev if x is not None]
        if len(parts) > max_items:
            s = ", ".join(parts[:max_items]) + f" (+{len(parts)-max_items} autres)"
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
    return re.sub(r"\s+", " ", s.strip().lower())


def _conf_rank(conf: Any) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(_norm(conf), 0)


def _prio_rank(p: Any) -> int:
    return {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}.get(str(p), 9)


def _sev_rank(sev: Any) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(_norm(sev), 0)


def compute_priority(f: Dict[str, Any]) -> str:
    sev = normalize_severity(f.get("severity"))
    conf = str(f.get("confidence") or "").strip().lower()
    cvss = f.get("cvss")
    matched_version = f.get("matched_version")

    base_score = 0
    if sev == "critical":
        base_score += 90
    elif sev == "high":
        base_score += 70
    elif sev == "medium":
        base_score += 50
    elif sev == "low":
        base_score += 30
    else:
        base_score += 10

    if conf == "high":
        base_score += 15
    elif conf == "medium":
        base_score += 8

    if isinstance(cvss, (int, float)):
        base_score += min(int(cvss), 10)

    prio_base = "P5"
    if base_score >= 90:
        prio_base = "P1"
    elif base_score >= 75:
        prio_base = "P2"
    elif base_score >= 55:
        prio_base = "P3"
    elif base_score >= 35:
        prio_base = "P4"

    if matched_version is False:
        if prio_base in {"P1", "P2", "P3"}:
            prio_base = "P4"

    return prio_base


def _as_list_unique(x: Any) -> List[str]:
    if x is None:
        return []
    vals = [str(v).strip() for v in (x if isinstance(x, list) else [x]) if str(v).strip()]
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
    cwe = f.get("cwe") or raw.get("cweid")
    alert_ref = f.get("alertRef") or raw.get("alertRef")

    if cve_id:
        return f"cve:{cve_id}"
    if raw_cve_id:
        return f"cve:{raw_cve_id}"
    if src == "zap" and alert_ref:
        return f"zap:{_norm(alert_ref)}"
    if cwe:
        return f"cwe:{_norm(cwe)}:{display_title or title}"

    if src == "nuclei":
        host = _norm(f.get("url") or "")
        return f"nuclei:{title}:{host}"

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
    cve_id = str(row.get("cve_id") or "").strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return cve_id
    ref = row.get("reference")
    title = row.get("title")
    ref_text = " ".join(str(x) for x in ref if x) if isinstance(ref, list) else str(ref or "")
    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", ref_text, flags=re.IGNORECASE)
    if m:
        return m.group(0).upper()
    m2 = re.search(r"\bCVE-\d{4}-\d{4,7}\b", str(title or ""), flags=re.IGNORECASE)
    if m2:
        return m2.group(0).upper()
    return _norm(title)


def dedupe_llm_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, unique = set(), []
    for row in rows:
        key = _llm_item_key(row) or _norm(json.dumps(row, ensure_ascii=False, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


def needs_rag(title: str, description: str = "") -> bool:
    text = f"{title or ''} {description or ''}".lower()
    keywords = [
        "csp", "content security policy", "clickjacking", "x-frame-options",
        "frame-ancestors", "integrity", "sri", "cve-", "sql injection", "xss",
        "cross-site scripting", "csrf", "cross-site request forgery",
        "open redirect", "reflected file download", "rest views",
        "organic groups", "webform", "views svg animation", "hsts",
        "strict-transport-security", "cookie", "cors", "cross-domain",
    ]
    return any(k in text for k in keywords)


def compress_rag_context(rag_docs):
    if not rag_docs:
        return {}
    selected_titles, technical_actions, verification_steps = [], [], []
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
        "technical_actions": technical_actions[:5],
        "verification_steps": verification_steps[:3],
    }


def _drop_empty_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def _make_annexe_row(f: Dict[str, Any]) -> Dict[str, Any]:
    sev = normalize_severity(f.get("severity"))

    priority = f.get("priority")
    if not priority or priority == "Non fourni":
        priority = compute_priority(f)

    description = f.get("description") or "Non fourni"
    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title
    source = str(f.get("source") or "").strip().lower()
    shown_title = display_title if source == "cve" and display_title != raw_title else display_title
    cve_id = f.get("cve_id") or (raw_title if raw_title.upper().startswith("CVE-") else None)
    source_owasp = get_owasp_from_source_tags(f)

    ref_a = f.get("reference") or f.get("cve_link") or "Non fourni"
    if ref_a and "\n" in str(ref_a):
        ref_a = str(ref_a).split("\n")[0].strip()

    mapped_owasp = map_owasp(
        title=shown_title,
        description=description if description != "Non fourni" else "",
        cwe=f.get("cwe"),
        cve_id=cve_id,
    )

    # ✅ même fallback OWASP dans l’annexe
    if mapped_owasp == "Non fourni":
        cwe_name = str(f.get("cwe_name") or "").lower()
        raw = f.get("raw") if isinstance(f.get("raw"), dict) else {}
        cwe_name_raw = str(raw.get("cwe_name") or "").lower()
        combined = f"{cwe_name} {cwe_name_raw} {description.lower()} {shown_title.lower()}"

        if "sql" in combined or "injection" in combined:
            mapped_owasp = "A03:2021 - Injection"
        elif "xss" in combined or "cross-site scripting" in combined or "cross site scripting" in combined:
            mapped_owasp = "A03:2021 - Injection"
        elif "csrf" in combined or "cross-site request forgery" in combined:
            mapped_owasp = "A01:2021 - Broken Access Control"
        elif "access control" in combined or "authorization" in combined or "forceful browsing" in combined:
            mapped_owasp = "A01:2021 - Broken Access Control"
        elif "redirect" in combined:
            mapped_owasp = "A01:2021 - Broken Access Control"
        elif "integrity" in combined:
            mapped_owasp = "A08:2021 - Software and Data Integrity Failures"

    row = {
        "title": shown_title,
        "severity": sev,
        "priority": priority,
        "risk": f.get("risk") or "—",
        "confidence": f.get("confidence") or "—",
        "source": f.get("source", "Non fourni"),
        "kind": f.get("kind", "Non fourni"),
        "target": _compact_target(f),
        "description": description,
        "evidence": _compact_evidence(f.get("evidence") or f.get("param")),
        "reference": ref_a,
        "owasp_category": mapped_owasp if mapped_owasp != "Non fourni" else (source_owasp or "Non fourni"),
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
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for f in all_compact:
        row = [
            str(f.get("priority", "—")), str(f.get("kind", "—")),
            str(f.get("severity", "—")), str(f.get("risk") or "—"),
            str(f.get("confidence") or "—"), str(f.get("title") or "—"),
            str(f.get("target") or "—"), str(f.get("evidence") or "—"),
            str(f.get("alertRef") or ""), str(f.get("note") or ""),
        ]
        row = [c.replace("\n", " ").replace("|", "\\|") for c in row]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def strip_llm_cvss_lines(report_text: str) -> str:
    return "\n".join(
        line for line in report_text.splitlines()
        if not re.match(r"^\s*[\*\-]?\s*Score CVSS\s*:", line, flags=re.IGNORECASE)
    )


def inject_cvss_in_section_b(report_text: str, top_findings: List[Dict[str, Any]]) -> str:
    lines, output, injected = report_text.splitlines(), [], set()
    for line in lines:
        output.append(line)
        for f in top_findings:
            cvss = f.get("cvss")
            if cvss in (None, "", "Non fourni"):
                continue
            title = f.get("title") or ""
            fid = id(f)
            if fid in injected:
                continue
            if title and title in line:
                indent = re.match(r"^(\s*)", line).group(1)
                output.append(f"{indent}* Score CVSS : {cvss}")
                injected.add(fid)
                break
    return "\n".join(output)


def inject_param_in_section_b(report_text: str, top_findings: List[Dict[str, Any]]) -> str:
    lines, output, injected = report_text.splitlines(), [], set()
    for line in lines:
        output.append(line)
        for f in top_findings:
            param = f.get("param")
            if not param or str(param).strip() in ("—", "", "Non fourni"):
                continue
            title = f.get("title") or ""
            fid = id(f)
            if fid in injected:
                continue
            if title and title in line:
                indent = re.match(r"^(\s*)", line).group(1)
                output.append(f"{indent}* **Paramètre/Ressource affecté(e) :** `{param}`")
                injected.add(fid)
                break
    return "\n".join(output)


def extract_section_b(report_text: str) -> str:
    m = re.search(
        r"(\*\*B\s*-\s*Vulnérabilités Prioritaires\*\*.*?)(?=\n\*\*C\s*-\s*Plan de remédiation\*\*|\Z)",
        report_text, flags=re.DOTALL | re.IGNORECASE,
    )
    return m.group(1).strip() if m else ""


def split_section_b_items(section_b: str) -> List[str]:
    lines, items, current = section_b.splitlines(), [], []
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
    seen, unique_items = set(), []
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
    return report_text.replace(section_b, "\n".join(rebuilt).strip(), 1)


def _is_conf_ok_for_section_b(f: Dict[str, Any]) -> bool:
    source = str(f.get("source") or "").strip().lower()
    if source in {"cve", "nuclei", "cms_scan"}:
        return True
    return str(f.get("confidence") or "").strip().lower() in {"high", "medium"}


def compute_risk_score(findings: List[Dict[str, Any]], source_level: str = "medium") -> Dict[str, Any]:
    severity_points = {
        "critical": 40,
        "high": 22,
        "medium": 10,
        "low": 4,
        "info": 0,
    }

    def reliability_multiplier(f: Dict[str, Any]) -> float:
        source = str(f.get("source") or "").strip().lower()
        severity = normalize_severity(f.get("severity"))

        if source == "cve" and f.get("matched_version") is False:
            return 0.15

        if source == "cve" and f.get("matched_version") is True:
            return 1.0

        if severity == "info":
            return 0.0

        return 1.0

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0.0

    for f in findings:
        severity = normalize_severity(f.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1

        if severity == "info":
            continue

        base = severity_points.get(severity, 0)
        total += base * reliability_multiplier(f)

    # Bonus léger de densité
    if counts["medium"] >= 4:
        total += 5
    if counts["high"] >= 2:
        total += 8
    if counts["critical"] >= 1 and counts["high"] >= 1:
        total += 10

    score = min(round(total), 100)

    source_level_norm = str(source_level or "").strip().lower()

    # garde-fous
    if counts["critical"] == 0 and counts["high"] == 0:
        score = min(score, 60)

    if source_level_norm == "medium" and counts["critical"] == 0 and counts["high"] == 0:
        score = min(score, 60)

    if counts["critical"] == 0 and counts["high"] == 0 and counts["medium"] == 0:
        score = min(score, 25)

    # ✅ empêcher CRITIQUE trop facilement
    has_confirmed_critical = any(
        normalize_severity(f.get("severity")) == "critical" and f.get("matched_version") is True
        for f in findings
    )

    has_confirmed_high = any(
        normalize_severity(f.get("severity")) == "high" and (
            str(f.get("source") or "").lower() != "cve" or f.get("matched_version") is True
        )
        for f in findings
    )

    if not has_confirmed_critical and not has_confirmed_high:
        score = min(score, 84)

    if score >= 85:
        level = "CRITIQUE"
    elif score >= 61:
        level = "ÉLEVÉ"
    elif score >= 31:
        level = "MODÉRÉ"
    else:
        level = "FAIBLE"

    return {
        "score": score,
        "level": level,
        "counts": counts,
    }


# ============================================================
#  FONCTION PRINCIPALE
# ============================================================

def analyze_full(findings: List[Dict[str, Any]], metadata: Dict[str, Any], top_n: int = 15) -> str:

    # ── ÉTAPE 1 : DÉDUPLICATION ──────────────────────────────────
    findings = dedupe_merge_across_scanners(findings)
    print("\n" + "=" * 80)
    print(f"Total findings dédupliqués : {len(findings)}")
    print(f"Findings CSRF : {len([f for f in findings if 'csrf' in str(f.get('title', '')).lower()])}")
    print("=" * 80)

    # ── ÉTAPE 2 : ENRICHISSEMENT ─────────────────────────────────
    nvd_key = os.getenv("NVD_API_KEY")
    if nvd_key:
        enrich_cves(findings, api_key=nvd_key, sleep_sec=1.2)

    for f in findings:
        f["priority"] = compute_priority(f)
    findings = sort_findings(findings)

    # ── ÉTAPE 3 : SÉPARATION matched_version ─────────────────────
    unconfirmed_cves, other_findings = [], []
    for f in findings:
        source = str(f.get("source") or "").lower()
        is_unconfirmed_cve = source == "cve" and f.get("matched_version") is False
        sev = normalize_severity(f.get("severity"))
        # CVEs HIGH/CRITICAL non confirmées → restent dans other_findings pour section B
        if is_unconfirmed_cve and sev not in {"high", "critical"}:
            unconfirmed_cves.append(f)
        else:
            other_findings.append(f)

    # ── ÉTAPE 4 : BASE OFFICIELLE ────────────────────────────────
    reportable_vulns = [f for f in other_findings if normalize_severity(f.get("severity")) != "info"]
    reportable_info = [f for f in other_findings if normalize_severity(f.get("severity")) == "info"]

    # ── ÉTAPE 5 : COMPTAGES ──────────────────────────────────────
    computed_counts = compute_summary(reportable_vulns)
    info_count = len(reportable_info)

    risk_data = compute_risk_score(
        reportable_vulns,
        source_level=metadata.get("risk_level") or "medium"
    )

    json_counts = metadata.get("severity_counts") or {}
    if json_counts:
        divergence_found = False
        for sev_key in ["critical", "high", "medium", "low"]:
            json_val = json_counts.get(sev_key, 0)
            computed_val = computed_counts.get(sev_key, 0)
            if json_val != computed_val:
                if not divergence_found:
                    print("\n⚠️  DIVERGENCE severity_counts JSON vs Calculé :")
                    divergence_found = True
                print(f"   '{sev_key}': JSON={json_val} | Calculé={computed_val}")
        if not divergence_found:
            print("✅ severity_counts JSON == Calculé")

    # ── ÉTAPE 6 : FILTRAGE SECTION B ─────────────────────────────
    def _force_section_b(f: Dict[str, Any]) -> bool:
        """CVE confirmée OU CVE HIGH/CRITICAL non confirmée → toujours dans section B."""
        source = str(f.get("source") or "").lower()
        if source != "cve":
            return False
        if f.get("matched_version") is True:
            return True
        sev = normalize_severity(f.get("severity"))
        return sev in {"high", "critical"}

    prioritized_for_section_b = [
        f for f in reportable_vulns
        if (
            str(f.get("priority")) in {"P1", "P2", "P3"}
            and _is_conf_ok_for_section_b(f)
        )
        or _force_section_b(f)
    ]
    print(f"\nSection B — après filtre confidence : {len(prioritized_for_section_b)}")

    top_findings = (
        prioritized_for_section_b if top_n is None or int(top_n) <= 0
        else prioritized_for_section_b[:int(top_n)]
    )

    # ── ÉTAPE 7 : CRÉATION DES ROWS (parallèle) ──────────────────
    top_llm_rows = make_llm_rows_parallel(top_findings, metadata, max_workers=6)
    top_llm_rows = dedupe_llm_rows(top_llm_rows)

    annexe_unconfirmed_rows = [_make_annexe_row(f) for f in unconfirmed_cves]
    all_annexe_rows = [_make_annexe_row(f) for f in other_findings]
    annexe_unconfirmed_md = build_annexe_table(annexe_unconfirmed_rows)
    annexe_md = build_annexe_table(all_annexe_rows)

    nb_unconfirmed = len(unconfirmed_cves)

    nb_high_unconfirmed = sum(
        1 for f in findings
        if str(f.get("source") or "").lower() == "cve"
        and f.get("matched_version") is False
        and normalize_severity(f.get("severity")) in {"high", "critical"}
    )

    print(f"Total findings annexe : {len(all_annexe_rows)} | CVE non confirmées : {len(annexe_unconfirmed_rows)}")

    # Détecter le secteur depuis l'URL cible
    target_url = metadata.get("target_url") or ""
    sector = "Non fourni"
    regulatory_context = "Non fourni"

    banking_keywords = ["bank", "banque", "credit", "finance", "biat", "stb", "bh ", "bnp", "atb"]
    if any(kw in target_url.lower() for kw in banking_keywords):
        sector = "Secteur bancaire / financier"
        regulatory_context = "BCT (Banque Centrale de Tunisie), circulaire n°2021-05 sur la cybersécurité, PCI-DSS si paiement en ligne"

    # ── ÉTAPE 8 : GÉNÉRATION DU PROMPT ───────────────────────────
    prompt = REPORT_PROMPT.format(
        scan_id=metadata.get("scan_id") or "Non fourni",
        target_url=metadata.get("target_url") or "Non fourni",
        cms=metadata.get("cms") or "Non fourni",
        cms_version=metadata.get("cms_version") or "Non fourni",
        mode=metadata.get("mode") or "Non fourni",
        total_vulnerabilities=len(reportable_vulns),
        created_at=metadata.get("created_at") or "Non fourni",
        scan_time_sec=metadata.get("scan_time_sec") if metadata.get("scan_time_sec") is not None else "Non fourni",
        severity_counts=json.dumps(metadata.get("severity_counts") or {}, ensure_ascii=False),
        computed_severity_counts=json.dumps(computed_counts, ensure_ascii=False),
        total_findings_extraits=len(reportable_vulns),
        top_findings_json=json.dumps(top_llm_rows, ensure_ascii=False, indent=2),
        nb_prioritaires=len(top_llm_rows),
        
        risk_level_computed=risk_data["level"],
        nb_unconfirmed=nb_unconfirmed,
        risk_level_source=metadata.get("risk_level") or "Non fourni",
        nb_high_unconfirmed=nb_high_unconfirmed,
        sector=sector,
        regulatory_context=regulatory_context,
    )

    with open("debug_prompt.txt", "w", encoding="utf-8") as f:
        f.write(prompt)
    print("Prompt sauvegardé dans debug_prompt.txt")

    # ── ÉTAPE 9 : GÉNÉRATION LLM via Groq ────────────────────────
    start_llm = time.time()
    narrative = ollama_run(prompt)
    llm_seconds = time.time() - start_llm
    print(f"⚡ Temps génération Groq : {llm_seconds:.2f}s ({llm_seconds/60:.2f} min)")

    # ── ÉTAPE 10 : POST-TRAITEMENTS ──────────────────────────────
    narrative = strip_llm_cvss_lines(narrative)
    narrative = dedupe_section_b(narrative)
    narrative = inject_cvss_in_section_b(narrative, top_findings)
    narrative = inject_param_in_section_b(narrative, top_findings)
    narrative = dedupe_section_b(narrative)

    # ── ÉTAPE 11 : TABLEAU DE SYNTHÈSE ───────────────────────────
    sev = computed_counts
    unconfirmed_counts = compute_summary(unconfirmed_cves)

    if nb_unconfirmed > 0:
        summary_table = f"""
    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise les vulnérabilités retenues dans le rapport principal après déduplication.
    > Les CVEs à version non confirmée sont séparées en Annexe A. Parmi elles, {nb_high_unconfirmed} vulnérabilité(s) HIGH/CRITICAL
    > figurent en section B à titre d’alerte, avec validation manuelle recommandée.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | {sev.get('low', 0)} | {info_count} |

     *En sus : {unconfirmed_counts.get('critical', 0)} critique(s), {nb_high_unconfirmed} élevé(s) et {unconfirmed_counts.get('medium', 0)} moyen(s) potentiels détectés (version non confirmée — voir Annexe A)*

    **Niveau de risque global : {risk_data['level']}**

    **Éléments techniques listés en annexe :** {len(findings)} | **Vulnérabilités retenues dans le rapport :** {len(reportable_vulns)} | **Prioritaires (section B) :** {len(top_llm_rows)}**

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication.
    > Le JSON source peut afficher davantage de CVEs brutes, y compris celles non confirmées en version.*
    """
    else:
        summary_table = f"""
    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise les vulnérabilités retenues dans le rapport principal après déduplication.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | {sev.get('low', 0)} | {info_count} |

    
    **Niveau de risque global : {risk_data['level']}**

    **Éléments techniques listés en annexe :** {len(findings)} | **Vulnérabilités retenues dans le rapport :** {len(reportable_vulns)} | **Prioritaires (section B) :** {len(top_llm_rows)}**

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication.*
    """

    # ── ÉTAPE 12 : RAPPORT FINAL ─────────────────────────────────
    report = narrative.strip() + "\n\n" + summary_table + "\n\n"

    if nb_unconfirmed > 0:
        report += (
            "## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)\n\n"
            + annexe_unconfirmed_md
            + "\n\n"
        )

    report += (
        "## Annexe B - Liste complète des findings dédupliqués (TOUS)\n\n"
        + annexe_md
        + "\n"
    )

    return report