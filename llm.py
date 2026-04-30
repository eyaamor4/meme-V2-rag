import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from groq import Groq

from prompts import REPORT_PROMPT, REPORT_PROMPT_COMPLETE
from parser import (
    build_summary_stats,
    classify_finding_kind,
    count_severity,
    get_owasp_from_source_tags,
    normalize_severity,
    split_findings,
)
from nvd import enrich_cves
from owasp import map_owasp
from rag_vector import retrieve_knowledge


# ============================================================
# CONFIG
# ============================================================

MODEL_NAME = "llama-3.3-70b-versatile"
GROQ_MAX_TOKENS = 3000


# ============================================================
# CLIENT GROQ
# ============================================================

def _get_groq_client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError(
            "⚠️ GROQ_API_KEY non définie.\n"
            "1. Va sur https://console.groq.com → API Keys → Create API Key\n"
            "2. Dans PowerShell : $env:GROQ_API_KEY = 'gsk_...'\n"
            "   Ou dans .env : GROQ_API_KEY=gsk_..."
        )
    return Groq(api_key=api_key)



# ============================================================
# OUTILS AGENT — définitions pour Groq tool calling
# ============================================================

AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_rag_knowledge",
            "description": (
                "Interroge la base de connaissances RAG locale pour obtenir des étapes de vérification, "
                "recommandations techniques et contexte sur une vulnérabilité. "
                "À appeler quand le contexte RAG manque ou est insuffisant pour une vulnérabilité connue "
                "(XSS, CSP, SQLi, TLS, CSRF, SRI, HSTS, cookies, CORS, etc.)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Titre exact de la vulnérabilité tel qu'il apparaît dans les données.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Description de la vulnérabilité (peut être vide).",
                    },
                    "owasp": {
                        "type": "string",
                        "description": "Catégorie OWASP associée (ex: A03:2021 - Injection).",
                    },
                    "cwe": {
                        "type": "string",
                        "description": "Identifiant CWE associé (ex: CWE-79).",
                    },
                },
                "required": ["title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_nvd_cve_info",
            "description": (
                "Récupère les informations NVD (description, score CVSS, CWE, références) "
                "pour un identifiant CVE donné. "
                "À appeler uniquement si le CVE_ID est présent dans les données et que "
                "le score CVSS ou la description sont manquants ou insuffisants."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "Identifiant CVE au format CVE-AAAA-NNNNN (ex: CVE-2021-44228).",
                    },
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "classify_owasp_category",
            "description": (
                "Détermine la catégorie OWASP Top 10 2021 la plus appropriée pour une vulnérabilité "
                "à partir de son titre, description et CWE. "
                "À appeler si la catégorie OWASP d'un finding est 'Non fourni' ou absente."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Titre de la vulnérabilité.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Description de la vulnérabilité.",
                    },
                    "cwe": {
                        "type": "string",
                        "description": "CWE associé si disponible.",
                    },
                },
                "required": ["title"],
            },
        },
    },
]


# ============================================================
# EXÉCUTION DES OUTILS AGENT
# ============================================================

def _execute_agent_tool(tool_name: str, tool_args: Dict[str, Any]) -> str:
    """Exécute un outil appelé par l'agent et retourne le résultat en JSON string."""

    if tool_name == "search_rag_knowledge":
        try:
            docs = retrieve_knowledge(
                title=tool_args.get("title", ""),
                description=tool_args.get("description", ""),
                owasp=tool_args.get("owasp", ""),
                cwe=tool_args.get("cwe", ""),
                top_k=2,
                min_score=0.60,
            )
            if not docs:
                return json.dumps({"result": "Aucun document trouvé dans la base RAG."})
            compressed = compress_rag_context(docs)
            print(f"🔧 [AGENT TOOL] search_rag_knowledge → {len(docs)} doc(s) pour: {tool_args.get('title')}")
            return json.dumps(compressed, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif tool_name == "fetch_nvd_cve_info":
        from nvd import fetch_nvd_cve, parse_nvd_fields
        cve_id = tool_args.get("cve_id", "")
        try:
            nvd_obj = fetch_nvd_cve(cve_id, api_key=os.getenv("NVD_API_KEY"))
            if not nvd_obj:
                return json.dumps({"result": f"CVE {cve_id} non trouvé dans NVD."})
            fields = parse_nvd_fields(nvd_obj)
            print(f"🔧 [AGENT TOOL] fetch_nvd_cve_info → CVSS={fields.get('cvss')} pour {cve_id}")
            return json.dumps(fields, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif tool_name == "classify_owasp_category":
        from owasp import map_owasp
        try:
            result = map_owasp(
                title=tool_args.get("title", ""),
                description=tool_args.get("description", ""),
                cwe=tool_args.get("cwe"),
            )
            print(f"🔧 [AGENT TOOL] classify_owasp_category → {result} pour: {tool_args.get('title')}")
            return json.dumps({"owasp_category": result}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    return json.dumps({"error": f"Outil inconnu: {tool_name}"})


# ============================================================
# BOUCLE AGENT (ReAct : Reason → Act → Observe → Repeat)
# ============================================================

def ollama_run(prompt: str) -> str:
    """
    Agent LLM avec boucle ReAct + tool calling Groq.
    Le modèle peut appeler jusqu'à MAX_AGENT_ITERATIONS outils
    avant de produire la réponse finale.
    """
    MAX_AGENT_ITERATIONS = 8

    print(f"Taille du prompt: {len(prompt)} chars (~{len(prompt)//4} tokens)")
    client = _get_groq_client()

    system_message = (
        "Tu es un consultant senior en cybersécurité. Réponds UNIQUEMENT en français.\n\n"
        "RÈGLE OBLIGATOIRE : Avant de rédiger le rapport, tu DOIS appeler les outils suivants :\n"
        "1. search_rag_knowledge : pour CHAQUE finding de la section B, "
        "afin d\'obtenir les étapes de vérification et recommandations depuis la base de connaissances.\n"
        "2. fetch_nvd_cve_info : pour CHAQUE finding dont le titre ou cve_id contient CVE-, "
        "afin de récupérer le score CVSS et la description officielle.\n"
        "3. classify_owasp_category : pour tout finding dont owasp_category vaut Non fourni.\n\n"
        "PROCESSUS OBLIGATOIRE :\n"
        "- Etape 1 : Analyse les findings recus.\n"
        "- Etape 2 : Appelle les outils pour chaque finding (search_rag_knowledge, fetch_nvd_cve_info).\n"
        "- Etape 3 : Apres avoir collecte toutes les informations, genere le rapport complet.\n"
        "Ne jamais rediger le rapport sans avoir appele les outils au moins une fois par finding."
    )

    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": prompt},
    ]

    tool_calls_log = []
    iteration = 0

    try:
        start = time.time()

        while iteration < MAX_AGENT_ITERATIONS:
            iteration += 1
            print(f"\n🤖 [AGENT] Itération {iteration}/{MAX_AGENT_ITERATIONS}")

            # Première itération : forcer l'appel d'outil (required)
            # Itérations suivantes : laisser le modèle décider (auto)
            current_tool_choice = "required" if iteration == 1 else "auto"

            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                tools=AGENT_TOOLS,
                tool_choice=current_tool_choice,
                temperature=0,
                max_tokens=GROQ_MAX_TOKENS,
                stream=False,
            )

            response_message = completion.choices[0].message
            finish_reason = completion.choices[0].finish_reason

            # ── Pas d'appel d'outil → réponse finale
            if finish_reason == "stop" or not response_message.tool_calls:
                out = response_message.content or ""
                elapsed = time.time() - start
                usage = completion.usage
                print(
                    f"✅ Agent terminé en {elapsed:.2f}s | "
                    f"{iteration} itération(s) | "
                    f"{len(tool_calls_log)} appel(s) d'outils | "
                    f"Tokens: {usage.prompt_tokens}→{usage.completion_tokens}"
                )
                if tool_calls_log:
                    print(f"   Outils utilisés: {tool_calls_log}")
                break

            # ── Appels d'outils demandés par le modèle
            # Ajouter le message assistant avec les tool_calls
            messages.append({
                "role": "assistant",
                "content": response_message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in response_message.tool_calls
                ],
            })

            # Exécuter chaque outil et ajouter les résultats
            for tool_call in response_message.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                print(f"   🔧 Appel outil: {tool_name}({list(tool_args.keys())})")
                tool_calls_log.append(tool_name)

                tool_result = _execute_agent_tool(tool_name, tool_args)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_result,
                })

        else:
            # MAX iterations atteint → forcer la génération finale
            print(f"⚠️ [AGENT] Limite de {MAX_AGENT_ITERATIONS} itérations atteinte — forçage réponse finale")
            messages.append({
                "role": "user",
                "content": "Tu as suffisamment d'informations. Génère maintenant le rapport complet en français.",
            })
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0,
                max_tokens=GROQ_MAX_TOKENS,
                stream=False,
            )
            out = completion.choices[0].message.content or ""

    except Exception as e:
        error_msg = str(e)
        if "rate_limit" in error_msg.lower() or "429" in error_msg:
            print("⚠️ Rate limit Groq atteint — attente 60s puis réessai...")
            time.sleep(60)
            return ollama_run(prompt)
        return f"⚠️ ERREUR GROQ: {error_msg}"

    if not out:
        return "⚠️ ERREUR: sortie agent vide."

    with open("debug_output.txt", "w", encoding="utf-8") as f:
        f.write(out)

    return out.strip()


# ============================================================
# UTILITAIRES
# ============================================================

def _norm(s: Any) -> str:
    s = "" if s is None else str(s)
    return re.sub(r"\s+", " ", s.strip().lower())


def _sev_rank(sev: Any) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(_norm(sev), 0)


def _prio_rank(p: Any) -> int:
    return {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}.get(str(p), 9)


def _conf_rank(conf: Any) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(_norm(conf), 0)


def _as_list_unique(x: Any) -> List[str]:
    if x is None:
        return []
    vals = [str(v).strip() for v in (x if isinstance(x, list) else [x]) if str(v).strip()]
    out = []
    for v in vals:
        if v not in out:
            out.append(v)
    return out

def _compact_evidence(ev: Any, max_items: int = 3, max_chars: int = 180) -> str:
    if ev is None:
        return "—"

    if isinstance(ev, list):
        parts = [str(x).strip() for x in ev if x is not None and str(x).strip()]
        s = ", ".join(parts[:max_items])
        if len(parts) > max_items:
            s += f" (+{len(parts)-max_items} autres)"
    else:
        s = str(ev).strip()

    s = " ".join(s.split())
    s_lower = s.lower()

    # CSP
  
    if "frame-ancestors" in s_lower or "form-action" in s_lower:
        return "Certaines directives CSP sensibles sont absentes ou incomplètes"

    if "unsafe-inline" in s_lower and "script-src" in s_lower and "style-src" in s_lower:
        return "Politique CSP autorise 'unsafe-inline' pour les scripts et styles"
    if "unsafe-inline" in s_lower and "script-src" in s_lower:
        return "Politique CSP autorise 'unsafe-inline' pour les scripts"
    if "unsafe-inline" in s_lower and "style-src" in s_lower:
        return "Politique CSP autorise 'unsafe-inline' pour les styles"

    if "default-src" in s_lower and "script-src" in s_lower:
        return "Configuration CSP trop permissive avec sources larges autorisées"
    # SRI
   
    if "<script" in s_lower and ("http://" in s_lower or "https://" in s_lower or "//" in s_lower):
        if "integrity=" in s_lower:
            return "Script externe avec attribut d’intégrité présent"
        return "Chargement de scripts depuis des domaines tiers"

    if "integrity=" in s_lower or "crossorigin=" in s_lower:
        return "Ressource externe détectée avec attributs de sécurité liés à l’intégrité"
    # Server header
    if "apache/" in s_lower or "nginx/" in s_lower or "iis" in s_lower:
        return f"Version du serveur exposée : {s[:80]}"

    # Fallback générique court
    if len(s) > max_chars:
        s = s[:max_chars].rstrip() + "…"

    return s if s else "—"


def _compact_target(f: Dict[str, Any]) -> str:
    return str(f.get("url") or f.get("host") or "—")


def _drop_empty_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def _text_blob(f: Dict[str, Any]) -> str:
    return _norm(" ".join([
        str(f.get("title") or ""),
        str(f.get("display_title") or ""),
        str(f.get("description") or ""),
        str(f.get("note") or ""),
        str(f.get("reference") or ""),
    ]))


def classify_finding_type(f: Dict[str, Any]) -> str:
    source = str(f.get("source") or "").strip().lower()
    severity = normalize_severity(f.get("severity"))
    text = _text_blob(f)
    matched_version = f.get("matched_version")

    if severity == "info":
        return "informational"

    if source == "cve":
        return "confirmed_cve" if matched_version is True else "potential_cve"

    tls_markers = [
        "tls", "ssl", "cipher", "sweet32", "lucky13", "beast", "breach",
        "poodle", "freak", "drown", "heartbleed", "logjam", "robot",
        "deprecated-tls", "weak-cipher", "weak cipher", "protocole depr",
    ]
    if any(m in text for m in tls_markers):
        return "tls_crypto"

    exposure_markers = [
        "cross-domain misconfiguration", "cross domain misconfiguration",
        "access-control-allow-origin", "port sensible expose", "server leaks",
        "x-powered-by", "google-calendar-exposure", "google calendar exposure",
        "timestamp disclosure",
    ]
    if any(m in text for m in exposure_markers):
        return "exposure"

    misconfig_markers = [
        "csp", "content security policy", "anti-clickjacking", "x-frame-options",
        "strict-transport-security", "hsts", "x-content-type-options",
        "cookie no httponly", "cookie without", "samesite", "secure flag",
        "sub resource integrity", "subresource integrity", "missing-sri",
        "cache-control", "fastly-debug", "permissions-policy", "referrer-policy",
    ]
    if any(m in text for m in misconfig_markers):
        return "web_misconfig"

    return "vulnerability_general"


# ============================================================
# PRIORITÉ
# ============================================================

def compute_priority(f: Dict[str, Any]) -> str:
    sev = normalize_severity(f.get("severity"))
    conf = str(f.get("confidence") or "").strip().lower()
    cvss = f.get("cvss")
    finding_type = f.get("finding_type") or classify_finding_type(f)

    def _cvss_bonus(value: Any) -> int:
        if isinstance(value, (int, float)):
            return min(int(value), 10)
        try:
            return min(int(float(str(value))), 10)
        except Exception:
            return 0

    if finding_type == "confirmed_cve":
        base = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
        return base.get(sev, "P5")

    if finding_type == "potential_cve":
        if sev in {"critical", "high"}:
            return "P3"
        if sev == "medium":
            return "P4"
        return "P5"

    if finding_type == "tls_crypto":
        title = str(f.get("title") or f.get("display_title") or "").lower()

        strong_tls = ["sweet32", "heartbleed", "drown", "poodle", "lucky13", "beast"]
        deprecated_tls = ["tls 1.0", "tls 1.1", "weak-cipher", "weak cipher", "deprecated-tls"]

        if any(k in title for k in strong_tls):
            if sev in {"critical", "high"}:
                return "P2"
            if sev == "medium":
                return "P3"
            return "P4"

        if any(k in title for k in deprecated_tls):
            if sev == "high":
                return "P3"
            if sev == "medium":
                return "P4"
            return "P5"

    # FIX: Les blocs exposure / web_misconfig / score numérique étaient
    # du code mort (unreachable) car un return inconditionnel les précédait.
    # Correction : placer le fallback générique EN DERNIER, après tous les blocs typés.

    if finding_type == "exposure":
        if sev in {"critical", "high"}:
            return "P2"
        if sev == "medium":
            return "P3"
        return "P4"

    if finding_type == "web_misconfig":
        if sev in {"critical", "high"}:
            return "P3"
        if sev == "medium":
            return "P4"
        return "P5"

    # Fallback : score numérique pour vulnerability_general
    base_score = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}.get(sev, 10)
    if conf == "high":
        base_score += 15
    elif conf == "medium":
        base_score += 8
    base_score += _cvss_bonus(cvss)

    if base_score >= 90:
        return "P1"
    if base_score >= 75:
        return "P2"
    if base_score >= 55:
        return "P3"
    if base_score >= 35:
        return "P4"
    return "P5"


def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
    return sorted(findings, key=lambda f: (order.get(f.get("priority", "P5"), 9), f.get("title") or ""))


# ============================================================
# DÉDUP INTER-SCANNERS
# ============================================================

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
        # FIX: inclure l'host dans la clé nuclei pour éviter les faux doublons
        # entre des findings nuclei identiques sur des hôtes différents
        host = _norm(f.get("url") or f.get("host") or "")
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

        for field in ["description", "solution", "reference", "risk", "cwe", "cvss", "note"]:
            if not m.get(field) and f.get(field):
                m[field] = f.get(field)

    out = []
    for m in merged.values():
        m["param"] = ", ".join(m.get("param", [])) if isinstance(m.get("param"), list) else (m.get("param") or "")
        targets = m.get("targets", [])
        m["targets"] = targets
        m["url"] = targets[0] if targets else (m.get("url") or "")
        m["evidence"] = ", ".join(m.get("evidences", [])) if m.get("evidences") else (m.get("evidence") or "")
        m["finding_type"] = classify_finding_type(m)
        m["kind"] = classify_finding_kind(m.get("severity"), m)
        out.append(m)

    return out


# ============================================================
# RAG / OWASP / PREP LLM
# ============================================================

def needs_rag(title: str, description: str = "") -> bool:
    text = f"{title or ''} {description or ''}".lower()
    keywords = [
        "csp", "content security policy", "clickjacking", "x-frame-options",
        "frame-ancestors", "integrity", "sri", "cve-", "sql injection", "xss",
        "cross-site scripting", "csrf", "cross-site request forgery",
        "open redirect", "reflected file download", "rest views",
        "organic groups", "webform", "views svg animation", "hsts",
        "strict-transport-security", "cookie", "cors", "cross-domain",
        "tls", "ssl", "breach", "beast", "lucky13",
    ]
    return any(k in text for k in keywords)


def compress_rag_context(rag_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
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


def is_rag_context_coherent(finding: Dict[str, Any], rag_docs: List[Dict[str, Any]]) -> bool:
    if not rag_docs:
        return False

    title = str(finding.get("title") or "").lower()
    description = str(finding.get("description") or "").lower()
    source = str(finding.get("source") or "").lower()
    owasp = str(finding.get("owasp_category") or "").lower()

    query_text = f"{title} {description} {owasp}"

    rag_text = " ".join(
        json.dumps(doc, ensure_ascii=False).lower()
        for doc in rag_docs[:2]
    )

    if source == "network_ssl" or any(x in query_text for x in ["tls", "ssl", "cipher", "sweet32", "lucky13", "breach", "beast"]):
        expected = ["tls", "ssl", "cipher", "sweet32", "lucky13", "breach", "beast", "cryptographic", "deprecated-tls", "weak-cipher"]
        return any(x in rag_text for x in expected)

    if "csp" in query_text or "content security policy" in query_text:
        expected = ["csp", "content security policy", "unsafe-inline", "unsafe-eval", "fallback", "wildcard"]
        return any(x in rag_text for x in expected)

    if "sub resource integrity" in query_text or "subresource integrity" in query_text or "integrity" in query_text:
        expected = ["sri", "integrity", "subresource"]
        return any(x in rag_text for x in expected)

    if "sql injection" in query_text or "sqli" in query_text:
        expected = ["sql injection", "sqli", "cwe-89"]
        return any(x in rag_text for x in expected)

    if "xss" in query_text or "cross-site scripting" in query_text or "cross site scripting" in query_text:
        expected = ["xss", "cross-site scripting", "cross site scripting"]
        return any(x in rag_text for x in expected)

    if "cross-domain misconfiguration" in query_text or "cross domain misconfiguration" in query_text or "access-control-allow-origin" in query_text:
        expected = ["cors", "cross-domain", "access-control-allow-origin"]
        return any(x in rag_text for x in expected)

    return True


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
        elif "tls" in combined or "ssl" in combined or "cipher" in combined:
            mapped_owasp = "A02:2021 - Cryptographic Failures"

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

            # FIX: valider la cohérence sur rag_docs complet (pas [:1])
            # avant de le comprimer — évite de perdre des docs valides
            tmp_finding = {
                "title": shown_title,
                "description": description,
                "source": source,
                "owasp_category": owasp_category,
            }

            if rag_docs and is_rag_context_coherent(tmp_finding, rag_docs):
                # compress sur les 2 premiers docs cohérents
                rag_context = _drop_empty_fields(compress_rag_context(rag_docs[:2]))
                print(f"✅ RAG cohérent pour: {shown_title} -> {rag_docs[0].get('title')}")
            else:
                rag_context = {}
                if rag_docs:
                    print(f"⚠️ RAG incohérent ignoré pour: {shown_title} -> {rag_docs[0].get('title')}")
                else:
                    print(f"ℹ️ Aucun RAG trouvé pour: {shown_title} -> fallback LLM")

        except Exception as e:
            print(f"⚠️ RAG erreur pour '{shown_title}': {e}")

    ref = f.get("reference") or f.get("cve_link")
    targets = f.get("targets") or []

    if not ref and targets:
        ref = targets[:5]

    if not ref:
        ref = "Non fourni"
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
        "severity": str(f.get("severity") or "Non fourni").upper(),
        "priority": f.get("priority") or "P5",
        "risk": f.get("risk") or "—",
        "confidence": f.get("confidence") or "—",
        "param": f.get("param") or "",
        "alertRef": f.get("alertRef") or "",
        "cwe": f.get("cwe") or "",
        "cve_id": cve_id or "",
        "published": f.get("published") or "",
    }

    if source == "cve" and f.get("matched_version") is True:
        sev = normalize_severity(f.get("severity"))
        if sev == "critical":
            remediation_delay = "sous 24h"
        elif sev == "high":
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
# DÉDUP ROWS LLM
# ============================================================

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



def _filter_row_for_llm_section_b(row: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "title",
        "description",
        "reference",
        "owasp_category",
        "severity",
       
        "matched_version",
        "module_name",
        "forced_recommendation",
        "cve_id",
        "cwe",
       
    }
    return {k: v for k, v in row.items() if k in allowed and v not in (None, "", [], {})}


def _filter_row_for_llm_section_c(row: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "title",
        "description",
        "module_name",
        "reference",
        "owasp_category",
        "severity",
    }
    return {k: v for k, v in row.items() if k in allowed and v not in (None, "", [], {})}


def _normalize_dedup_title(title: str) -> str:
    t = _norm(title)

    # équivalences métier
    if "sub resource integrity attribute missing" in t or "missing sri" in t:
        return "sub resource integrity"

    if "content security policy" in t or t.startswith("csp:") or "weak csp" in t:
        # on garde les variantes CSP spécifiques séparées
        if "failure to define directive with no fallback" in t:
            return "csp no fallback"
        if "wildcard directive" in t:
            return "csp wildcard"
        if "script src unsafe inline" in t:
            return "csp script unsafe inline"
        if "style src unsafe inline" in t:
            return "csp style unsafe inline"
        if "notices" in t:
            return "csp notices"
        return "csp generic"

    if "missing anti-clickjacking header" in t or "x-frame-options" in t:
        return "clickjacking"

    if "strict-transport-security header not set" in t or "http-missing-security-headers:strict-transport-security" in t:
        return "hsts"

    if "tls 1.0" in t or "deprecated-tls:tls_1.0" in t:
        return "tls 1.0"

    if "tls 1.1" in t or "deprecated-tls:tls_1.1" in t:
        return "tls 1.1"

    if "tls-version" in t:
        # tls-version brut est une observation technique
        return f"tls-version:{t}"

    return t


def _finding_dedup_key(f: Dict[str, Any]) -> str:
    cve_id = str(f.get("cve_id") or "").strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return cve_id

    title = str(f.get("display_title") or f.get("title") or "")
    desc = str(f.get("description") or "")

    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", title, flags=re.IGNORECASE)
    if m:
        return m.group(0).upper()

    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", desc, flags=re.IGNORECASE)
    if m:
        return m.group(0).upper()

    return _normalize_dedup_title(title)


def _row_dedup_key(row: Dict[str, Any]) -> str:
    cve_id = str(row.get("cve_id") or "").strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return cve_id

    title = row.get("title") or ""
    return _normalize_dedup_title(title)


def _is_pure_observation_row(row: Dict[str, Any]) -> bool:
    title = _norm(row.get("title"))
    kind = _norm(row.get("kind"))
    severity = _norm(row.get("severity"))

    if kind == "information":
        return True

    observation_markers = [
        "ssl-issuer",
        "ssl-dns-names",
        "wildcard-tls",
        "tls-version",
        "dkim-record-detect",
        "dmarc-detect",
        "spf-record-detect",
        "mx-fingerprint",
        "mx-service-detector",
        "nameserver-fingerprint",
        "txt-fingerprint",
        "aaaa-fingerprint",
        "caa-fingerprint",
        "drupal-detect",
        "drupal-login",
        "dns-waf-detect",
        "technologie détectée",
    ]

    if any(m in title for m in observation_markers):
        return True

    # les findings info marqués vulnerability par erreur -> observation
    if severity == "info":
        return True

    return False

# ============================================================
# ANNEXES
# ============================================================

def _make_annexe_row(f: Dict[str, Any]) -> Dict[str, Any]:
    sev = normalize_severity(f.get("severity"))
    
    priority = f.get("priority")
    if not priority or priority == "Non fourni":
        priority = compute_priority(f)

    description = f.get("description") or "Non fourni"
    raw_title = f.get("title") or "Non fourni"
    display_title = f.get("display_title") or raw_title
    source = str(f.get("source") or "").strip().lower()
    cve_id = f.get("cve_id") or (raw_title if raw_title.upper().startswith("CVE-") else None)

    if source == "cve":
        shown_title = cve_id or display_title or raw_title
    else:
        shown_title = display_title

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
        elif "tls" in combined or "ssl" in combined or "cipher" in combined:
            mapped_owasp = "A02:2021 - Cryptographic Failures"

    row = {
        "title": shown_title,
        "severity": sev,
        "priority": priority,
        "risk": f.get("risk") or "—",
        "confidence": f.get("confidence") or "—",
        "source": f.get("source", "Non fourni"),
        "kind": f.get("kind", "Non fourni"),
       
        "description": description,
        "evidence": _compact_evidence(f.get("evidence") or f.get("param")),
        "reference": ref_a,
        "owasp_category": mapped_owasp if mapped_owasp != "Non fourni" else (source_owasp or "Non fourni"),
        "alertRef": f.get("alertRef") or "",
        
    }

    cvss = f.get("cvss")
    if cvss not in (None, "", "Non fourni"):
        row["cvss"] = cvss

    return row


def build_annexe_table(all_compact: List[Dict[str, Any]]) -> str:
    headers = ["Priorité", "Titre", "Sévérité ",  "Preuve", "alertRef"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]

    for f in all_compact:
        row = [
            str(f.get("priority", "—")),
            str(f.get("title") or "—"),
            str(f.get("severity", "—")),
            str(f.get("evidence") or "—"),
            str(f.get("alertRef") or ""),
        ]
        row = [c.replace("\n", " ").replace("|", "\\|") for c in row]
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)


# ============================================================
# POST-TRAITEMENTS NARRATIF
# ============================================================

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
                output.append(f"{indent}  - Paramètre/Ressource affecté(e) : {param}")
                injected.add(fid)
                break

    return "\n".join(output)

def extract_section_b(report_text: str) -> str:
    m = re.search(
        r"(\*\*B\s*-\s*Vulnérabilités Prioritaires\*\*.*?)(?=\n\*\*C\s*-\s*Plan de remédiation\*\*|\Z)",
        report_text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return m.group(1).strip() if m else ""

def remove_empty_section_c(report_text: str, nb_potential_cves: int) -> str:
    if nb_potential_cves != 0:
        return report_text

    return re.sub(
        r"\nC\s*-\s*Vulnérabilités Potentielles à Valider\s*\n.*?(?=\nD\s*-\s*Plan de remédiation)",
        "\n",
        report_text,
        flags=re.DOTALL | re.IGNORECASE,
    ).strip()

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


# ============================================================
# SECTION B
# ============================================================
def _is_conf_ok_for_section_b(f: Dict[str, Any]) -> bool:
    finding_type = f.get("finding_type") or classify_finding_type(f)
    conf = str(f.get("confidence") or "").strip().lower()
    sev = normalize_severity(f.get("severity"))
    source = str(f.get("source") or "").strip().lower()

    # Toujours garder les CVE confirmées / potentielles et le TLS
    if finding_type in {"confirmed_cve", "potential_cve", "tls_crypto"}:
        return True

    # Findings Nuclei : garder si medium+
    if source == "nuclei":
        return sev in {"medium", "high", "critical"}

    # Findings ZAP / web misconfig : garder si medium+
    if finding_type == "web_misconfig":
        return sev in {"medium", "high", "critical"}

    # Exposition : garder si medium+
    if finding_type == "exposure":
        return sev in {"medium", "high", "critical"}

    # Fallback
    return conf in {"high", "medium"}



# ============================================================
# SCORE RISQUE
# ============================================================

def compute_risk_score(vulnerabilities: List[Dict[str, Any]], source_level: str = "medium") -> Dict[str, Any]:
    severity_points = {
        "critical": 40,
        "high": 22,
        "medium": 10,
        "low": 4,
        "info": 0,
    }

    type_multiplier = {
        "confirmed_cve": 1.0,
        "potential_cve": 0.30,
        "tls_crypto": 0.85,
        "exposure": 0.70,
        "web_misconfig": 0.45,
        "vulnerability_general": 0.80,
        "informational": 0.0,
    }

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0.0
    type_counts: Dict[str, int] = {}

    for f in vulnerabilities:
        severity = normalize_severity(f.get("severity"))
        finding_type = f.get("finding_type") or classify_finding_type(f)
        counts[severity] = counts.get(severity, 0) + 1
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1

        if severity == "info":
            continue

        base = severity_points.get(severity, 0)
        total += base * type_multiplier.get(finding_type, 0.8)

    if type_counts.get("confirmed_cve", 0) >= 1:
        total += 12
    if type_counts.get("tls_crypto", 0) >= 2:
        total += 8
    if counts["medium"] >= 4 and type_counts.get("web_misconfig", 0) >= 3:
        total += 3

    score = min(round(total), 100)
    source_level_norm = str(source_level or "").strip().lower()

    only_misconfig_like = all(
        (f.get("finding_type") or classify_finding_type(f)) in {"web_misconfig", "informational"}
        for f in vulnerabilities
    ) if vulnerabilities else True

    no_strong_core_risk = not any(
        (f.get("finding_type") or classify_finding_type(f)) in {"confirmed_cve", "tls_crypto"}
        and normalize_severity(f.get("severity")) in {"critical", "high", "medium"}
        for f in vulnerabilities
    )

    if only_misconfig_like and no_strong_core_risk:
        score = min(score, 35)

    if counts["critical"] == 0 and counts["high"] == 0:
        score = min(score, 60)

    if source_level_norm == "medium" and counts["critical"] == 0 and counts["high"] == 0:
        score = min(score, 60)

    if counts["critical"] == 0 and counts["high"] == 0 and counts["medium"] == 0:
        score = min(score, 25)

    has_confirmed_critical = any(
        (f.get("finding_type") or classify_finding_type(f)) == "confirmed_cve"
        and normalize_severity(f.get("severity")) == "critical"
        for f in vulnerabilities
    )

    has_confirmed_high = any(
        (f.get("finding_type") or classify_finding_type(f)) == "confirmed_cve"
        and normalize_severity(f.get("severity")) == "high"
        for f in vulnerabilities
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
        "type_counts": type_counts,
    }


def cleanup_manual_validation_text(report_text: str) -> str:
    patterns_to_remove = [
        r"^\s*Validation manuelle recommandée\.?\s*$",
        r"^.*Annexe A.*$",
        r"^\s*Il est essentiel de procéder à une validation manuelle.*?\s*$",
        r"^\s*Puisque\s*0\s+vulnérabilités?\s+potentielles?.*?\s*$",
        r"^\s*Aucune validation manuelle n'est recommandée\.?\s*$",
    ]

    cleaned = report_text
    for pattern in patterns_to_remove:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.MULTILINE)

    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


# ============================================================
# ANALYSE PRINCIPALE
# ============================================================

def analyze_full(findings: List[Dict[str, Any]], metadata: Dict[str, Any], top_n: int = 15) -> str:
    # --------------------------------------------------------
    # 1) Déduplication inter-scanners
    # --------------------------------------------------------
    findings = dedupe_merge_across_scanners(findings)
    print("\n" + "=" * 80)
    print(f"Total findings dédupliqués : {len(findings)}")
    print("=" * 80)

    # --------------------------------------------------------
    # 2) Enrichissement NVD
    # --------------------------------------------------------
    enrich_cves(findings, api_key=None, sleep_sec=6)

 
    # 3) Recalcul des priorités
    # --------------------------------------------------------
    for f in findings:
        f["finding_type"] = classify_finding_type(f)
        f["priority"] = compute_priority(f)
        f["kind"] = classify_finding_kind(f.get("severity"), f)
    findings = sort_findings(findings)

    # --------------------------------------------------------
   


    # --------------------------------------------------------
    # 4) Split clair : vulnérabilités / infos
    # --------------------------------------------------------

    vulnerabilities, informations = split_findings(findings)

    potential_cves = []            # CVE matched_version=False + HIGH/CRITICAL
    hidden_unconfirmed_cves = []   # CVE matched_version=False + LOW/MEDIUM/INFO
    reportable_vulns = []

    for f in vulnerabilities:
        is_unconfirmed_cve = (
            str(f.get("source") or "").lower() == "cve"
            and f.get("matched_version") is False
        )

        if is_unconfirmed_cve:
            sev = normalize_severity(f.get("severity"))

            if sev in {"high", "critical"}:
                potential_cves.append(f)
            else:
                hidden_unconfirmed_cves.append(f)
            continue

        if normalize_severity(f.get("severity")) != "info":
            reportable_vulns.append(f)

    reportable_info = informations

   

    # --------------------------------------------------------
    # 5) Comptages cohérents
    # --------------------------------------------------------
    all_stats = build_summary_stats(findings)
    vuln_counts = count_severity(reportable_vulns, vulnerabilities_only=False)
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
            computed_val = vuln_counts.get(sev_key, 0)
            if json_val != computed_val:
                if not divergence_found:
                    print("\n⚠️ DIVERGENCE severity_counts JSON vs Calculé :")
                    divergence_found = True
                print(f"   '{sev_key}': JSON={json_val} | Calculé={computed_val}")
        if not divergence_found:
            print("✅ severity_counts JSON == Calculé")
    
    def business_score(f: Dict[str, Any]) -> int:
        title = _norm(f.get("title"))
        owasp = _norm(f.get("owasp_category"))
        finding_type = f.get("finding_type") or classify_finding_type(f)
        sev = normalize_severity(f.get("severity"))

        score = 0

        # 1) type métier
        if finding_type == "confirmed_cve":
            score += 100
        elif finding_type == "tls_crypto":
            score += 90
        elif finding_type == "exposure":
            score += 75
        elif finding_type == "web_misconfig":
            score += 40
        else:
            score += 30

        # 2) sévérité
        if sev == "critical":
            score += 40
        elif sev == "high":
            score += 30
        elif sev == "medium":
            score += 15
        elif sev == "low":
            score += 5

        # 3) bonus OWASP / impact métier
        if "injection" in owasp:
            score += 35
        if "broken access control" in owasp:
            score += 30
        if "cryptographic failures" in owasp:
            score += 25
        if "software and data integrity failures" in owasp:
            score += 12

        # 4) bonus précis par titre
        if "tls 1.0" in title:
            score += 35
        elif "sweet32" in title:
            score += 28
        elif "lucky13" in title:
            score += 22
        elif "tls 1.1" in title:
            score += 12

        elif "csp: failure to define directive with no fallback" in title:
            score += 20
        elif "csp: script-src unsafe-inline" in title:
            score += 17
        elif "csp: style-src unsafe-inline" in title:
            score += 14
        elif "content security policy (csp) header not set" in title:
            score += 10
        elif "csp: wildcard directive" in title:
            score += 8

        elif "sub resource integrity" in title:
            score += 10
        elif "anti-clickjacking" in title:
            score += 7
        elif "cookie" in title:
            score += 3

        return score


    # --------------------------------------------------------
    # 6) Filtrage section B
    # --------------------------------------------------------
  
    candidates_section_b = [
        f for f in reportable_vulns
        if normalize_severity(f.get("severity")) != "low"
        and str(f.get("priority")) in {"P1", "P2", "P3", "P4"}
        and _is_conf_ok_for_section_b(f)
    ]

    if len(candidates_section_b) < 4:
        extra_mediums = [
            f for f in reportable_vulns
            if normalize_severity(f.get("severity")) == "medium"
            and f not in candidates_section_b
        ]
        extra_mediums = sorted(
            extra_mediums,
            key=lambda f: (
                -business_score(f),
                _prio_rank(f.get("priority")),
                -_sev_rank(f.get("severity")),
                str(f.get("title") or ""),
            ),
        )
        candidates_section_b.extend(extra_mediums[: 4 - len(candidates_section_b)])
        

    
    


    prioritized_for_section_b = sorted(
        candidates_section_b,
        key=lambda f: (
            -business_score(f),
            _prio_rank(f.get("priority")),
            -_sev_rank(f.get("severity")),
            str(f.get("title") or ""),
        ),
    )

    # conserver tous les findings jugés prioritaires
    top_findings = prioritized_for_section_b

    # fallback : si rien ne remonte, garder le meilleur MEDIUM
    if not top_findings:
        medium_fallback = [
            f for f in reportable_vulns
            if normalize_severity(f.get("severity")) == "medium"
        ]
        if medium_fallback:
            medium_fallback = sorted(
                medium_fallback,
                key=lambda f: (-business_score(f), str(f.get("title") or ""))
            )
            top_findings = [medium_fallback[0]]

    print(f"\nSection B — après priorisation métier : {len(top_findings)}")

    # --------------------------------------------------------
    # 7) Rows LLM
    # --------------------------------------------------------
    top_llm_rows = make_llm_rows_parallel(top_findings, metadata, max_workers=6)
    top_llm_rows = dedupe_llm_rows(top_llm_rows)
    top_llm_rows_filtered = [_filter_row_for_llm_section_b(row) for row in top_llm_rows]

    potential_llm_rows = make_llm_rows_parallel(potential_cves, metadata, max_workers=6) if potential_cves else []
    potential_llm_rows = dedupe_llm_rows(potential_llm_rows)
    clean_potential_llm_rows = [_filter_row_for_llm_section_c(row) for row in potential_llm_rows]

    # clés des findings déjà affichés en section B
    section_b_keys = {_finding_dedup_key(f) for f in top_findings}


    all_annexe_rows = []
    seen_annexe_keys = set()

    for f in findings:
        is_unconfirmed_cve = (
            str(f.get("source") or "").lower() == "cve"
            and f.get("matched_version") is False
        )
        if is_unconfirmed_cve:
            continue

        row = _make_annexe_row(f)
        key = _finding_dedup_key(f)

        # 1) supprimer tout ce qui est déjà en section B
        if key in section_b_keys:
            continue

   

        # 3) supprimer les observations pures mal classées en vulnérabilité
        if (
            _is_pure_observation_row(row)
            and str(row.get("source", "")).lower() not in {"zap", "nuclei", "cve", "network_ssl", "network_ports"}
        ):
            row["kind"] = "information"
            row["severity"] = "info"
            row["priority"] = "P5"
        # 4) supprimer les doublons internes de l'annexe B
        row_key = _row_dedup_key(row)
        if row_key in seen_annexe_keys:
            continue
        seen_annexe_keys.add(row_key)

        all_annexe_rows.append(row)

    annexe_md = build_annexe_table(all_annexe_rows)


    print(
    f"Total findings annexe : {len(all_annexe_rows)} | "
    f"Vulnérabilités reportables : {len(reportable_vulns)} | "
    f"Infos : {len(reportable_info)} | "
    f"CVE potentielles à valider : {len(potential_cves)} | "
    f"CVE non confirmées masquées : {len(hidden_unconfirmed_cves)}"
)

    # --------------------------------------------------------
    # 8) Détection secteur
    # --------------------------------------------------------
    target_url = metadata.get("target_url") or ""
    sector = "Non fourni"
    regulatory_context = "Non fourni"

    banking_keywords = ["bank", "banque", "credit", "finance", "biat", "stb", "bh ", "bnp", "atb"]
    if any(kw in target_url.lower() for kw in banking_keywords):
        sector = "Secteur bancaire / financier"
        regulatory_context = (
            "BCT (Banque Centrale de Tunisie), circulaire n°2021-05 sur la cybersécurité, "
            "PCI-DSS si paiement en ligne"
        )

    # --------------------------------------------------------
    # 9) Prompt
    # --------------------------------------------------------
    is_complete = str(metadata.get("mode") or "").lower() == "complete"


    prompt_kwargs = dict(
    scan_id=metadata.get("scan_id") or "Non fourni",
    target_url=metadata.get("target_url") or "Non fourni",
    cms=metadata.get("cms") or "Non fourni",
    cms_version=metadata.get("cms_version") or "Non fourni",
    mode=metadata.get("mode") or "Non fourni",
    total_vulnerabilities=len(reportable_vulns),
    created_at=metadata.get("created_at") or "Non fourni",
    scan_time_sec=metadata.get("scan_time_sec") if metadata.get("scan_time_sec") is not None else "Non fourni",
    severity_counts=json.dumps(metadata.get("severity_counts") or {}, ensure_ascii=False),
    computed_severity_counts=json.dumps(vuln_counts, ensure_ascii=False),
    total_findings_extraits=len(findings),
    top_findings_json=json.dumps(top_llm_rows_filtered, ensure_ascii=False, indent=2),
    potential_cves_json=json.dumps(clean_potential_llm_rows, ensure_ascii=False, indent=2),
    nb_prioritaires=len(top_llm_rows_filtered),
    nb_potential_cves=len(clean_potential_llm_rows),
   
    risk_level_computed=risk_data["level"],
    sector=sector,
    regulatory_context=regulatory_context,
)

    if is_complete:
        prompt = REPORT_PROMPT_COMPLETE.format(
            **prompt_kwargs,
            ssl_grade=metadata.get("ssl_grade") or "",
            open_ports_count=metadata.get("open_ports_count") or 0,
            whois_org=metadata.get("whois_org") or "Non fourni",
        )
    else:
        prompt = REPORT_PROMPT.format(**prompt_kwargs)

    with open("debug_prompt.txt", "w", encoding="utf-8") as f:
        f.write(prompt)
    print("Prompt sauvegardé dans debug_prompt.txt")

    # --------------------------------------------------------
    # 10) Génération LLM
    # --------------------------------------------------------
    start_llm = time.time()
    narrative = ollama_run(prompt)
    llm_seconds = time.time() - start_llm
    print(f"⚡ Temps génération Groq : {llm_seconds:.2f}s ({llm_seconds/60:.2f} min)")

    # --------------------------------------------------------
    # 11) Post-traitements
    # --------------------------------------------------------
    narrative = strip_llm_cvss_lines(narrative)
    narrative = dedupe_section_b(narrative)
    narrative = inject_cvss_in_section_b(narrative, top_findings)
    narrative = inject_param_in_section_b(narrative, top_findings)
    narrative = dedupe_section_b(narrative)
    narrative = cleanup_manual_validation_text(narrative)
    
    # --------------------------------------------------------
    # 12) Tableau de synthèse cohérent
    # --------------------------------------------------------
    sev = vuln_counts


    summary_table = f"""
    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | {sev.get('low', 0)} | {info_count} |

    **Niveau de risque global : {risk_data['level']}**

    **Vulnérabilités confirmées retenues dans le rapport :** {len(reportable_vulns)}  
    **Vulnérabilités potentielles à valider :** {len(potential_llm_rows)}  
    **Éléments informationnels :** {len(reportable_info)}  
    **Prioritaires confirmées (section B) :** {len(top_findings)} 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    """

    # --------------------------------------------------------
    # 13) Rapport final
    # --------------------------------------------------------
    report = narrative.strip() + "\n\n" + summary_table + "\n\n"

   

    report += (
        "## Annexe  - Liste complète des findings dédupliqués (TOUS)\n\n"
        + annexe_md
        + "\n"
    )

    return report