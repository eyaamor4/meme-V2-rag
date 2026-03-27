import json
import os
import re
from typing import Any, Dict, List, Set, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer


MODEL_NAME = "all-MiniLM-L6-v2"
MODEL = SentenceTransformer(MODEL_NAME)


def _normalize_text(s: Any) -> str:
    if s is None:
        return ""
    s = str(s).strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _normalize_key(s: Any) -> str:
    s = _normalize_text(s)
    s = s.replace("_", " ").replace("-", " ")
    s = re.sub(r"[^\w\s:]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, dict):
        return [str(v).strip() for v in value.values() if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _extract_cves(text: str) -> List[str]:
    if not text:
        return []
    found = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)
    return list(dict.fromkeys([x.upper() for x in found]))


def _build_doc_text(doc: Dict[str, Any]) -> str:
    parts = []

    parts.append(doc.get("title", ""))
    parts.append(doc.get("description", ""))
    parts.append(doc.get("owasp", ""))
    parts.append(doc.get("cwe", ""))

    parts.extend(_to_list(doc.get("tags")))
    parts.extend(_to_list(doc.get("keywords")))
    parts.extend(_to_list(doc.get("aliases")))
    parts.extend(_to_list(doc.get("cves")))

    return " ".join([p for p in parts if p]).strip()


def load_knowledge_base(path: str = None) -> List[Dict[str, Any]]:
    if path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_1 = os.path.join(base_dir, "knowledge_base", "security_knowledge.json")
        candidate_2 = os.path.join(base_dir, "security_knowledge.json")

        if os.path.exists(candidate_1):
            path = candidate_1
        elif os.path.exists(candidate_2):
            path = candidate_2
        else:
            raise FileNotFoundError(
                "Impossible de trouver security_knowledge.json. "
                "Place le fichier dans knowledge_base/security_knowledge.json "
                "ou dans le même dossier que rag_vector.py"
            )

    with open(path, "r", encoding="utf-8") as f:
        raw_docs = json.load(f)

    docs = []
    for raw in raw_docs:
        aliases = raw.get("aliases", [])

        cves_from_fields = _extract_cves(
            " ".join([
                str(raw.get("title", "")),
                str(raw.get("description", "")),
                " ".join(_to_list(raw.get("aliases"))),
                " ".join(_to_list(raw.get("tags"))),
                " ".join(_to_list(raw.get("keywords"))),
                " ".join(_to_list(raw.get("references"))),
            ])
        )

        item = {
            "id": raw.get("id", ""),
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "owasp": raw.get("owasp", ""),
            "cwe": raw.get("cwe", ""),
            "tags": raw.get("tags", []),
            "keywords": raw.get("keywords", []),
            "aliases": aliases,
            "cves": cves_from_fields,
            "recommendation": raw.get("recommendation", ""),
            "recommendation_summary": raw.get("recommendation_summary", ""),
            "technical_actions": raw.get("technical_actions", []),
            "implementation_examples": raw.get("implementation_examples", {}),
            "verification": raw.get("verification", ""),
            "verification_steps": raw.get("verification_steps", []),
            "report_template": raw.get("report_template", ""),
            "affected_technologies": raw.get("affected_technologies", []),
            "affected_components": raw.get("affected_components", []),
            "notes": raw.get("notes", []),
            "references": raw.get("references", []),
        }
        item["_search_text"] = _build_doc_text(item)
        docs.append(item)

    return docs


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    na = np.linalg.norm(a)
    nb = np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def _exact_title_match(title: str, docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    query = _normalize_key(title)
    if not query:
        return []

    matches = []
    for doc in docs:
        doc_title = _normalize_key(doc.get("title", ""))
        aliases = [_normalize_key(a) for a in _to_list(doc.get("aliases"))]

        if query == doc_title or query in aliases:
            matches.append(doc)

    return matches


def _exact_cve_match(cves: List[str], docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not cves:
        return []

    cve_set = {c.upper() for c in cves}
    matches = []

    for doc in docs:
        doc_cves = {c.upper() for c in _to_list(doc.get("cves"))}
        aliases = " ".join(_to_list(doc.get("aliases"))).upper()
        title = str(doc.get("title", "")).upper()
        desc = str(doc.get("description", "")).upper()
        search_text = str(doc.get("_search_text", "")).upper()

        if doc_cves & cve_set:
            matches.append(doc)
            continue

        for cve in cve_set:
            if cve in aliases or cve in title or cve in desc or cve in search_text:
                matches.append(doc)
                break

    return matches


def _classify_vuln_type(title: str) -> str:
    t = _normalize_key(title)

    if "content security policy csp header not set" in t or "csp header not set" in t:
        return "csp_header_missing"
    if "failure to define directive with no fallback" in t:
        return "csp_no_fallback"
    if "wildcard directive" in t:
        return "csp_wildcard"
    if "script src unsafe inline" in t:
        return "csp_script_unsafe_inline"
    if "style src unsafe inline" in t:
        return "csp_style_unsafe_inline"
    if "script src unsafe eval" in t:
        return "csp_script_unsafe_eval"
    if "cookie no httponly flag" in t or "cookies without httponly" in t:
        return "cookie_httponly_missing"
    if "cookie without secure flag" in t or "cookies without secure" in t:
        return "cookie_secure_missing"
    if "cookie without samesite attribute" in t or "missing cookie samesite" in t:
        return "cookie_samesite_missing"
    if "server leaks information via x powered by http response header field" in t:
        return "x_powered_by_exposure"
    if "server leaks version information via server http response header field" in t:
        return "server_header_version_disclosure"
    if "cross domain javascript source file inclusion" in t:
        return "cross_domain_js"
    if "absence of anti csrf tokens" in t:
        return "csrf_token_missing"
    if "missing anti clickjacking header" in t or "x frame options header missing" in t:
        return "clickjacking_missing"
    if "sub resource integrity attribute missing" in t or "subresource integrity attribute missing" in t:
        return "sri_missing"
    if "strict transport security header not set" in t or "hsts header not set" in t:
        return "hsts_missing"
    if "x content type options header missing" in t:
        return "x_content_type_options_missing"
    if "permissions policy header missing" in t:
        return "permissions_policy_missing"
    if "cross origin opener policy header missing" in t:
        return "coop_missing"
    if "cross origin embedder policy header missing" in t:
        return "coep_missing"
    if "cross origin resource policy header missing" in t:
        return "corp_missing"
    if "x permitted cross domain policies header missing" in t:
        return "x_permitted_cross_domain_policies_missing"
    if "clear site data header missing" in t:
        return "clear_site_data_missing"
    if "sql injection" in t or "sqli" in t:
        return "sql_injection"
    if "cross site scripting" in t or "xss" in t:
        return "xss"
    if "cross site request forgery" in t or "csrf" in t:
        return "csrf"
    if "open redirect" in t:
        return "open_redirect"
    if "reflected file download" in t:
        return "reflected_file_download"
    if "rest views" in t:
        return "rest_views_exposure"
    if "organic groups" in t or " og " in f" {t} ":
        return "og_access_issue"
    if "views svg animation" in t:
        return "views_svg_xss"
    if "views module" in t and ("access" in t or "hidden content" in t or "statistics" in t):
        return "views_access_bypass"
    if "webform" in t and ("session" in t or "cache" in t):
        return "webform_session_exposure"
    if "webform" in t and ("xss" in t or "cross site scripting" in t):
        return "webform_xss"
    if "views module" in t and ("xss" in t or "cross site scripting" in t):
        return "views_xss"
    if "cve-" in t:
        return "generic_cve"

    return "generic"


def _same_vuln_family(
    finding_title: str,
    doc_title: str,
    finding_desc: str = "",
    doc_desc: str = ""
) -> bool:
    finding_type = _classify_vuln_type(f"{finding_title} {finding_desc}")
    doc_type = _classify_vuln_type(f"{doc_title} {doc_desc}")

    if finding_type == "generic" or doc_type == "generic":
        return False

    return finding_type == doc_type


def _keyword_prefilter(title: str, description: str, docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    q_all = _normalize_key(f"{title} {description}")
    q_tokens = [t for t in q_all.split() if len(t) >= 4]

    if not q_tokens:
        return docs

    filtered = []
    threshold = 2 if len(q_tokens) >= 4 else 1

    for doc in docs:
        searchable = _normalize_key(doc.get("_search_text", ""))
        hit_count = sum(1 for tok in q_tokens if tok in searchable)

        if hit_count >= threshold:
            filtered.append(doc)

    return filtered if filtered else docs


def _specificity_score_for_exact_match(
    finding_title: str,
    finding_desc: str,
    doc: Dict[str, Any]
) -> float:
    ft = _normalize_key(f"{finding_title} {finding_desc}")
    searchable = _normalize_key(" ".join([
        str(doc.get("title", "")),
        str(doc.get("description", "")),
        " ".join(_to_list(doc.get("aliases"))),
        " ".join(_to_list(doc.get("tags"))),
        " ".join(_to_list(doc.get("keywords"))),
    ]))

    score = 0.0

    strong_terms = [
        "rest views", "views svg animation", "organic groups",
        "system module", "webform", "views", "drupal",
    ]
    for term in strong_terms:
        if term in ft and term in searchable:
            score += 0.30

    vuln_terms = [
        "sql injection", "cross site scripting", "xss", "csrf",
        "reflected file download", "forceful browsing", "sensitive information",
        "access restriction", "hidden content", "open redirect",
    ]
    for term in vuln_terms:
        if term in ft and term in searchable:
            score += 0.20

    doc_title = _normalize_key(doc.get("title", ""))
    if "drupal" in doc_title:
        score += 0.08
    if "module" in doc_title:
        score += 0.05

    return score


def _boost_score(
    query_title: str,
    query_desc: str,
    query_owasp: str,
    query_cwe: str,
    query_cves: List[str],
    doc: Dict[str, Any],
) -> float:
    q_title = _normalize_key(query_title)
    q_owasp = _normalize_key(query_owasp)
    q_cwe = _normalize_key(query_cwe)
    q_all = _normalize_key(f"{query_title} {query_desc} {query_owasp} {query_cwe}")

    searchable = _normalize_key(doc.get("_search_text", ""))
    boost = 0.0

    doc_title = _normalize_key(doc.get("title", ""))
    aliases = [_normalize_key(a) for a in _to_list(doc.get("aliases"))]

    query_type = _classify_vuln_type(query_title)
    doc_type = _classify_vuln_type(doc.get("title", ""))

    if q_title and (q_title == doc_title or q_title in aliases):
        boost += 1.20

    doc_cves = {c.upper() for c in _to_list(doc.get("cves"))}
    query_cve_set = {c.upper() for c in query_cves}
    if doc_cves & query_cve_set:
        boost += 1.50

    if query_type != "generic" and doc_type != "generic":
        if query_type == doc_type:
            boost += 0.90
        else:
            boost -= 1.20

    if q_owasp and q_owasp in searchable:
        boost += 0.15
    if q_cwe and q_cwe in searchable:
        boost += 0.20

    if query_type == "csp_header_missing":
        if "content security policy" in searchable or "csp" in searchable:
            boost += 0.25
        if "header not set" in searchable or "missing csp" in searchable:
            boost += 0.35
    elif query_type == "csp_no_fallback":
        if "no fallback" in searchable or "form action" in searchable or "frame ancestors" in searchable:
            boost += 0.35
    elif query_type == "csp_wildcard":
        if "wildcard" in searchable or "*" in str(doc.get("title", "")):
            boost += 0.35
    elif query_type == "csp_script_unsafe_inline":
        if "script src unsafe inline" in searchable:
            boost += 0.40
    elif query_type == "csp_style_unsafe_inline":
        if "style src unsafe inline" in searchable:
            boost += 0.40
    elif query_type == "clickjacking_missing":
        if any(x in searchable for x in ["clickjacking", "x frame options", "frame ancestors"]):
            boost += 0.40
    elif query_type == "sri_missing":
        if any(x in searchable for x in ["subresource integrity", "sub resource integrity", "sri", "integrity"]):
            boost += 0.40
    elif query_type == "hsts_missing":
        if any(x in searchable for x in ["strict transport security", "hsts"]):
            boost += 0.40
    elif query_type == "sql_injection":
        if any(x in searchable for x in ["sql injection", "sqli"]):
            boost += 0.40
    elif query_type == "xss":
        if any(x in searchable for x in ["xss", "cross site scripting"]):
            boost += 0.40
    elif query_type == "csrf":
        if any(x in searchable for x in ["csrf", "cross site request forgery"]):
            boost += 0.40
    elif query_type == "open_redirect":
        if "open redirect" in searchable:
            boost += 0.40
    elif query_type == "reflected_file_download":
        if "reflected file download" in searchable:
            boost += 0.40
    elif query_type == "rest_views_exposure":
        if "rest views" in searchable:
            boost += 0.45
    elif query_type == "og_access_issue":
        if any(x in searchable for x in ["organic groups", "og"]):
            boost += 0.45
    elif query_type == "views_svg_xss":
        if "views svg animation" in searchable:
            boost += 0.45
    elif query_type == "views_access_bypass":
        if "views" in searchable and any(x in searchable for x in ["hidden content", "access", "statistics"]):
            boost += 0.45
    elif query_type == "webform_session_exposure":
        if "webform" in searchable and any(x in searchable for x in ["session", "cache"]):
            boost += 0.45
    elif query_type == "webform_xss":
        if "webform" in searchable and any(x in searchable for x in ["xss", "cross site scripting"]):
            boost += 0.45
    elif query_type == "views_xss":
        if "views" in searchable and any(x in searchable for x in ["xss", "cross site scripting"]):
            boost += 0.45
    elif query_type == "cookie_httponly_missing":
        if any(x in searchable for x in ["httponly", "cookie no httponly", "cookies without httponly"]):
            boost += 0.40
    elif query_type == "cookie_secure_missing":
        if any(x in searchable for x in ["secure flag", "without secure", "cookies without secure"]):
            boost += 0.40
    elif query_type == "cookie_samesite_missing":
        if any(x in searchable for x in ["samesite", "cookie without samesite", "missing cookie samesite"]):
            boost += 0.40
    elif query_type == "x_powered_by_exposure":
        if any(x in searchable for x in ["x powered by", "server leaks", "information disclosure"]):
            boost += 0.40
    elif query_type == "server_header_version_disclosure":
        if any(x in searchable for x in ["server header", "server version disclosure"]):
            boost += 0.40
    elif query_type == "cross_domain_js":
        if any(x in searchable for x in ["cross domain javascript", "third party script", "external javascript"]):
            boost += 0.40
    elif query_type == "csrf_token_missing":
        if any(x in searchable for x in ["csrf", "anti csrf", "cross site request forgery"]):
            boost += 0.40

    if "drupal" in q_all and "drupal" in searchable:
        boost += 0.08

    return boost


# Chargement global
DOCS = load_knowledge_base()
DOC_EMBEDDINGS = MODEL.encode([doc["_search_text"] for doc in DOCS], convert_to_numpy=True)
DOC_ID_TO_INDEX = {doc["id"]: idx for idx, doc in enumerate(DOCS)}


def retrieve_knowledge(
    title: str,
    description: str = "",
    owasp: str = "",
    cwe: str = "",
    technology: str = "",
    component: str = "",
    reference: str = "",
    top_k: int = 2,
    min_score: float = 0.60,
) -> List[Dict[str, Any]]:
    try:
        query_blob = " ".join([
            str(title or ""),
            str(description or ""),
            str(reference or ""),
        ])
        query_cves = _extract_cves(query_blob)

        # 1) Exact match CVE + reranking spécifique
        exact_cve = _exact_cve_match(query_cves, DOCS)
        if exact_cve:
            ranked = sorted(
                exact_cve,
                key=lambda d: _specificity_score_for_exact_match(title, description, d),
                reverse=True,
            )
            out = []
            for doc in ranked[:top_k]:
                item = doc.copy()
                item["score"] = round(1.0 + _specificity_score_for_exact_match(title, description, doc), 4)
                out.append(item)

            print("\n=== RAG EXACT CVE MATCH ===")
            print("Query title:", title)
            for x in out:
                print("Selected:", x.get("title"), "| score =", x.get("score"))
            return out

        # 2) Exact match title / alias
        exact = _exact_title_match(title, DOCS)
        if exact:
            out = []
            for doc in exact[:top_k]:
                item = doc.copy()
                item["score"] = 1.0
                out.append(item)

            print("\n=== RAG EXACT TITLE MATCH ===")
            print("Query title:", title)
            for x in out:
                print("Selected:", x.get("title"), "| score =", x.get("score"))
            return out

        # 3) Préfiltre keyword large
        filtered_docs = _keyword_prefilter(title, description, DOCS)

        # 4) Embedding query enrichie
        query_text = " ".join([
            str(title or ""),
            str(description or ""),
            str(owasp or ""),
            str(cwe or ""),
            str(technology or ""),
            str(component or ""),
            str(reference or ""),
            " ".join(query_cves),
        ]).strip()

        query_embedding = MODEL.encode(query_text, convert_to_numpy=True)

        results = []
        for doc in filtered_docs:
            idx = DOC_ID_TO_INDEX[doc["id"]]
            emb_score = _cosine_similarity(query_embedding, DOC_EMBEDDINGS[idx])

            score = emb_score + _boost_score(
                query_title=title,
                query_desc=description,
                query_owasp=owasp,
                query_cwe=cwe,
                query_cves=query_cves,
                doc=doc,
            )

            item = doc.copy()
            item["score"] = round(score, 4)
            results.append(item)

        results.sort(key=lambda x: x["score"], reverse=True)
        results = results[: max(top_k * 2, top_k)]

        print("\n=== RAG RAW RESULTS ===")
        print("Query title:", title)
        for r in results:
            print(" -", r.get("title"), "| score =", r.get("score"))

        # 5) Validation famille
        validated = [
            r for r in results
            if _same_vuln_family(
                title,
                r.get("title", ""),
                description,
                r.get("description", "")
            )
        ]
        if validated:
            strong = [r for r in validated if r["score"] >= min_score]
            final = strong if strong else validated[:top_k]

            print("\n=== RAG VALIDATED RESULTS ===")
            for r in final[:top_k]:
                print(" -", r.get("title"), "| score =", r.get("score"))
            return final[:top_k]

        # ─── CORRECTION : return [] supprimé ici ─────────────────────────────
        # Avant : return [] bloquait l'accès au fallback (code mort)
        # Maintenant : on tombe dans le fallback si aucun doc validé

        # 6) Fallback — résultats par score embedding seul
        print("\n=== RAG FALLBACK RESULTS ===")
        print("Query title:", title)
        print("No validated document found. Trying score-based fallback.")

        strong = [r for r in results if r["score"] >= min_score]
        final = strong if strong else results[:top_k]

        for r in final[:top_k]:
            print(" -", r.get("title"), "| score =", r.get("score"))

        return final[:top_k]

    except Exception as e:
        print(f"⚠️ Erreur retrieve_knowledge: {e}")
        return []