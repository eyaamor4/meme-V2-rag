import json
from typing import Any, Dict, List, Optional


import json
import re
from typing import Any, Dict, List, Optional


def safe_get(d: Dict[str, Any], *keys: str, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def safe_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []

def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def normalize_cve_id(value: Any) -> str:
    if not value:
        return ""
    s = str(value).strip().upper()
    m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", s)
    return m.group(0) if m else s

def classify_finding_kind(severity: str) -> str:
    sev = normalize_severity(severity)
    if sev in {"critical", "high", "medium", "low"}:
        return "vulnerability"
    return "information"


def normalize_severity(sev: Optional[str]) -> str:
    if not sev:
        return "info"
    s = str(sev).strip().lower()
    mapping = {
        "informational": "info",
        "information": "info",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get(s, s)


def confidence_rank(conf: Optional[str]) -> int:
    """Higher is better."""
    c = (conf or "").strip().lower()
    if c == "high":
        return 3
    if c == "medium":
        return 2
    if c == "low":
        return 1
    return 0


def normalize_confidence(conf: Optional[str]) -> str:
    c = (conf or "").strip().lower()
    if c in {"high", "medium", "low"}:
        return c.capitalize()
    return "Non fourni"




def severity_to_priority(sev: str) -> str:
    sev = normalize_severity(sev)
    if sev == "critical":
        return "P1"
    if sev == "high":
        return "P2"
    if sev == "medium":
        return "P3"
    if sev == "low":
        return "P4"
    return "P5"


def get_scan_root(data: Dict[str, Any]) -> Dict[str, Any]:
    s = data.get("scan")
    return s if isinstance(s, dict) else data


# ─── CORRECTION 1 : extract_metadata extrait cms_version ─────────────────────
def extract_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    scan = get_scan_root(data)

    # Extraire la version du CMS depuis recon.webanalyze.technologies
    cms_version = None
    technologies = (
        safe_get(scan, "recon", "webanalyze", "technologies")
        or safe_get(data, "scan", "recon", "webanalyze", "technologies")
        or []
    )

    cms_name = (scan.get("cms_type") or data.get("cms") or "").lower()
    for tech in technologies:
        if not isinstance(tech, dict):
            continue
        tech_name = str(tech.get("name", "")).lower()
        tech_version = str(tech.get("version", "")).strip()
        # Matcher le CMS détecté (drupal, wordpress, joomla...)
        if tech_name in {cms_name, "drupal", "wordpress", "joomla"} and tech_version:
            cms_version = tech_version
            break

    return {
        "scan_id": data.get("scan_id") or scan.get("scan_id"),
        "target_url": scan.get("target_url") or data.get("target_url"),
        "cms": scan.get("cms_type") or data.get("cms") or safe_get(scan, "cms_scan", "cms"),
        "cms_version": cms_version,  # NOUVEAU — version CMS détectée (ex: "10", "11", "6.4.3")
        "mode": scan.get("mode") or data.get("mode"),
        "risk_level": scan.get("risk_level") or data.get("risk_level"),
        "total_vulnerabilities": data.get("total_vulnerabilities")
        if data.get("total_vulnerabilities") is not None
        else safe_get(scan, "cms_scan", "total_vulnerabilities"),
        "created_at": scan.get("created_at") or data.get("created_at"),
        "scan_time_sec": scan.get("scan_time") if scan.get("scan_time") is not None else data.get("scan_time"),
        "severity_counts": data.get("severity_counts") or scan.get("severity_counts") or {},
    }

def make_cve_dedup_key(cve: Dict[str, Any]) -> str:
    """
    Clé robuste de déduplication :
    - priorité au CVE ID
    - sinon plugin/module + version + title/description
    """
    cve_id = normalize_cve_id(cve.get("cve_id") or cve.get("cve"))
    if cve_id:
        return f"cve:{cve_id}"

    plugin_name = normalize_text(
        cve.get("plugin")
        or cve.get("matched_module")
        or cve.get("module_name")
        or ""
    )
    plugin_version = normalize_text(
        cve.get("plugin_version")
        or cve.get("version")
        or cve.get("fixed_in")
        or ""
    )
    title = normalize_text(cve.get("title") or cve.get("description") or "")

    if plugin_name or plugin_version or title:
        return f"plugin:{plugin_name}|version:{plugin_version}|title:{title}"

    return f"fallback:{normalize_text(json.dumps(cve, sort_keys=True, default=str))}"


def extract_cves_dedup(data: Dict[str, Any], scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    
    # ✅ CORRECTION — priorité à scan.cms_scan.cves
    # Si elle existe → on l'utilise UNIQUEMENT
    # Si elle n'existe pas → on prend root_cves comme fallback

    nested_cves = safe_list(safe_get(scan, "cms_scan", "cves"))
    
    if nested_cves:
        sources = nested_cves  # ✅ source prioritaire
    else:
        sources = safe_list(safe_get(data, "cms_scan", "cves"))  # fallback

    seen = set()
    unique: List[Dict[str, Any]] = []

    for cve in sources:
        if not isinstance(cve, dict):
            continue
        key = make_cve_dedup_key(cve)
        if key in seen:
            continue
        seen.add(key)
        unique.append(cve)

    return unique

def extract_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    scan = get_scan_root(data)

    cms_name = str(
        scan.get("cms_type")
        or data.get("cms")
        or safe_get(scan, "cms_scan", "cms")
        or ""
    ).strip().lower()

    # --- CMS scan findings (simple strings) ---
    for line in safe_list(safe_get(scan, "cms_scan", "findings")):
        if not isinstance(line, str):
            continue
        findings.append(
            {
                "source": "cms_scan",
                "title": line,
                "severity": "info",
                "priority": severity_to_priority("info"),
                "url": scan.get("target_url"),
                "kind": classify_finding_kind("info"),
                "raw": line,
            }
        )

    # --- Webanalyze technologies (toujours affichées en annexe) ---
    for tech in safe_list(safe_get(scan, "recon", "webanalyze", "technologies")):
        if not isinstance(tech, dict):
            continue

        tech_name = str(tech.get("name") or "").strip()
        tech_version = str(tech.get("version") or "").strip()

        if not tech_name:
            continue

        findings.append(
            {
                "source": "webanalyze",
                "title": f"Technologie détectée : {tech_name}",
                "severity": "info",
                "priority": severity_to_priority("info"),
                "url": scan.get("target_url"),
                "kind": "information",
                "evidence": tech_version if tech_version else "Version non fournie",
                "note": "Technologie détectée via Webanalyze",
                "raw": tech,
            }
        )

        # --- CMS scan CVEs / wpprobe uniquement pour WordPress / Drupal ---
    if cms_name in {"wordpress", "drupal"}:
        cms_cves = extract_cves_dedup(data, scan)

        # --- GROUPING PAR CVE ID / title+plugin (DEDUP LOGIQUE CONSERVÉE) ---
        grouped_cves: Dict[str, List[Dict[str, Any]]] = {}

        for cve in cms_cves:
            cve_id = normalize_cve_id(cve.get("cve_id") or cve.get("cve"))
            title = normalize_text(cve.get("title") or cve.get("description") or "")
            plugin_name = normalize_text(cve.get("plugin") or cve.get("matched_module") or "")

            if cve_id:
                key = f"cve:{cve_id}"
            elif title:
                key = f"title:{title}|plugin:{plugin_name}"
            else:
                key = make_cve_dedup_key(cve)

            grouped_cves.setdefault(key, []).append(cve)

        for key, group in grouped_cves.items():
            cve = group[0]

            # Plugins sans CVE réelle → finding informatif
            cve_id = normalize_cve_id(cve.get("cve_id") or cve.get("cve"))
            title = cve.get("title") or ""
            plugin_name = cve.get("plugin") or ""

            if not cve_id and title in ("N/A", "", "Non fourni"):
                findings.append(
                    {
                        "source": "cms_scan",
                        "title": f"Plugin détecté : {plugin_name}" if plugin_name else "Plugin détecté",
                        "severity": "info",
                        "priority": severity_to_priority("info"),
                        "url": scan.get("target_url"),
                        "kind": "information",
                        "note": "Plugin installé — aucune CVE connue associée",
                        "raw": cve,
                    }
                )
                continue

            sev = normalize_severity(cve.get("severity") or "high")
            matched_version = cve.get("matched_version")

            # ✅ CORRECTION ICI — ajuster priorité selon matched_version
            if matched_version is True:
                effective_priority = severity_to_priority(sev)
                note = "✅ Vulnérabilité confirmée sur votre installation"

            elif matched_version is False:
                effective_priority = "P4"
                note = "⚠️ Faux positif probable — version non confirmée"

            else:  # matched_version = None (absent du JSON)
                effective_priority = severity_to_priority(sev)
                note = "ℹ️ Version non vérifiable — traiter selon la severity"
            # ✅ CORRECTION — avant le item = {...}
            # Convertir module_name liste → string lisible

            module_name_raw = cve.get("module_name", [])
            if isinstance(module_name_raw, list):
                module_name_str = ", ".join(str(m) for m in module_name_raw)
            else:
                module_name_str = str(module_name_raw or "")

            item = {
                "source": "cve",
                "title": cve_id,
                "cve_id": cve_id,
                "display_title": cve.get("description") or "Non fourni",
                "severity": sev,
                "priority": effective_priority,
                "url": scan.get("target_url"),
                "description": cve.get("description"),
                "cwe": cve.get("cwe_id"),
                "reference": cve.get("nvd_reference"),
                "kind": classify_finding_kind(sev),
                "module_name":  module_name_str, 
                "matched_module": cve.get("matched_module"),
                "matched_version": cve.get("matched_version", False),
                "published": cve.get("published"),
                "cvss_version": cve.get("cvss_version"),
                "raw": cve,
                "note": note, 
            }

            cvss = cve.get("cvss_score")
            if cvss not in (None, "", "Non fourni"):
                item["cvss"] = cvss

            findings.append(item)

            

    # --- Nuclei parsed results ---
    for r in safe_list(safe_get(scan, "nuclei_scan", "parsed_results")):
        if not isinstance(r, dict):
            continue
        sev = normalize_severity(r.get("severity"))
        findings.append(
            {
                "source": "nuclei",
                "title": r.get("name"),
                "severity": sev,
                "priority": severity_to_priority(sev),
                "url": r.get("host"),
                "evidence": r.get("details"),
                "kind": classify_finding_kind(sev),
                "raw": r,
            }
        )

    # --- ZAP ---
  
    zap_alerts = [a for a in safe_list(safe_get(scan, "zap_scan", "alerts")) if isinstance(a, dict)]

    # Grouper par alertRef
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for a in zap_alerts:
        key = str(a.get("alertRef") or a.get("pluginId") or a.get("alert") or "unknown")
        grouped.setdefault(key, []).append(a)

    for key, group in grouped.items():
        # Prendre celui avec la meilleure confidence
        rep = max(group, key=lambda x: confidence_rank(x.get("confidence")))
        sev = normalize_severity(rep.get("risk"))
        
        # ✅ CORRECTION : Pas de filtre ici
        # On garde TOUT pour l'annexe
        # Le filtrage se fera dans llm.py pour la Section B
        
        # Fusionner tous les params des instances
        params: List[str] = []
        for g in group:
            p = (g.get("param") or "").strip()
            if p and p not in params:
                params.append(p)
        
        merged_param = ", ".join(params) if params else rep.get("param")
        evidences: List[str] = []
        for g in group:
            e = (g.get("evidence") or "").strip()
            if e and e not in evidences:
                evidences.append(e)
        merged_evidence = ", ".join(evidences) if evidences else rep.get("evidence")
        
        findings.append({
            "source": "zap",
            "title": rep.get("alert") or rep.get("name"),
            "severity": sev,
            "priority": severity_to_priority(sev),
            "risk": rep.get("risk") or "Non fourni",
            "confidence": normalize_confidence(rep.get("confidence")),
            "alertRef": rep.get("alertRef") or key,
            "url": rep.get("url"),
            "param": merged_param,
            "evidence": merged_evidence,  
            "description": rep.get("description"),
            "solution": rep.get("solution"),
            "reference": rep.get("reference"),
            "cwe": rep.get("cweid"),
            "kind": classify_finding_kind(sev),
            "raw": rep,
            "group_size": len(group),  # Nombre d'instances dédupliquées
        })

    return findings