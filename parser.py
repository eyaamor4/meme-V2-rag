import json
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


def should_keep_by_confidence(severity: str, confidence: Optional[str]) -> bool:
    sev = normalize_severity(severity)
    conf = (confidence or "").strip().lower()
    if sev in {"high", "critical"}:
        return True
    return conf in {"medium", "high"}


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


def extract_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    scan = get_scan_root(data)

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

    # --- CMS scan CVEs ---
    for cve in safe_list(safe_get(scan, "cms_scan", "cves")):
        if not isinstance(cve, dict):
            continue
        
        # Plugins sans CVE réelle → finding informatif
        cve_id = cve.get("cve_id") or cve.get("cve")
        title = cve.get("title") or ""
        plugin_name = cve.get("plugin") or ""

        if not cve_id and title in ("N/A", "", "Non fourni"):
            findings.append({
                "source": "cms_scan",
                "title": f"Plugin détecté : {plugin_name}" if plugin_name else "Plugin détecté",
                "severity": "info",
                "priority": severity_to_priority("info"),
                "url": scan.get("target_url"),
                "kind": "information",
                "note": "Plugin installé — aucune CVE connue associée",
                "raw": cve,
            })
            continue

        sev = normalize_severity(cve.get("severity") or "high")
        matched_version = cve.get("matched_version", False)
    
         
        item = {
            "source": "cve",
            "title": cve.get("cve_id"),
            "cve_id": cve.get("cve_id"),                         # NOUVEAU — pour map_owasp() override
            "display_title": cve.get("description") or "Non fourni",
            "severity": sev,
            "priority": severity_to_priority(sev),
            "url": scan.get("target_url"),
            "description": cve.get("description"),
            "cwe": cve.get("cwe_id"),
            "reference": cve.get("nvd_reference"),
            "kind": classify_finding_kind(sev),
            "module_name": cve.get("module_name", []),
            "matched_module": cve.get("matched_module"),
            "matched_version": cve.get("matched_version", False),  # NOUVEAU — False si non confirmé
            "published": cve.get("published"),
            "cvss_version": cve.get("cvss_version"),
            "raw": cve,
            "note": " À vérifier — module détecté mais version non confirmée" if not matched_version else "Vulnérabilité confirmée sur votre installation", 

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
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for a in zap_alerts:
        key = str(a.get("alertRef") or a.get("pluginId") or a.get("alert") or "unknown")
        grouped.setdefault(key, []).append(a)

    for key, group in grouped.items():
        rep = max(group, key=lambda x: confidence_rank(x.get("confidence")))
        sev = normalize_severity(rep.get("risk"))
        if not should_keep_by_confidence(sev, rep.get("confidence")):
            continue

        params: List[str] = []
        for g in group:
            p = (g.get("param") or "").strip()
            if p and p not in params:
                params.append(p)
        merged_param = ", ".join(params) if params else rep.get("param")

        findings.append(
            {
                "source": "zap",
                "title": rep.get("alert") or rep.get("name"),
                "severity": sev,
                "priority": severity_to_priority(sev),
                "risk": rep.get("risk") or "Non fourni",
                "confidence": normalize_confidence(rep.get("confidence")),
                "alertRef": rep.get("alertRef") or key,
                "url": rep.get("url"),
                "param": merged_param,
                "evidence": rep.get("evidence"),
                "description": rep.get("description"),
                "solution": rep.get("solution"),
                "reference": rep.get("reference"),
                "cwe": rep.get("cweid"),
                "kind": classify_finding_kind(sev),
                "raw": rep,
                "group_size": len(group),
            }
        )

    return findings