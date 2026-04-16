import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# Helpers généraux
# ============================================================

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


def normalize_confidence(conf: Optional[str]) -> str:
    c = (conf or "").strip().lower()
    if c in {"high", "medium", "low"}:
        return c.capitalize()
    return "Non fourni"


def confidence_rank(conf: Optional[str]) -> int:
    c = (conf or "").strip().lower()
    if c == "high":
        return 3
    if c == "medium":
        return 2
    if c == "low":
        return 1
    return 0


def normalize_severity(sev: Optional[str]) -> str:
    """
    Normalise la sévérité vers une valeur canonique parmi :
    critical, high, medium, low, info.
    FIX: retournait la valeur brute pour les valeurs inconnues au lieu de "info".
    Maintenant fallback explicite sur "info" pour toute valeur non reconnue.
    """
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
        # alias utiles
        "moderate": "medium",
        "med": "medium",
        "warn": "low",
        "warning": "low",
        "none": "info",
        "unknown": "info",
    }
    # FIX: fallback sur "info" au lieu de retourner s brut
    return mapping.get(s, "info")


def _text_blob_from_finding(f: Dict[str, Any]) -> str:
    return normalize_text(" ".join([
        str(f.get("title") or ""),
        str(f.get("display_title") or ""),
        str(f.get("description") or ""),
        str(f.get("note") or ""),
        str(f.get("reference") or ""),
        str(f.get("param") or ""),
        str(f.get("evidence") or ""),
    ]))


# ============================================================
# classify_finding_type — version unique consolidée
# FIX: ce fichier avait deux définitions de classify_finding_type.
# La seconde écrasait silencieusement la première. Les deux versions
# ont été fusionnées en une seule qui couvre tous les cas.
# ============================================================

def classify_finding_type(f: Dict[str, Any]) -> str:
    source = str(f.get("source") or "").strip().lower()
    title = normalize_text(f.get("display_title") or f.get("title") or "")
    severity = normalize_severity(f.get("severity"))
    matched_version = f.get("matched_version")
    text = _text_blob_from_finding(f)

    # CVE source : priorité absolue sur le matched_version
    if source == "cve":
        if matched_version is True:
            return "confirmed_cve"
        return "potential_cve"

    # TLS / crypto — combinaison source + mots-clés dans title et texte complet
    tls_keywords = [
        "tls", "ssl", "cipher", "sweet32", "lucky13", "beast",
        "breach", "heartbleed", "freak", "logjam", "drown", "poodle",
        "deprecated tls", "deprecated-tls", "weak cipher", "weak-cipher",
        "protocole déprécié", "protocole deprecie", "grade ssl", "grade tls",
    ]
    if source == "network_ssl" or any(k in title for k in tls_keywords) or any(k in text for k in tls_keywords):
        return "tls_crypto"

    # Exposition réseau / fuite info
    exposure_keywords = [
        "cross-domain misconfiguration", "cross domain misconfiguration",
        "access-control-allow-origin", "access control allow origin",
        "port sensible exposé", "port sensible expose", "server leaks",
        "x-powered-by", "google-calendar-exposure", "google calendar exposure",
        "timestamp disclosure", "suspicious comments",
    ]
    if source == "network_ports" or any(k in title for k in exposure_keywords) or any(k in text for k in exposure_keywords):
        return "exposure"

    # Mauvaise config web / headers / intégrité
    web_misconfig_keywords = [
        "csp", "content security policy", "strict-transport-security",
        "strict transport security", "x-frame-options", "anti-clickjacking",
        "clickjacking", "cookie without secure", "cookie no httponly",
        "cookie without samesite", "missing security header",
        "permissions-policy", "referrer-policy",
        "sub resource integrity", "subresource integrity", "missing-sri",
        "x-content-type-options", "cache-control", "cache control",
        "retrieved from cache",
    ]
    if any(k in title for k in web_misconfig_keywords) or any(k in text for k in web_misconfig_keywords):
        return "web_misconfig"

    # Informationnels (sévérité info sans autre marqueur)
    if severity == "info":
        return "informational"

    return "vulnerability_general"


def classify_finding_kind(severity: str, finding: Optional[Dict[str, Any]] = None) -> str:
    sev = normalize_severity(severity)

    if finding is not None:
        finding_type = classify_finding_type(finding)
        if finding_type == "informational":
            return "information"
        if finding_type in {
            "confirmed_cve",
            "potential_cve",
            "tls_crypto",
            "exposure",
            "web_misconfig",
            "vulnerability_general",
        }:
            return "vulnerability"

    if sev in {"critical", "high", "medium", "low"}:
        return "vulnerability"
    return "information"


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


def parse_mongo_date(value: Any) -> str:
    """
    Convertit :
    - {"$date": "2026-04-09T19:07:22.925Z"}
    - "2026-04-09T19:07:22.925Z"
    en texte lisible.
    """
    if isinstance(value, dict) and "$date" in value:
        value = value["$date"]

    if not value:
        return "Non fourni"

    s = str(value).strip()

    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return s


def normalize_target_url(value: Any) -> str:
    if not value:
        return ""
    return str(value).strip()


def get_scan_root(data: Dict[str, Any]) -> Dict[str, Any]:
    s = data.get("scan")
    return s if isinstance(s, dict) else data


def _is_complete_mode(data: Dict[str, Any]) -> bool:
    if data.get("network_scan"):
        return True
    if isinstance(data.get("nuclei_scan"), list):
        return True
    if isinstance(data.get("zap_results"), list):
        return True
    return False


# ============================================================
# OWASP / source helpers
# ============================================================

def get_owasp_from_source_tags(f: Dict[str, Any]) -> Optional[str]:
    raw = f.get("raw")
    if not isinstance(raw, dict):
        return None

    tags = raw.get("tags")
    if not isinstance(tags, dict):
        return None

    mapping = {
        "OWASP_2021_A01": "A01:2021 - Broken Access Control",
        "OWASP_2021_A02": "A02:2021 - Cryptographic Failures",
        "OWASP_2021_A03": "A03:2021 - Injection",
        "OWASP_2021_A04": "A04:2021 - Insecure Design",
        "OWASP_2021_A05": "A05:2021 - Security Misconfiguration",
        "OWASP_2021_A06": "A06:2021 - Vulnerable and Outdated Components",
        "OWASP_2021_A07": "A07:2021 - Identification and Authentication Failures",
        "OWASP_2021_A08": "A08:2021 - Software and Data Integrity Failures",
        "OWASP_2021_A09": "A09:2021 - Security Logging and Monitoring Failures",
        "OWASP_2021_A10": "A10:2021 - Server-Side Request Forgery",
    }

    for key, value in mapping.items():
        if key in tags:
            return value
    return None


# ============================================================
# Métadonnées
# ============================================================

def extract_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    scan = get_scan_root(data)

    technologies = (
        safe_get(scan, "recon", "webanalyze", "technologies")
        or safe_get(data, "scan", "recon", "webanalyze", "technologies")
        or []
    )

    cms_name = str(
        scan.get("cms_type") or data.get("cms") or safe_get(scan, "cms_scan", "cms") or ""
    ).lower()

    cms_version = None
    for tech in technologies:
        if not isinstance(tech, dict):
            continue
        tech_name = str(tech.get("name", "")).lower()
        tech_version = str(tech.get("version", "")).strip()
        if tech_name in {cms_name, "drupal", "wordpress", "joomla"} and tech_version:
            cms_version = tech_version
            break

    meta = {
        "scan_id": data.get("scan_id") or scan.get("scan_id"),
        "target_url": scan.get("target_url") or data.get("target_url") or data.get("domain"),
        "cms": scan.get("cms_type") or data.get("cms") or safe_get(scan, "cms_scan", "cms") or "inconnu",
        "cms_version": cms_version or "Non fourni",
        "mode": scan.get("mode") or data.get("mode") or "Non fourni",
        "risk_level": scan.get("risk_level") or data.get("risk_level") or "Non fourni",
        "total_vulnerabilities": data.get("total_vulnerabilities")
        if data.get("total_vulnerabilities") is not None
        else safe_get(scan, "cms_scan", "total_vulnerabilities"),
        "created_at": parse_mongo_date(scan.get("created_at") or data.get("created_at")),
        "scan_time_sec": scan.get("scan_time") if scan.get("scan_time") is not None else data.get("scan_time"),
        "severity_counts": data.get("severity_counts") or scan.get("severity_counts") or {},
    }

    if _is_complete_mode(data):
        network = data.get("network_scan") or {}
        ssl = network.get("ssl") or {}
        whois = network.get("whois") or {}
        scans = network.get("scans") or {}

        raw_out = ssl.get("raw_output", "")
        ssl_grade = ""
        if raw_out:
            m = re.search(r"Overall Grade\s+([A-F][+-]?)", raw_out)
            if m:
                ssl_grade = m.group(1)

        open_ports: set = set()
        for scan_data in scans.values():
            if not isinstance(scan_data, dict):
                continue
            for host in safe_list(scan_data.get("hosts")):
                if not isinstance(host, dict):
                    continue
                for p in safe_list(host.get("ports")):
                    if isinstance(p, dict) and str(p.get("state", "")).lower() == "open":
                        open_ports.add(str(p.get("port", "")))

        meta.update({
            "domain": data.get("domain") or meta.get("target_url", ""),
            "whois_org": whois.get("org") or whois.get("reseller") or "Non fourni",
            "whois_country": whois.get("country") or "Non fourni",
            "ssl_grade": ssl_grade or "Non fourni",
            "open_ports_count": len(open_ports),
            "completed_at": parse_mongo_date(data.get("completed_at") or scan.get("completed_at")),
        })

    return meta


# ============================================================
# CVE helpers
# ============================================================

def make_cve_dedup_key(cve: Dict[str, Any]) -> str:
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
    nested_cves = safe_list(safe_get(scan, "cms_scan", "cves"))
    sources = nested_cves if nested_cves else safe_list(safe_get(data, "cms_scan", "cves"))

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


# ============================================================
# Réseau / TLS / Ports
# ============================================================

_TLS_VULN_SEV: Dict[str, str] = {
    "beast": "medium",
    "lucky13": "medium",
    "breach": "low",
    "poodle": "high",
    "freak": "medium",
    "logjam": "medium",
    "sweet32": "medium",
    "drown": "high",
    "heartbleed": "critical",
    "robot": "medium",
    "ticketbleed": "medium",
}

# FIX: les patterns de protocoles dépréciés utilisaient "tls 1 " (avec espace trailing)
# ce qui ne matchait pas les variantes "tls1", "tls1.0", "tls 1\n" du raw output testssl.
# Correction : utiliser des patterns plus robustes alignés sur la sortie réelle testssl.sh.
_DEPRECATED_PROTOCOLS_PATTERNS: Dict[str, Tuple[str, str]] = {
    "sslv2": ("critical", "SSLv2 activé — protocole obsolète et non sécurisé"),
    "sslv3": ("high", "SSLv3 activé — vulnérable à POODLE (CVE-2014-3566)"),
    "tls 1.0": ("high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
    "tls 1.1": ("medium", "TLS 1.1 activé — protocole déprécié (RFC 8996)"),
}

# Patterns supplémentaires couvrant les variantes compactes du raw output testssl
_DEPRECATED_PROTOCOLS_COMPACT: Dict[str, Tuple[str, str, str]] = {
    # clé_pattern: (label_affichage, sev, desc)
    "tls1 ": ("TLS 1.0", "high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
    "tls1\t": ("TLS 1.0", "high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
    "tls1\n": ("TLS 1.0", "high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
    " tls 1 ": ("TLS 1.0", "high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
}

_RISKY_PORTS: Dict[str, Tuple[str, str]] = {
    "21": ("FTP", "medium"),
    "23": ("Telnet", "high"),
    "25": ("SMTP", "low"),
    "3306": ("MySQL", "high"),
    "5432": ("PostgreSQL", "high"),
    "6379": ("Redis", "high"),
    "27017": ("MongoDB", "high"),
    "8080": ("HTTP alternatif", "low"),
    "8880": ("HTTP alternatif", "low"),
    "2082": ("cPanel HTTP", "medium"),
    "2086": ("WHM HTTP", "medium"),
    "2083": ("cPanel HTTPS", "low"),
    "2087": ("WHM HTTPS", "low"),
    "2095": ("Webmail HTTP", "low"),
}


def _make_finding(
    source: str,
    title: str,
    severity: str,
    url: str = "",
    description: str = "",
    reference: str = "",
    evidence: Any = None,
    note: str = "",
    raw: Any = None,
    risk: str = "",
    confidence: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sev = normalize_severity(severity)
    item = {
        "source": source,
        "title": title,
        "severity": sev,
        "priority": severity_to_priority(sev),
        "url": normalize_target_url(url),
        "description": description or "",
        "reference": reference or "",
        "evidence": evidence if evidence is not None else "—",
        "note": note or "—",
        "risk": risk or "—",
        "confidence": confidence or "—",
        "raw": raw,
    }
    if extra:
        item.update(extra)

    item["finding_type"] = classify_finding_type(item)
    item["kind"] = classify_finding_kind(sev, item)
    return item


def _parse_tls_raw_output(raw_output: str, target_url: str) -> List[Dict[str, Any]]:
    """
    Parse la sortie brute testssl.sh pour extraire les vulnérabilités TLS.

    FIX: le pattern "tls 1 " (avec espace trailing) ne matchait pas les vraies
    lignes testssl.sh qui écrivent "TLS 1      offered (deprecated)" ou
    "TLS 1.0    offered (deprecated)". Remplacé par une regex robuste.
    """
    if not raw_output:
        return []

    findings: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(title: str, sev: str, desc: str, ref: str = "") -> None:
        key = f"{normalize_text(title)}|{normalize_text(target_url)}"
        if key in seen:
            return
        seen.add(key)
        findings.append(_make_finding(
            source="network_ssl",
            title=title,
            severity=sev,
            url=target_url,
            description=desc,
            reference=ref,
            note="Détecté via testssl.sh",
        ))

    for line in raw_output.splitlines():
        lo = line.lower()

        # FIX: détection des protocoles dépréciés via regex plus robuste
        # couvre : "TLS 1      offered", "TLS 1.0    offered", "TLS 1.1    offered"
        # sans matcher "TLS 1.2" ou "TLS 1.3"
        if "offered" in lo and "not offered" not in lo:
            if re.search(r"\btls\s+1\.0\b|\btls\s+1\s+(?![\.\d])", lo):
                _add(
                    "Protocole déprécié activé : TLS 1.0",
                    "high",
                    "TLS 1.0 activé — protocole déprécié (RFC 8996)",
                    "https://www.rfc-editor.org/rfc/rfc8996",
                )
            elif re.search(r"\btls\s+1\.1\b", lo):
                _add(
                    "Protocole déprécié activé : TLS 1.1",
                    "medium",
                    "TLS 1.1 activé — protocole déprécié (RFC 8996)",
                    "https://www.rfc-editor.org/rfc/rfc8996",
                )
            elif re.search(r"\bsslv2\b", lo):
                _add(
                    "Protocole déprécié activé : SSLv2",
                    "critical",
                    "SSLv2 activé — protocole obsolète et non sécurisé",
                    "https://www.rfc-editor.org/rfc/rfc8996",
                )
            elif re.search(r"\bsslv3\b", lo):
                _add(
                    "Protocole déprécié activé : SSLv3",
                    "high",
                    "SSLv3 activé — vulnérable à POODLE (CVE-2014-3566)",
                    "https://www.rfc-editor.org/rfc/rfc8996",
                )

        # Vulnérabilités TLS nommées
        for vuln_key, sev in _TLS_VULN_SEV.items():
            if vuln_key in lo:
                if "not vulnerable" in lo or "not affected" in lo:
                    continue
                if "vulnerable" in lo or "potentially" in lo:
                    parts = line.strip().split()
                    label = parts[0] if parts else vuln_key.upper()
                    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", line, re.IGNORECASE)
                    cve_ref = cve_match.group(0) if cve_match else ""
                    _add(
                        f"Vulnérabilité TLS : {label}",
                        sev,
                        line.strip(),
                        f"https://nvd.nist.gov/vuln/detail/{cve_ref}" if cve_ref else "",
                    )

        if "grade capped" in lo or "grade cap reasons" in lo:
            _add(
                "Grade SSL/TLS dégradé (SSL Labs)",
                "info",
                line.strip(),
                "https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide",
            )

    return findings


def _parse_ssl_protocols_fallback(ssl_data: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    protocols = ssl_data.get("protocols") or {}
    seen = set()

    proto_map = {
        "sslv2": ("SSLv2", "critical", "SSLv2 activé — protocole obsolète et non sécurisé"),
        "sslv3": ("SSLv3", "high", "SSLv3 activé — vulnérable à POODLE (CVE-2014-3566)"),
        "tls1.0": ("TLS 1.0", "high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
        "tls10": ("TLS 1.0", "high", "TLS 1.0 activé — protocole déprécié (RFC 8996)"),
        "tls1.1": ("TLS 1.1", "medium", "TLS 1.1 activé — protocole déprécié (RFC 8996)"),
        "tls11": ("TLS 1.1", "medium", "TLS 1.1 activé — protocole déprécié (RFC 8996)"),
    }

    for proto, state in protocols.items():
        if not isinstance(state, str):
            continue
        if "offered" in state.lower() and "not" not in state.lower():
            # FIX: normaliser la clé proto pour matcher les variantes "TLS 1.0", "tls10", etc.
            proto_key = re.sub(r"[\s\.\-]+", "", str(proto).lower())
            for canonical_key, (label, sev, desc) in proto_map.items():
                canonical_norm = re.sub(r"[\s\.\-]+", "", canonical_key)
                if proto_key == canonical_norm:
                    key = f"{normalize_text(label)}|{normalize_text(target_url)}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_make_finding(
                        source="network_ssl",
                        title=f"Protocole déprécié activé : {label}",
                        severity=sev,
                        url=target_url,
                        description=desc,
                        reference="https://www.rfc-editor.org/rfc/rfc8996",
                        note="Détecté via analyse SSL",
                    ))
                    break

    return findings


def _parse_open_ports(scans: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen_ports: set = set()

    for scan_name, scan_data in (scans or {}).items():
        if not isinstance(scan_data, dict):
            continue

        for host in safe_list(scan_data.get("hosts")):
            if not isinstance(host, dict):
                continue

            for port_info in safe_list(host.get("ports")):
                if not isinstance(port_info, dict):
                    continue

                port = str(port_info.get("port", ""))
                state = str(port_info.get("state", "")).lower()
                service = port_info.get("service") or ""
                product = port_info.get("product") or ""
                version = port_info.get("version") or ""

                if state != "open" or port in seen_ports:
                    continue
                seen_ports.add(port)

                if port in _RISKY_PORTS:
                    label, sev = _RISKY_PORTS[port]
                    evidence = service or label
                    if product:
                        evidence += f" ({product}"
                        if version:
                            evidence += f" {version}"
                        evidence += ")"

                    findings.append(_make_finding(
                        source="network_ports",
                        title=f"Port sensible exposé : {port}/{service or label}",
                        severity=sev,
                        url=target_url,
                        description=f"Le port {port} ({label}) est ouvert et accessible depuis Internet.",
                        evidence=evidence,
                        note=f"Détecté via scan réseau ({scan_name})",
                    ))

    return findings


def extract_network_findings(data: Dict[str, Any], scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    network = data.get("network_scan") or {}
    if not network:
        return []

    target_url = (
        data.get("target_url")
        or scan.get("target_url")
        or str(data.get("domain", ""))
    )

    ssl = network.get("ssl") or {}
    raw_out = ssl.get("raw_output", "")
    scans = network.get("scans") or {}

    results: List[Dict[str, Any]] = []

    if raw_out:
        results.extend(_parse_tls_raw_output(raw_out, target_url))
    else:
        results.extend(_parse_ssl_protocols_fallback(ssl, target_url))

    results.extend(_parse_open_ports(scans, target_url))
    return results


# ============================================================
# Nuclei / ZAP
# ============================================================

def extract_nuclei_root(data: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
    raw = data.get("nuclei_scan")
    if not isinstance(raw, list):
        return []

    findings: List[Dict[str, Any]] = []
    seen_titles: set = set()

    for r in raw:
        if not isinstance(r, dict):
            continue

        sev = normalize_severity(r.get("severity"))
        name = r.get("name") or ""
        host = r.get("matched_at") or r.get("host") or target_url
        details = r.get("details")

        detail_str = ""
        if isinstance(details, list) and details:
            detail_str = str(details[0]).strip()[:80]
        elif isinstance(details, str) and details.strip():
            detail_str = details.strip()[:80]

        unique_title = f"{name}:{detail_str}" if detail_str else name
        dedup_key = f"{normalize_text(unique_title)}|{normalize_text(host)}"

        if dedup_key in seen_titles:
            continue
        seen_titles.add(dedup_key)

        findings.append(_make_finding(
            source="nuclei",
            title=unique_title,
            severity=sev,
            url=host,
            description=r.get("description", ""),
            evidence=details if details else "—",
            raw=r,
            extra={"display_title": name},
        ))

    return findings


def extract_zap_results(data: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
    raw = data.get("zap_results")
    if not isinstance(raw, list):
        return []

    findings: List[Dict[str, Any]] = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        name = item.get("name") or ""
        risk = item.get("risk") or "Informational"
        confidence = item.get("confidence") or "Low"
        urls = safe_list(item.get("urls"))
        count = item.get("instance_count") or len(urls)

        sev = normalize_severity(risk)
        rep_url = urls[0] if urls else target_url

        findings.append(_make_finding(
            source="zap",
            title=name,
            severity=sev,
            url=rep_url,
            description=f"{name} — {count} instance(s) détectée(s).",
            raw=item,
            risk=risk,
            confidence=normalize_confidence(confidence),
            extra={
                "targets": urls[:5],
                "group_size": count,
            },
        ))

    return findings


# ============================================================
# Déduplication globale finale
# ============================================================

def make_global_dedup_key(f: Dict[str, Any]) -> str:
    cve_id = normalize_cve_id(f.get("cve_id"))
    if cve_id:
        return f"cve|{cve_id}"

    source = normalize_text(f.get("source"))
    title = normalize_text(f.get("display_title") or f.get("title"))
    url = normalize_text(f.get("url"))
    evidence = normalize_text(f.get("evidence"))

    # evidence tronquée pour éviter les clés immenses
    evidence = evidence[:120]

    return f"{source}|{title}|{url}|{evidence}"


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique: List[Dict[str, Any]] = []
    seen = set()

    for f in findings:
        key = make_global_dedup_key(f)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return unique


# ============================================================
# Extraction principale
# ============================================================

def extract_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    scan = get_scan_root(data)

    cms_name = str(
        scan.get("cms_type")
        or data.get("cms")
        or safe_get(scan, "cms_scan", "cms")
        or ""
    ).strip().lower()

    # ---------- MODE COMPLETE ----------
    if _is_complete_mode(data):
        target_url_for_complete = (
            data.get("target_url")
            or scan.get("target_url")
            or str(data.get("domain", ""))
        )
        findings.extend(extract_network_findings(data, scan))
        findings.extend(extract_nuclei_root(data, target_url_for_complete))
        findings.extend(extract_zap_results(data, target_url_for_complete))

    # ---------- CMS simple findings ----------
    for line in safe_list(safe_get(scan, "cms_scan", "findings")):
        if not isinstance(line, str):
            continue
        findings.append(_make_finding(
            source="cms_scan",
            title=line,
            severity="info",
            url=scan.get("target_url"),
            raw=line,
        ))

    # ---------- Webanalyze ----------
    for tech in safe_list(safe_get(scan, "recon", "webanalyze", "technologies")):
        if not isinstance(tech, dict):
            continue

        tech_name = str(tech.get("name") or "").strip()
        tech_version = str(tech.get("version") or "").strip()
        if not tech_name:
            continue

        findings.append(_make_finding(
            source="webanalyze",
            title=f"Technologie détectée : {tech_name}",
            severity="info",
            url=scan.get("target_url"),
            evidence=tech_version if tech_version else "Version non fournie",
            note="Technologie détectée via Webanalyze",
            raw=tech,
        ))

    # ---------- CVEs WordPress / Drupal ----------
    if cms_name in {"wordpress", "drupal"}:
        cms_cves = extract_cves_dedup(data, scan)

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

        for _, group in grouped_cves.items():
            cve = group[0]

            cve_id = normalize_cve_id(cve.get("cve_id") or cve.get("cve"))
            title = cve.get("title") or ""
            plugin_name = cve.get("plugin") or ""

            if not cve_id and title in ("N/A", "", "Non fourni"):
                findings.append(_make_finding(
                    source="cms_scan",
                    title=f"Plugin détecté : {plugin_name}" if plugin_name else "Plugin détecté",
                    severity="info",
                    url=scan.get("target_url"),
                    note="Plugin installé — aucune CVE connue associée",
                    raw=cve,
                ))
                continue

            sev = normalize_severity(cve.get("severity") or "high")
            matched_version = cve.get("matched_version")

            if matched_version is True:
                effective_priority = severity_to_priority(sev)
                note = "Correspondance module/version détectée — validation manuelle recommandée"
            elif matched_version is False:
                effective_priority = "P4"
                note = "Vulnérabilité potentielle non confirmée — version exacte non vérifiée"
            else:
                effective_priority = severity_to_priority(sev)
                note = "Version non vérifiable — analyse complémentaire recommandée"

            module_name_raw = cve.get("module_name", [])
            if isinstance(module_name_raw, list):
                module_name_str = ", ".join(str(m) for m in module_name_raw)
            else:
                module_name_str = str(module_name_raw or "")

            item = _make_finding(
                source="cve",
                title=cve_id or "CVE non fournie",
                severity=sev,
                url=scan.get("target_url"),
                description=cve.get("description") or "Non fourni",
                reference=cve.get("nvd_reference") or "",
                raw=cve,
                note=note,
                extra={
                    "cve_id": cve_id,
                    "display_title": cve.get("description") or "Non fourni",
                    "cwe": cve.get("cwe_id"),
                    "module_name": module_name_str,
                    "matched_module": cve.get("matched_module"),
                    "matched_version": cve.get("matched_version", False),
                    "published": cve.get("published"),
                    "cvss_version": cve.get("cvss_version"),
                }
            )

            item["priority"] = effective_priority

            cvss = cve.get("cvss_score")
            if cvss not in (None, "", "Non fourni"):
                item["cvss"] = cvss

            findings.append(item)

    # ---------- Nuclei mode light ----------
    for r in safe_list(safe_get(scan, "nuclei_scan", "parsed_results")):
        if not isinstance(r, dict):
            continue

        sev = normalize_severity(r.get("severity"))
        name = r.get("name") or ""
        host = r.get("host") or ""
        details = r.get("details")

        detail_str = ""
        if isinstance(details, str) and details.strip():
            detail_str = details.strip()[:80]
        elif isinstance(details, list) and details:
            detail_str = str(details[0]).strip()[:80]

        unique_title = f"{name}:{detail_str}" if detail_str else name

        findings.append(_make_finding(
            source="nuclei",
            title=unique_title,
            severity=sev,
            url=host,
            evidence=details if details else "—",
            raw=r,
            extra={"display_title": name},
        ))

    # ---------- ZAP mode light ----------
    zap_alerts = [a for a in safe_list(safe_get(scan, "zap_scan", "alerts")) if isinstance(a, dict)]
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for a in zap_alerts:
        key = str(a.get("alertRef") or a.get("pluginId") or a.get("alert") or "unknown")
        grouped.setdefault(key, []).append(a)

    for key, group in grouped.items():
        rep = max(group, key=lambda x: confidence_rank(x.get("confidence")))
        sev = normalize_severity(rep.get("risk"))

        params: List[str] = []
        for g in group:
            p = (g.get("param") or "").strip()
            if p and p not in params:
                params.append(p)

        evidences: List[str] = []
        for g in group:
            e = (g.get("evidence") or "").strip()
            if e and e not in evidences:
                evidences.append(e)

        merged_param = ", ".join(params) if params else rep.get("param")
        merged_evidence = ", ".join(evidences) if evidences else rep.get("evidence")

        findings.append(_make_finding(
            source="zap",
            title=rep.get("alert") or rep.get("name") or key,
            severity=sev,
            url=rep.get("url"),
            description=rep.get("description") or "",
            reference=rep.get("reference") or "",
            evidence=merged_evidence if merged_evidence else "—",
            raw=rep,
            risk=rep.get("risk") or "Non fourni",
            confidence=normalize_confidence(rep.get("confidence")),
            extra={
                "alertRef": rep.get("alertRef") or key,
                "param": merged_param,
                "solution": rep.get("solution"),
                "cwe": rep.get("cweid"),
                "group_size": len(group),
            },
        ))

    # Déduplication globale finale
    findings = deduplicate_findings(findings)
    return findings


# ============================================================
# Helpers utiles pour llm.py / report builder
# ============================================================

def split_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    vulnerabilities = [f for f in findings if f.get("kind") == "vulnerability"]
    informations = [f for f in findings if f.get("kind") != "vulnerability"]
    return vulnerabilities, informations


def count_severity(findings: List[Dict[str, Any]], vulnerabilities_only: bool = True) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        if vulnerabilities_only and f.get("kind") != "vulnerability":
            continue
        sev = normalize_severity(f.get("severity"))
        if sev not in counts:
            sev = "info"
        counts[sev] += 1

    return counts


def build_summary_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    vulns, infos = split_findings(findings)
    severity_counts_vulns = count_severity(vulns, vulnerabilities_only=False)
    severity_counts_all = count_severity(findings, vulnerabilities_only=False)

    return {
        "all_findings_count": len(findings),
        "vulnerability_count": len(vulns),
        "information_count": len(infos),
        "severity_counts_vulnerabilities": severity_counts_vulns,
        "severity_counts_all": severity_counts_all,
    }