# ============================================================
#  map_owasp.py — Mapping CWE / Titre / CVE → OWASP Top 10 2021
#  Version corrigée — basée sur l'analyse de 5 rapports LLM
#
#  Corrections appliquées :
#  [BUG-1] CWE-326, 310, 311, 312, 330 ajoutés (A02 TLS/Crypto)
#  [BUG-2] CWE-497, 933, 113 ajoutés (A05/A03)
#  [BUG-3] "bypass" générique supprimé → remplacé par clés spécifiques
#  [BUG-4] "weak-cipher-suites" avec tiret ajouté
#  [BUG-5] Normalisation texte : tirets → espaces avant matching
#  [BUG-6] CVE_OWASP_OVERRIDE pour CVE mal classés par NVD
#  [NEW]   map_owasp() accepte cve_id pour les overrides
#  [NEW]   map_owasp_from_finding() : interface haut niveau
#  [NEW]   map_owasp_wordpress_plugin() : cas cms_scan wpprobe
# ============================================================


# ------------------------------------------------------------------
# 1. OVERRIDES CVE — priorité absolue (NVD parfois mal classé)
# ------------------------------------------------------------------

CVE_OWASP_OVERRIDE: dict[str, str] = {
    # CVE-2024-13254 : Drupal REST Views — Forceful Browsing
    # NVD assigne CWE-94 (Code Injection) — incorrect
    # Mécanisme réel : accès non autorisé à données sensibles
    "CVE-2024-13254": "A01:2021 - Broken Access Control",

    # Ajouter ici d'autres CVE mal classés par NVD si nécessaire
    # "CVE-XXXX-YYYY": "AXX:2021 - ...",
}


# ------------------------------------------------------------------
# 2. TABLE CWE → OWASP
# ------------------------------------------------------------------

OWASP_BY_CWE: dict[str, str] = {

    # ── A01 - Broken Access Control ──────────────────────────────
    "22":   "A01:2021 - Broken Access Control",   # Path Traversal
    "23":   "A01:2021 - Broken Access Control",   # Relative Path Traversal
    "35":   "A01:2021 - Broken Access Control",   # Path Traversal: '.../...//'
    "59":   "A01:2021 - Broken Access Control",   # Link Following
    "200":  "A01:2021 - Broken Access Control",   # Exposure of Sensitive Info
    "201":  "A01:2021 - Broken Access Control",   # Insertion of Sensitive Info
    "264":  "A01:2021 - Broken Access Control",   # Permissions / Privileges
    "284":  "A01:2021 - Broken Access Control",   # Improper Access Control
    "285":  "A01:2021 - Broken Access Control",   # Improper Authorization
    "352":  "A01:2021 - Broken Access Control",   # CSRF

    # ── A02 - Cryptographic Failures ─────────────────────────────
    "259":  "A02:2021 - Cryptographic Failures",  # Hard-coded Password
    "310":  "A02:2021 - Cryptographic Failures",  # Cryptographic Issues (générique)
    "311":  "A02:2021 - Cryptographic Failures",  # Missing Encryption of Sensitive Data
    "312":  "A02:2021 - Cryptographic Failures",  # Cleartext Storage
    "319":  "A02:2021 - Cryptographic Failures",  # Cleartext Transmission
    "326":  "A02:2021 - Cryptographic Failures",  # Inadequate Encryption Strength — TLS faible [BUG-1]
    "327":  "A02:2021 - Cryptographic Failures",  # Use of Broken Algorithm
    "330":  "A02:2021 - Cryptographic Failures",  # Insufficient Random Values [BUG-1]

    # ── A03 - Injection ───────────────────────────────────────────
    "73":   "A03:2021 - Injection",               # External Control of File Name
    "79":   "A03:2021 - Injection",               # XSS
    "89":   "A03:2021 - Injection",               # SQL Injection
    "94":   "A03:2021 - Injection",               # Code Injection
    "113":  "A03:2021 - Injection",               # HTTP Header Injection [BUG-2]
    "933":  "A03:2021 - Injection",               # CRLF Injection [BUG-2]

    # ── A05 - Security Misconfiguration ──────────────────────────
    "16":   "A05:2021 - Security Misconfiguration",  # Configuration
    "497":  "A05:2021 - Security Misconfiguration",  # Server Header Info Leak [BUG-2]
    "525":  "A05:2021 - Security Misconfiguration",  # Sensitive Browser Cache
    "614":  "A05:2021 - Security Misconfiguration",  # Cookie Without Secure Flag
    "615":  "A05:2021 - Security Misconfiguration",  # Sensitive Info in Source Comment
    "693":  "A05:2021 - Security Misconfiguration",  # CSP — Protection Mechanism Failure
    "1004": "A05:2021 - Security Misconfiguration",  # Cookie Without HttpOnly
    "1021": "A05:2021 - Security Misconfiguration",  # Clickjacking
    "1275": "A05:2021 - Security Misconfiguration",  # Cookie Without SameSite

    # ── A06 - Vulnerable and Outdated Components ──────────────────
    "1104": "A06:2021 - Vulnerable and Outdated Components",

    # ── A07 - Identification and Authentication Failures ──────────
    "287":  "A07:2021 - Identification and Authentication Failures",  # Improper Authentication
    "384":  "A07:2021 - Identification and Authentication Failures",  # Session Fixation

    # ── A08 - Software and Data Integrity Failures ────────────────
    "345":  "A08:2021 - Software and Data Integrity Failures",  # SRI
    "494":  "A08:2021 - Software and Data Integrity Failures",  # Download Without Integrity Check
    "502":  "A08:2021 - Software and Data Integrity Failures",  # Deserialization
    "829":  "A08:2021 - Software and Data Integrity Failures",  # Cross-Domain JS Inclusion
}


# ------------------------------------------------------------------
# 3. TABLE TITRE/DESCRIPTION → OWASP  (fallback si CWE absent)
#    IMPORTANT : les clés sont triées par longueur décroissante
#    dans map_owasp() pour prioriser les matches spécifiques.
# ------------------------------------------------------------------

OWASP_BY_TITLE: dict[str, str] = {

    # ── A03 - Injection ───────────────────────────────────────────
    "sql injection":                "A03:2021 - Injection",
    "sqli":                         "A03:2021 - Injection",
    "cross-site scripting":         "A03:2021 - Injection",
    "xss":                          "A03:2021 - Injection",
    "remote code execution":        "A03:2021 - Injection",
    "arbitrary code":               "A03:2021 - Injection",
    "code injection":               "A03:2021 - Injection",
    "header injection":             "A03:2021 - Injection",
    "crlf injection":               "A03:2021 - Injection",

    # ── A01 - Broken Access Control ──────────────────────────────
    "cross-site request forgery":       "A01:2021 - Broken Access Control",
    "cross domain misconfiguration":    "A01:2021 - Broken Access Control",  # CORS wildcard
    "does not properly restrict":       "A01:2021 - Broken Access Control",
    "improper access control":          "A01:2021 - Broken Access Control",
    "information disclosure":           "A01:2021 - Broken Access Control",
    "access control bypass":            "A01:2021 - Broken Access Control",  # [BUG-3] spécifique
    "authorization bypass":             "A01:2021 - Broken Access Control",  # [BUG-3] spécifique
    "authentication bypass":            "A01:2021 - Broken Access Control",  # [BUG-3] spécifique
    "improper authorization":           "A01:2021 - Broken Access Control",
    "forceful browsing":                "A01:2021 - Broken Access Control",
    "access restriction":               "A01:2021 - Broken Access Control",
    "sensitive information":            "A01:2021 - Broken Access Control",
    "obtain sensitive":                 "A01:2021 - Broken Access Control",
    "hijack the authentication":        "A01:2021 - Broken Access Control",
    "cors":                             "A01:2021 - Broken Access Control",
    "csrf":                             "A01:2021 - Broken Access Control",

    # ── A02 - Cryptographic Failures ─────────────────────────────
    "weak-cipher-suites":           "A02:2021 - Cryptographic Failures",  # [BUG-4] tiret
    "weak cipher suites":           "A02:2021 - Cryptographic Failures",  # espace
    "deprecated-tls":               "A02:2021 - Cryptographic Failures",  # [BUG-4] tiret
    "deprecated tls":               "A02:2021 - Cryptographic Failures",  # espace
    "insecure transport":           "A02:2021 - Cryptographic Failures",
    "cleartext":                    "A02:2021 - Cryptographic Failures",
    "tls 1.0":                      "A02:2021 - Cryptographic Failures",
    "tls 1.1":                      "A02:2021 - Cryptographic Failures",
    "tls10":                        "A02:2021 - Cryptographic Failures",
    "tls11":                        "A02:2021 - Cryptographic Failures",
    "tls":                          "A02:2021 - Cryptographic Failures",

    # ── A05 - Security Misconfiguration ──────────────────────────
    "content security policy":          "A05:2021 - Security Misconfiguration",
    "strict-transport-security":        "A05:2021 - Security Misconfiguration",
    "strict transport security":        "A05:2021 - Security Misconfiguration",
    "x-content-type-options":           "A05:2021 - Security Misconfiguration",
    "x-frame-options":                  "A05:2021 - Security Misconfiguration",
    "anti-clickjacking":                "A05:2021 - Security Misconfiguration",
    "clickjacking":                     "A05:2021 - Security Misconfiguration",
    "cookie without secure flag":       "A05:2021 - Security Misconfiguration",
    "cookie no httponly flag":          "A05:2021 - Security Misconfiguration",
    "cookie without samesite":          "A05:2021 - Security Misconfiguration",
    "cookie without secure":            "A05:2021 - Security Misconfiguration",
    "missing security header":          "A05:2021 - Security Misconfiguration",
    "missing anti-clickjacking":        "A05:2021 - Security Misconfiguration",
    "server leaks version":             "A05:2021 - Security Misconfiguration",
    "security misconfiguration":        "A05:2021 - Security Misconfiguration",
    "hsts":                             "A05:2021 - Security Misconfiguration",
    "csp":                              "A05:2021 - Security Misconfiguration",
    "permissions-policy":               "A05:2021 - Security Misconfiguration",
    "referrer-policy":                  "A05:2021 - Security Misconfiguration",
    "fastly-debug":                     "A05:2021 - Security Misconfiguration",
    "xss-deprecated-header":           "A05:2021 - Security Misconfiguration",
    "x-xss-protection":                "A05:2021 - Security Misconfiguration",

    # ── A06 - Vulnerable and Outdated Components ──────────────────
    "vulnerable and outdated":          "A06:2021 - Vulnerable and Outdated Components",
    "outdated component":               "A06:2021 - Vulnerable and Outdated Components",
    "obsolete component":               "A06:2021 - Vulnerable and Outdated Components",

    # ── A07 - Identification and Authentication Failures ──────────
    "session fixation":                 "A07:2021 - Identification and Authentication Failures",
    "improper authentication":          "A07:2021 - Identification and Authentication Failures",

    # ── A08 - Software and Data Integrity Failures ────────────────
    "subresource integrity":            "A08:2021 - Software and Data Integrity Failures",
    "sub resource integrity":           "A08:2021 - Software and Data Integrity Failures",
    "sub-resource integrity":           "A08:2021 - Software and Data Integrity Failures",
    "cross-domain javascript":          "A08:2021 - Software and Data Integrity Failures",
    "cross domain javascript":          "A08:2021 - Software and Data Integrity Failures",
    "untrusted javascript":             "A08:2021 - Software and Data Integrity Failures",
    "missing-sri":                      "A08:2021 - Software and Data Integrity Failures",
    "missing sri":                      "A08:2021 - Software and Data Integrity Failures",
}


# ------------------------------------------------------------------
# 4. MAPPING TEMPLATES NUCLEI → OWASP
#    Pour les findings nuclei qui n'ont ni CWE ni titre standard ZAP
# ------------------------------------------------------------------

NUCLEI_TEMPLATE_OWASP: dict[str, str] = {
    # A02
    "deprecated-tls":               "A02:2021 - Cryptographic Failures",
    "weak-cipher-suites":           "A02:2021 - Cryptographic Failures",
    "tls-version":                  "A02:2021 - Cryptographic Failures",

    # A05
    "cookies-without-httponly":         "A05:2021 - Security Misconfiguration",
    "cookies-without-secure":           "A05:2021 - Security Misconfiguration",
    "missing-cookie-samesite-strict":   "A05:2021 - Security Misconfiguration",
    "http-missing-security-headers":    "A05:2021 - Security Misconfiguration",
    "xss-deprecated-header":           "A05:2021 - Security Misconfiguration",
    "fastly-debug-headers":            "A05:2021 - Security Misconfiguration",
    "drupal-login":                    "A05:2021 - Security Misconfiguration",

    # A08
    "missing-sri":                  "A08:2021 - Software and Data Integrity Failures",

    # A01
    "google-calendar-exposure":     "A01:2021 - Broken Access Control",
    "csp-script-src-wildcard":      "A05:2021 - Security Misconfiguration",
    "weak-csp-detect":              "A05:2021 - Security Misconfiguration",

    # Info pure — pas de catégorie OWASP applicable
    "dns-waf-detect":               None,
    "mx-fingerprint":               None,
    "spf-record-detect":            None,
    "dkim-record-detect":           None,
    "dmarc-detect":                 None,
    "nameserver-fingerprint":       None,
    "ssl-issuer":                   None,
    "ssl-dns-names":                None,
    "wildcard-tls":                 None,
    "txt-fingerprint":              None,
    "caa-fingerprint":              None,
    "aaaa-fingerprint":             None,
    "mx-service-detector":          None,
    "dns-saas-service-detection":   None,
    "drupal-detect":                None,
}


# ------------------------------------------------------------------
# 5. FONCTIONS UTILITAIRES
# ------------------------------------------------------------------

def normalize_cwe(cwe) -> str | None:
    """Normalise n'importe quelle représentation de CWE en string numérique pure."""
    if cwe is None:
        return None
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, dict):
        cwe = cwe.get("id") or cwe.get("cwe") or cwe.get("value")
    cwe_str = str(cwe).strip().lower().replace("cwe-", "").replace(" ", "")
    return cwe_str if cwe_str and cwe_str != "none" else None


def normalize_text(text: str) -> str:
    """
    Normalise un texte pour le matching heuristique.
    [BUG-5] : remplace les tirets par des espaces pour unifier
    'weak-cipher-suites' et 'weak cipher suites'.
    """
    return text.lower().replace("-", " ").replace("_", " ")


# ------------------------------------------------------------------
# 6. FONCTION PRINCIPALE
# ------------------------------------------------------------------

def map_owasp(
    title: str = "",
    description: str = "",
    cwe=None,
    cve_id: str | None = None,
    nuclei_template: str | None = None,
) -> str:
    """
    Retourne la catégorie OWASP Top 10 2021 correspondante.

    Ordre de priorité :
      1. Override CVE (CVE_OWASP_OVERRIDE) — corrige les erreurs NVD
      2. Template nuclei (NUCLEI_TEMPLATE_OWASP) — si fourni
      3. CWE officiel (OWASP_BY_CWE)
      4. Matching heuristique titre+description (OWASP_BY_TITLE)
      5. Fallback : "Non fourni"

    Args:
        title       : titre du finding (ZAP alert, nuclei name, CVE title...)
        description : description textuelle du finding
        cwe         : CWE sous toute forme (str, int, list, dict, "CWE-89"...)
        cve_id      : identifiant CVE ("CVE-2024-13254") pour les overrides
        nuclei_template : nom du template nuclei (ex: "deprecated-tls")
    """

    # ── Étape 1 : Override CVE ────────────────────────────────────
    if cve_id and cve_id.upper() in CVE_OWASP_OVERRIDE:
        return CVE_OWASP_OVERRIDE[cve_id.upper()]

    # ── Étape 2 : Template nuclei ─────────────────────────────────
    if nuclei_template:
        # Cherche d'abord le template exact, puis le préfixe
        template_norm = nuclei_template.lower().strip()
        if template_norm in NUCLEI_TEMPLATE_OWASP:
            result = NUCLEI_TEMPLATE_OWASP[template_norm]
            return result if result is not None else "Non fourni"
        # Matching préfixe (ex: "http-missing-security-headers:content-security-policy")
        for key in NUCLEI_TEMPLATE_OWASP:
            if template_norm.startswith(key):
                result = NUCLEI_TEMPLATE_OWASP[key]
                return result if result is not None else "Non fourni"

    # ── Étape 3 : CWE officiel ────────────────────────────────────
    cwe_str = normalize_cwe(cwe)
    if cwe_str and cwe_str in OWASP_BY_CWE:
        return OWASP_BY_CWE[cwe_str]

    # ── Étape 4 : Matching heuristique ────────────────────────────
    # [BUG-5] : normaliser le texte (tirets → espaces)
    raw_text = f"{title or ''} {description or ''}"
    text = normalize_text(raw_text)

    # Trier par longueur décroissante pour prioriser les clés spécifiques
    for key in sorted(OWASP_BY_TITLE.keys(), key=len, reverse=True):
        if key in text:
            return OWASP_BY_TITLE[key]

    # ── Étape 5 : Fallback ────────────────────────────────────────
    return "Non fourni"


# ------------------------------------------------------------------
# 7. INTERFACE HAUT NIVEAU — finding complet (dict)
# ------------------------------------------------------------------

def map_owasp_from_finding(finding: dict) -> str:
    """
    Interface haut niveau : extrait automatiquement les champs
    nécessaires depuis un finding complet (ZAP alert, CVE dict,
    nuclei result...) et appelle map_owasp().

    Champs supportés :
      ZAP   : alert/name, description, cweid, alertRef
      CVE   : cve_id/cve, description, cwe_id/cwe_name
      Nuclei: name/template_id, severity, details
    """
    title = (
        finding.get("alert")
        or finding.get("name")
        or finding.get("title")
        or finding.get("template_id")
        or ""
    )
    description = (
        finding.get("description")
        or finding.get("desc")
        or finding.get("details")
        or ""
    )
    cwe = (
        finding.get("cweid")
        or finding.get("cwe_id")
        or finding.get("cwe")
    )
    cve_id = (
        finding.get("cve_id")
        or finding.get("cve")
        or finding.get("cveId")
    )
    nuclei_template = (
        finding.get("template_id")
        or finding.get("nuclei_template")
        # Extraire le template depuis le titre nuclei (ex: "deprecated-tls:tls_1.0")
        or (title.split(":")[0] if ":" in str(title) else None)
    )

    return map_owasp(
        title=str(title),
        description=str(description),
        cwe=cwe,
        cve_id=str(cve_id) if cve_id else None,
        nuclei_template=str(nuclei_template) if nuclei_template else None,
    )


# ------------------------------------------------------------------
# 8. CAS SPÉCIAL — Plugins WordPress (cms_scan wpprobe)
# ------------------------------------------------------------------

def map_owasp_wordpress_plugin(plugin: dict) -> str:
    """
    Mappe un finding wpprobe (plugin WordPress) sur la catégorie OWASP.

    Logique :
    - Si cve != null et cvss_score > 0  → utiliser map_owasp_from_finding()
    - Si cve == null ou cvss_score == 0 → A06:2021 (composant non audité)

    Args:
        plugin : dict wpprobe avec champs source, plugin, cve, cvss_score, etc.
    """
    cve = plugin.get("cve") or plugin.get("cve_id")
    cvss = plugin.get("cvss_score", 0) or 0
    title = plugin.get("title", "") or ""

    # CVE réelle avec score → mapping précis
    if cve and str(cve).upper().startswith("CVE") and float(cvss) > 0:
        return map_owasp_from_finding(plugin)

    # Pas de CVE connue ou score nul → composant à surveiller
    # [CORRECTION Themewagon] : ne plus ignorer ces plugins
    return "A06:2021 - Vulnerable and Outdated Components"


# ------------------------------------------------------------------
# 9. TESTS UNITAIRES RAPIDES
# ------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        # (description, kwargs, expected)
        (
            "CVE-2024-13254 override (Forceful Browsing → A01)",
            {"title": "Insertion of Sensitive Information Into Sent Data", "cwe": "CWE-94", "cve_id": "CVE-2024-13254"},
            "A01:2021 - Broken Access Control",
        ),
        (
            "deprecated-tls nuclei template",
            {"nuclei_template": "deprecated-tls:tls_1.0"},
            "A02:2021 - Cryptographic Failures",
        ),
        (
            "weak-cipher-suites nuclei template (tiret)",
            {"title": "weak-cipher-suites:tls-1.0"},
            "A02:2021 - Cryptographic Failures",
        ),
        (
            "CWE-89 SQL Injection",
            {"title": "SQL injection", "cwe": "CWE-89"},
            "A03:2021 - Injection",
        ),
        (
            "CWE-326 TLS faible (manquant avant correction)",
            {"title": "Weak TLS", "cwe": "326"},
            "A02:2021 - Cryptographic Failures",
        ),
        (
            "CWE-693 CSP",
            {"title": "Content Security Policy Header Not Set", "cwe": "693"},
            "A05:2021 - Security Misconfiguration",
        ),
        (
            "CWE-1021 Clickjacking",
            {"title": "Missing Anti-clickjacking Header", "cwe": "1021"},
            "A05:2021 - Security Misconfiguration",
        ),
        (
            "CWE-345 SRI",
            {"title": "Sub Resource Integrity Missing", "cwe": "345"},
            "A08:2021 - Software and Data Integrity Failures",
        ),
        (
            "CWE-829 Cross-Domain JS",
            {"title": "Cross-Domain JavaScript Source File Inclusion", "cwe": "829"},
            "A08:2021 - Software and Data Integrity Failures",
        ),
        (
            "CWE-497 Server Header Leak",
            {"title": "Server Leaks Version Information", "cwe": "497"},
            "A05:2021 - Security Misconfiguration",
        ),
        (
            "CSRF via titre (sans CWE)",
            {"title": "CSRF vulnerability in Views module", "cwe": None},
            "A01:2021 - Broken Access Control",
        ),
        (
            "google-calendar-exposure nuclei",
            {"nuclei_template": "google-calendar-exposure"},
            "A01:2021 - Broken Access Control",
        ),
        (
            "Plugin WP sans CVE → A06",
            {},  # géré par map_owasp_wordpress_plugin
            "A06:2021 - Vulnerable and Outdated Components",
        ),
        (
            "dns-waf-detect → Non fourni (info pure)",
            {"nuclei_template": "dns-waf-detect"},
            "Non fourni",
        ),
    ]

    print("=" * 65)
    print("  Tests unitaires map_owasp.py")
    print("=" * 65)

    passed = 0
    failed = 0

    for desc, kwargs, expected in tests:
        if desc.startswith("Plugin WP"):
            result = map_owasp_wordpress_plugin({"cve": None, "cvss_score": 0})
        else:
            result = map_owasp(**kwargs)

        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {desc}")
        if result != expected:
            print(f"      Attendu  : {expected}")
            print(f"      Obtenu   : {result}")

    print("-" * 65)
    print(f"  Résultat : {passed}/{passed + failed} tests passés")
    print("=" * 65)