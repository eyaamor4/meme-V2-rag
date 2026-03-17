OWASP_BY_CWE = {
    # A01 - Broken Access Control
    "22": "A01:2021 - Broken Access Control",
    "23": "A01:2021 - Broken Access Control",
    "35": "A01:2021 - Broken Access Control",
    "59": "A01:2021 - Broken Access Control",
    "200": "A01:2021 - Broken Access Control",
    "201": "A01:2021 - Broken Access Control",
    "264": "A01:2021 - Broken Access Control",
    "284": "A01:2021 - Broken Access Control",
    "285": "A01:2021 - Broken Access Control",  # ajouté
    "352": "A01:2021 - Broken Access Control",

    # A02 - Cryptographic Failures
    "259": "A02:2021 - Cryptographic Failures",
    "319": "A02:2021 - Cryptographic Failures",
    "327": "A02:2021 - Cryptographic Failures",

    # A03 - Injection
    "73":  "A03:2021 - Injection",
    "79":  "A03:2021 - Injection",
    "89":  "A03:2021 - Injection",
    "94":  "A03:2021 - Injection",   # ajouté - Code Injection

    # A05 - Security Misconfiguration
    "16":   "A05:2021 - Security Misconfiguration",
    "525":  "A05:2021 - Security Misconfiguration",
    "614":  "A05:2021 - Security Misconfiguration",
    "615":  "A05:2021 - Security Misconfiguration",  # ajouté
    "693":  "A05:2021 - Security Misconfiguration",
    "1004": "A05:2021 - Security Misconfiguration",
    "1021": "A05:2021 - Security Misconfiguration",
    "1275": "A05:2021 - Security Misconfiguration",

    # A06 - Vulnerable and Outdated Components
    "1104": "A06:2021 - Vulnerable and Outdated Components",

    # A07 - Identification and Authentication Failures
    "287": "A07:2021 - Identification and Authentication Failures",
    "384": "A07:2021 - Identification and Authentication Failures",

    # A08 - Software and Data Integrity Failures
    "345": "A08:2021 - Software and Data Integrity Failures",
    "494": "A08:2021 - Software and Data Integrity Failures",
    "502": "A08:2021 - Software and Data Integrity Failures",
    "829": "A08:2021 - Software and Data Integrity Failures",
}

OWASP_BY_TITLE = {
    # Injection
    "sql injection":            "A03:2021 - Injection",
    "sqli":                     "A03:2021 - Injection",
    "cross-site scripting":     "A03:2021 - Injection",
    "xss":                      "A03:2021 - Injection",
    "remote code execution":    "A03:2021 - Injection",
    "arbitrary code":           "A03:2021 - Injection",
    "code injection":           "A03:2021 - Injection",

    # Broken Access Control
    "csrf":                          "A01:2021 - Broken Access Control",
    "cross-site request forgery":    "A01:2021 - Broken Access Control",
    "improper access control":       "A01:2021 - Broken Access Control",
    "cors":                          "A01:2021 - Broken Access Control",  # ajouté
    "cross-domain misconfiguration": "A01:2021 - Broken Access Control",  # ajouté
    "forceful browsing":             "A01:2021 - Broken Access Control",  # ajouté
    "information disclosure":        "A01:2021 - Broken Access Control",  # ajouté
    "access restriction":            "A01:2021 - Broken Access Control",  # ajouté
    "bypass":                        "A01:2021 - Broken Access Control",  # ajouté

    # Cryptographic Failures
    "weak-cipher-suites":   "A02:2021 - Cryptographic Failures",
    "weak cipher suites":   "A02:2021 - Cryptographic Failures",
    "deprecated-tls":       "A02:2021 - Cryptographic Failures",
    "deprecated tls":       "A02:2021 - Cryptographic Failures",
    "cleartext":            "A02:2021 - Cryptographic Failures",
    "insecure transport":   "A02:2021 - Cryptographic Failures",
    "tls":                  "A02:2021 - Cryptographic Failures",

    # Security Misconfiguration
    "content security policy":      "A05:2021 - Security Misconfiguration",
    "strict-transport-security":    "A05:2021 - Security Misconfiguration",
    "x-content-type-options":       "A05:2021 - Security Misconfiguration",
    "x-frame-options":              "A05:2021 - Security Misconfiguration",
    "cookie without secure flag":   "A05:2021 - Security Misconfiguration",
    "cookie no httponly flag":      "A05:2021 - Security Misconfiguration",
    "cookie without samesite":      "A05:2021 - Security Misconfiguration",
    "missing security header":      "A05:2021 - Security Misconfiguration",
    "security misconfiguration":    "A05:2021 - Security Misconfiguration",
    "hsts":                         "A05:2021 - Security Misconfiguration",
    "csp":                          "A05:2021 - Security Misconfiguration",

    # Software and Data Integrity Failures
    "subresource integrity":       "A08:2021 - Software and Data Integrity Failures",
    "sub resource integrity":      "A08:2021 - Software and Data Integrity Failures",
    "cross-domain javascript source file inclusion": "A08:2021 - Software and Data Integrity Failures",
    "untrusted javascript":        "A08:2021 - Software and Data Integrity Failures",

    # Vulnerable and Outdated Components
    "vulnerable and outdated components": "A06:2021 - Vulnerable and Outdated Components",
    "outdated component":                 "A06:2021 - Vulnerable and Outdated Components",
    "obsolete component":                 "A06:2021 - Vulnerable and Outdated Components",

    # Identification and Authentication Failures
    "session fixation":          "A07:2021 - Identification and Authentication Failures",
    "improper authentication":   "A07:2021 - Identification and Authentication Failures",
    "authentication bypass":     "A07:2021 - Identification and Authentication Failures",
}


def normalize_cwe(cwe) -> str | None:
    if cwe is None:
        return None
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, dict):
        cwe = cwe.get("id") or cwe.get("cwe") or cwe.get("value")
    cwe_str = str(cwe).strip().lower().replace("cwe-", "")
    return cwe_str if cwe_str else None


def map_owasp(title: str = "", description: str = "", cwe=None) -> str:
    # 1) CWE officiel en priorité
    cwe_str = normalize_cwe(cwe)
    if cwe_str and cwe_str in OWASP_BY_CWE:
        return OWASP_BY_CWE[cwe_str]

    # 2) Matching heuristique — clés longues en premier (plus spécifique)
    text = f"{title or ''} {description or ''}".lower()
    for key in sorted(OWASP_BY_TITLE.keys(), key=len, reverse=True):
        if key in text:
            return OWASP_BY_TITLE[key]

    return "Non fourni"