A - Résumé Exécutif
10 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires. La surface d'attaque XSS est plus large en raison de la combinaison de plusieurs findings CSP, ce qui rend le risque combiné plus élevé.

B - Vulnérabilités Prioritaires
**CSP: Failure to Define Directive with No Fallback**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) ne définit pas une directive qui n'a pas de fallback, ce qui est équivalent à autoriser tout.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

**CSP: Wildcard Directive**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La directive CSP utilise un joker qui autorise des sources trop larges.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer le joker par une liste précise d'hôtes de confiance.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Comparer la CSP déployée avec l'inventaire réel des ressources chargées.

**CSP: script-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La directive CSP autorise l'exécution de scripts inline.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier que script-src ne contient plus unsafe-inline.

**CSP: style-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La directive CSP autorise l'injection de styles inline.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier que style-src ne contient plus unsafe-inline.

**Sub Resource Integrity Attribute Missing**
* Description : L'attribut d'intégrité de ressource est manquant sur un script ou un lien servi par un serveur externe.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter l'attribut d'intégrité sur les ressources stables et versionnées.
* Vérification : 
  - Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity='
  - Vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

C - Plan de remédiation
1. **CSP: Failure to Define Directive with No Fallback** : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
2. **CSP: Wildcard Directive** : Remplacer le joker par une liste précise d'hôtes de confiance.
3. **CSP: script-src unsafe-inline** : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés.
4. **CSP: style-src unsafe-inline** : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
5. **Sub Resource Integrity Attribute Missing** : Ajouter l'attribut d'intégrité sur les ressources stables et versionnées.

D - Conclusion
Le niveau de risque global est ÉLEVÉ. L'action prioritaire la plus critique est de remédier à la vulnérabilité **CSP: Failure to Define Directive with No Fallback**. Il est recommandé de prendre des mesures correctives dans les 7 jours.


## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 5 | 5 | 32 |

**Éléments techniques listés en annexe :** 59 | **Vulnérabilités retenues dans le rapport :** 10 | **Prioritaires (section B) :** 5


## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Devel module before 5.x-0.1 for Drupal allows remote attackers to inject arbitrary web script or HTML via a site variable, related to lack of escaping of the variable table. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | high | — | — | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the variable editor in the Devel module 5.x before 5.x-1.2 and 6.x before 6.x-1.18, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a variable name. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | high | — | — | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | high | — | — | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Performance logging module in the Devel module 5.x before 5.x-1.3 and 6.x before 6.x-1.21 for Drupal allows remote authenticated users, with add url aliases and report access permissions, to inject arbitrary web script or HTML via crafted node paths in a URL. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://antares.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-4 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-6 | — |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script>, <script src="https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js"></script> | 90003 | — |
| P4 | vulnerability | low | Low | High | CSP: Notices | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-3 | — |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script>, <script src="https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js"></script> | 10017 | — |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://antares.tn/ | — | 10035-1 | — |
| P5 | information | info | — | — | Technologie détectée : Cloudflare | https://antares.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Drupal | https://antares.tn/ | 11 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HTTP/3 | https://antares.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : PHP | https://antares.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | aaaa-fingerprint | antares.tn | 2606:4700:3037::6815:2d1b, 2606:4700:3031::ac43:d014 |  | — |
| P5 | information | info | — | — | caa-fingerprint | antares.tn | — |  | — |
| P5 | information | info | — | — | deprecated-tls:tls_1.0 | antares.tn:443 | tls10 |  | — |
| P5 | information | info | — | — | deprecated-tls:tls_1.1 | antares.tn:443 | tls11 |  | — |
| P5 | information | info | — | — | dkim-record-detect | s1._domainkey.antares.tn | "v=DKIM1;t=s;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kDmU1YoAmYLEc3kjBGVjJIn7T6gZrbjcYWMg2SVXmAAlbuowpNXXKPEqD20F1ONleJgpioVa6e0cgEFHi27OliB+3pQjqHC2NAk2TveV1V0VmvWjGcZQVnV0buRd6F+XGlFlkFgUVNXVbDjT6KxeiPq1KzV5M+h3XSX0Mo9UnwIDAQAB"", "v=DKIM1;t=s;p=MIGfMA0GCS… |  | — |
| P5 | information | info | — | — | dmarc-detect | _dmarc.antares.tn | ""v=DMARC1;p=reject;rua=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@rua.easydmarc.com;ruf=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@ruf.easydmarc.com;aspf=s;adkim=s;fo=1;"" |  | — |
| P5 | information | info | — | — | dns-waf-detect:cloudflare | antares.tn | — |  | — |
| P5 | information | info | — | — | drupal-detect | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | drupal-login | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:permissions-policy | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:strict-transport-security | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://antares.tn/ | — |  | — |
| P5 | information | info | — | — | missing-sri | https://antares.tn/ | https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js, https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js |  | — |
| P5 | information | info | — | — | mx-fingerprint | antares.tn | 10 alt3.aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 1 aspmx.l.google.com. |  | — |
| P5 | information | info | — | — | mx-service-detector:Google Apps | antares.tn | — |  | — |
| P5 | information | info | — | — | nameserver-fingerprint | antares.tn | sri.ns.cloudflare.com., brianna.ns.cloudflare.com. |  | — |
| P5 | information | info | — | — | spf-record-detect | antares.tn | "v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"" |  | — |
| P5 | information | info | — | — | ssl-dns-names | antares.tn:443 | antares.tn, *.antares.tn |  | — |
| P5 | information | info | — | — | ssl-issuer | antares.tn:443 | Google Trust Services |  | — |
| P5 | information | info | — | — | tls-version | antares.tn:443 | tls10, tls11, tls12, tls13 |  | — |
| P5 | information | info | — | — | txt-fingerprint | antares.tn | ""v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"",""MS=30DD2F2CD0F16D7EA3365B56D58C6E468916806D"",""ahrefs-site-verification_f15e967d15c60d7aaf91839236b91319da7e012e9f5d4a2eaa0080e4786b01cf"",""google-site-verification=BLOCvNHiYzK-BZA7Ft6cO6X36CwzP… |  | — |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.0 | antares.tn:443 | [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  | — |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.1 | antares.tn:443 | [tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  | — |
| P5 | information | info | — | — | weak-csp-detect:unsafe-script-src | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… |  | — |
| P5 | information | info | — | — | wildcard-tls | antares.tn:443 | CN: antares.tn, SAN: [antares.tn *.antares.tn] |  | — |
| P5 | information | info | — | — | xss-deprecated-header | https://antares.tn/ | 1; mode=block |  | — |
