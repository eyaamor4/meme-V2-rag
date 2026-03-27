**A - Résumé Exécutif**

Le système a été analysé et 13 vulnérabilités prioritaires ont été identifiées. Le nombre total de vulnérabilités est de 29.

**B - Vulnérabilités Prioritaires**

1. **SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal**
* Score CVSS : 7.5
	* Description : SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields."
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
	* Vérification : Rechercher les usages de concaténation SQL dans le code et tester les paramètres identifiés avec payloads d’injection.

2. **SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal**
* Score CVSS : 7.5
	* Description : SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments."
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
	* Vérification : Rechercher les usages de concaténation SQL dans le code et tester les paramètres identifiés avec payloads d’injection.

3. **Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views**
* Score CVSS : 7.5
	* Description : Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Inventorier les vues REST exposées publiquement, limiter les permissions sur les displays REST de Views.
	* Vérification : Tester l’accès anonyme et authentifié aux endpoints REST.

4. **CSP: Failure to Define Directive with No Fallback**
	* Description : The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
	* Vérification : Exécuter curl -I sur plusieurs pages HTML et vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

5. **CSP: Wildcard Directive**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Remplacer * par une liste précise d’hôtes de confiance, éviter les schémas génériques comme https:.
	* Vérification : Comparer la CSP déployée avec l’inventaire réel des ressources chargées.

6. **CSP: script-src unsafe-inline**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Identifier les scripts inline présents dans les templates HTML, migrer les scripts inline vers des fichiers JS statiques versionnés.
	* Vérification : Vérifier que script-src ne contient plus unsafe-inline.

7. **CSP: style-src unsafe-inline**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Identifier les styles inline dans les templates et composants front-end, déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
	* Vérification : Vérifier que style-src ne contient plus unsafe-inline.

8. **Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation**
* Score CVSS : 6.8
	* Description : Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2010-4519
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Générer un jeton CSRF unique par session ou requête selon le framework.
	* Vérification : Tester les formulaires et endpoints POST/PUT/PATCH/DELETE.

9. **The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access**
* Score CVSS : 5.0
	* Description : The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2012-2081
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour Organic Groups vers une version corrigée.
	* Vérification : Tester les accès avec plusieurs rôles.

10. **The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache**
* Score CVSS : 5.0
	* Description : The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2015-5490
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour le module Views.
	* Vérification : Contrôler la version corrigée installée.

11. **The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions**
* Score CVSS : 5.3
	* Description : The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-6212
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour le module Views.
	* Vérification : Contrôler la version corrigée installée.

12. **Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation**
* Score CVSS : 5.4
	* Description : Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13287
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour le module Views SVG Animation.
	* Vérification : Contrôler la version corrigée installée.

13. **Sub Resource Integrity Attribute Missing**
	* Description : The integrity attribute is missing on a script or link tag served by an external server.
	* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter integrity et crossorigin sur les ressources stables et versionnées.
	* Vérification : Vérifier la présence de integrity et crossorigin sur les balises script et link externes.

**C - Plan de remédiation**

1. Mettre à jour le module Views vers une version corrigée.
2. Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
3. Générer un jeton CSRF unique par session ou requête selon le framework.
4. Mettre à jour Organic Groups vers une version corrigée.
5. Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
6. Remplacer * par une liste précise d’hôtes de confiance, éviter les schémas génériques comme https:.
7. Identifier les scripts inline présents dans les templates HTML, migrer les scripts inline vers des fichiers JS statiques versionnés.
8. Identifier les styles inline dans les templates et composants front-end, déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
9. Mettre à jour le module Views SVG Animation.
10. Ajouter integrity et crossorigin sur les ressources stables et versionnées.

**D - Conclusion**

Le système a été analysé et 13 vulnérabilités prioritaires ont été identifiées. Il est recommandé de mettre en œuvre les actions de remédiation listées ci-dessus pour corriger ces vulnérabilités.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P2 | vulnerability | high | Non fourni | Non fourni | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://antares.tn/ |  |  |
| P2 | vulnerability | high | Non fourni | Non fourni | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://antares.tn/ |  |  |
| P2 | vulnerability | high | Non fourni | Non fourni | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-13 |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-4 |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-5 |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-6 |
| P3 | vulnerability | medium | Non fourni | Non fourni | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script> | 90003 |
| P4 | vulnerability | low | Low | High | CSP: Notices | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-3 |
| P4 | vulnerability | medium | Non fourni | Non fourni | Cross-site scripting (XSS) vulnerability in the Devel module before 5.x-0.1 for Drupal allows remote attackers to inject arbitrary web script or HTML via a site variable, related to lack of escaping of the variable table. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | Cross-site scripting (XSS) vulnerability in the variable editor in the Devel module 5.x before 5.x-1.2 and 6.x before 6.x-1.18, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a variable name. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://antares.tn/ |  |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script> | 10017 |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://antares.tn/ |  | 10035-1 |
| P5 | vulnerability | low | Non fourni | Non fourni | Cross-site scripting (XSS) vulnerability in the Performance logging module in the Devel module 5.x before 5.x-1.3 and 6.x before 6.x-1.21 for Drupal allows remote authenticated users, with add url aliases and report access permissions, to inject arbitrary web script or HTML via crafted node paths in a URL. | https://antares.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://antares.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | aaaa-fingerprint | antares.tn | 2606:4700:3037::6815:2d1b, 2606:4700:3031::ac43:d014 |  |
| P5 | information | info | Non fourni | Non fourni | caa-fingerprint | antares.tn |  |  |
| P5 | information | info | Non fourni | Non fourni | deprecated-tls:tls_1.0 | antares.tn:443 | tls10 |  |
| P5 | information | info | Non fourni | Non fourni | deprecated-tls:tls_1.1 | antares.tn:443 | tls11 |  |
| P5 | information | info | Non fourni | Non fourni | dkim-record-detect | s1._domainkey.antares.tn | "v=DKIM1;t=s;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kDmU1YoAmYLEc3kjBGVjJIn7T6gZrbjcYWMg2SVXmAAlbuowpNXXKPEqD20F1ONleJgpioVa6e0cgEFHi27OliB+3pQjqHC2NAk2TveV1V0VmvWjGcZQVnV0buRd6F+XGlFlkFgUVNXVbDjT6KxeiPq1KzV5M+h3XSX0Mo9UnwIDAQAB"", "v=DKIM1;t=s;p=MIGfMA0GCS… |  |
| P5 | information | info | Non fourni | Non fourni | dmarc-detect | _dmarc.antares.tn | ""v=DMARC1;p=reject;rua=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@rua.easydmarc.com;ruf=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@ruf.easydmarc.com;aspf=s;adkim=s;fo=1;"" |  |
| P5 | information | info | Non fourni | Non fourni | dns-waf-detect:cloudflare | antares.tn |  |  |
| P5 | information | info | Non fourni | Non fourni | drupal-detect | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | drupal-login | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:clear-site-data | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:cross-origin-embedder-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:cross-origin-opener-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:cross-origin-resource-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:permissions-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:strict-transport-security | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:x-permitted-cross-domain-policies | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | missing-sri | https://antares.tn/ | https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js, https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js |  |
| P5 | information | info | Non fourni | Non fourni | mx-fingerprint | antares.tn | 10 alt3.aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 1 aspmx.l.google.com. |  |
| P5 | information | info | Non fourni | Non fourni | mx-service-detector:Google Apps | antares.tn |  |  |
| P5 | information | info | Non fourni | Non fourni | nameserver-fingerprint | antares.tn | sri.ns.cloudflare.com., brianna.ns.cloudflare.com. |  |
| P5 | information | info | Non fourni | Non fourni | spf-record-detect | antares.tn | "v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"" |  |
| P5 | information | info | Non fourni | Non fourni | ssl-dns-names | antares.tn:443 | antares.tn, *.antares.tn |  |
| P5 | information | info | Non fourni | Non fourni | ssl-issuer | antares.tn:443 | Google Trust Services |  |
| P5 | information | info | Non fourni | Non fourni | tls-version | antares.tn:443 | tls10, tls11, tls12, tls13 |  |
| P5 | information | info | Non fourni | Non fourni | txt-fingerprint | antares.tn | ""v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"",""MS=30DD2F2CD0F16D7EA3365B56D58C6E468916806D"",""ahrefs-site-verification_f15e967d15c60d7aaf91839236b91319da7e012e9f5d4a2eaa0080e4786b01cf"",""google-site-verification=BLOCvNHiYzK-BZA7Ft6cO6X36CwzP… |  |
| P5 | vulnerability | low | Non fourni | Non fourni | weak-cipher-suites:tls-1.0 | antares.tn:443 | [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | vulnerability | low | Non fourni | Non fourni | weak-cipher-suites:tls-1.1 | antares.tn:443 | [tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | information | info | Non fourni | Non fourni | weak-csp-detect:unsafe-script-src | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… |  |
| P5 | information | info | Non fourni | Non fourni | wildcard-tls | antares.tn:443 | CN: antares.tn, SAN: [antares.tn *.antares.tn] |  |
| P5 | information | info | Non fourni | Non fourni | xss-deprecated-header | https://antares.tn/ | 1; mode=block |  |
