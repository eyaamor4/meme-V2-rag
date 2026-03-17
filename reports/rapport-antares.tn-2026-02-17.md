**A - Résumé Exécutif**

Le rapport de vulnérabilité présente 13 vulnérabilités prioritaires identifiées sur le système. Ces vulnérabilités nécessitent une attention immédiate pour garantir la sécurité du système.

**B - Vulnérabilités Prioritaires**

1. **SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal**
	* Description : SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields."
	* Impact potentiel : Les attaquants peuvent exécuter des commandes SQL arbitraires, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views à 6.x-2.2 ou supérieur.
	* Vérification : Vérifier que la version du module Views est à 6.x-2.2 ou supérieur.
	* Score CVSS : 7.5

2. **SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal**
	* Description : SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments."
	* Impact potentiel : Les attaquants peuvent exécuter des commandes SQL arbitraires, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views à 6.x-2.13 ou supérieur.
	* Vérification : Vérifier que la version du module Views est à 6.x-2.13 ou supérieur.
	* Score CVSS : 7.5

3. **Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views**
	* Description : Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1.
	* Impact potentiel : Les attaquants peuvent accéder à des informations sensibles, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module REST Views à 3.0.1 ou supérieur.
	* Vérification : Vérifier que la version du module REST Views est à 3.0.1 ou supérieur.
	* Score CVSS : 7.5

4. **CSP: Failure to Define Directive with No Fallback**
	* Description : The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.
	* Impact potentiel : Les attaquants peuvent injecter du code malveillant, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src.
	* Vérification : Vérifier que les directives CSP sont définies correctement.
	* Score CVSS : Non fourni

5. **CSP: Wildcard Directive**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
	* Impact potentiel : Les attaquants peuvent injecter du code malveillant, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
	* Vérification : Contrôler que les directives CSP n’utilisent plus de joker '*' ni de schéma trop permissif comme https: lorsqu’une liste d’hôtes précise peut être définie.
	* Score CVSS : Non fourni

6. **CSP: script-src unsafe-inline**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
	* Impact potentiel : Les attaquants peuvent injecter du code malveillant, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que script-src ne contient plus 'unsafe-inline' et que les scripts inline nécessaires utilisent un nonce ou un hash.
	* Score CVSS : Non fourni

7. **CSP: style-src unsafe-inline**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
	* Impact potentiel : Les attaquants peuvent injecter du code malveillant, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que script-src ne contient plus 'unsafe-inline' et que les scripts inline nécessaires utilisent un nonce ou un hash.
	* Score CVSS : Non fourni

8. **Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal**
	* Description : Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views.
	* Impact potentiel : Les attaquants peuvent accéder aux comptes administrateurs, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 5.x-1.8 ou supérieur.
	* Vérification : Vérifier que la version du module Views est à 5.x-1.8 ou supérieur.
	* Score CVSS : 6.8

9. **The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access**
	* Description : The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module.
	* Impact potentiel : Les attaquants peuvent accéder à des informations sensibles, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module OG à 6.x-2.3 ou supérieur.
	* Vérification : Vérifier que la version du module OG est à 6.x-2.3 ou supérieur.
	* Score CVSS : 5.0

10. **The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache**
	* Description : The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors.
	* Impact potentiel : Les attaquants peuvent accéder à du contenu caché, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 7.x-3.10 ou supérieur.
	* Vérification : Vérifier que la version du module Views est à 7.x-3.10 ou supérieur.
	* Score CVSS : 5.0

11. **The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions**
	* Description : The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors.
	* Impact potentiel : Les attaquants peuvent accéder à des informations sensibles, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 7.x-3.14 ou supérieur.
	* Vérification : Vérifier que la version du module Views est à 7.x-3.14 ou supérieur.
	* Score CVSS : 5.3

12. **Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation**
	* Description : Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1.
	* Impact potentiel : Les attaquants peuvent injecter du code malveillant, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views SVG Animation à 1.0.1 ou supérieur.
	* Vérification : Vérifier que la version du module Views SVG Animation est à 1.0.1 ou supérieur.
	* Score CVSS : 5.4

13. **Sub Resource Integrity Attribute Missing**
	* Description : The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content.
	* Impact potentiel : Les attaquants peuvent injecter du code malveillant, ce qui peut entraîner une compromission de la sécurité du système.
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut integrity valide correspondant au contenu réellement servi.
	* Score CVSS : Non fourni

**C - Plan de remédiation**

1. Mettre à jour la version du module Views à 6.x-2.2 ou supérieur pour résoudre la vulnérabilité SQL injection.
2. Mettre à jour la version du module Views à 6.x-2.13 ou supérieur pour résoudre la vulnérabilité SQL injection.
3. Mettre à jour la version du module REST Views à 3.0.1 ou supérieur pour résoudre la vulnérabilité d'insertion de données sensibles.
4. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src pour résoudre la vulnérabilité de la politique de sécurité.
5. Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée pour résoudre la vulnérabilité de la politique de sécurité.
6. Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes pour résoudre la vulnérabilité de la politique de sécurité.
7. Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes pour résoudre la vulnérabilité de la politique de sécurité.
8. Mettre à jour la version du module Views à 5.x-1.8 ou supérieur pour résoudre la vulnérabilité CSRF.
9. Mettre à jour la version du module OG à 6.x-2.3 ou supérieur pour résoudre la vulnérabilité d'accès non autorisé.
10. Mettre à jour la version du module Views à 7.x-3.10 ou supérieur pour résoudre la vulnérabilité d'accès non autorisé.
11. Mettre à jour la version du module Views à 7.x-3.14 ou supérieur pour résoudre la vulnérabilité d'accès non autorisé.
12. Mettre à jour la version du module Views SVG Animation à 1.0.1 ou supérieur pour résoudre la vulnérabilité XSS.
13. Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN pour résoudre la vulnérabilité de l'intégrité des ressources.

**D - Conclusion**

Le rapport de vulnérabilité a identifié 13 vulnérabilités prioritaires sur le système. Il est essentiel de mettre en œuvre les recommandations de remédiation pour résoudre ces vulnérabilités et garantir la sécurité du système.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P2 | vulnerability | high | Non fourni | Non fourni | cve | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://antares.tn/ |  |  |
| P2 | vulnerability | high | Non fourni | Non fourni | cve | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://antares.tn/ |  |  |
| P2 | vulnerability | high | Non fourni | Non fourni | cve | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Medium | High | zap | CSP: Failure to Define Directive with No Fallback | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-13 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: Wildcard Directive | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-4 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: script-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-5 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: style-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-6 |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://antares.tn/ |  |  |
| P3 | vulnerability | medium | Medium | High | zap | Sub Resource Integrity Attribute Missing | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script> | 90003 |
| P4 | vulnerability | low | Low | High | zap | CSP: Notices | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-3 |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Devel module before 5.x-0.1 for Drupal allows remote attackers to inject arbitrary web script or HTML via a site variable, related to lack of escaping of the variable table. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the variable editor in the Devel module 5.x before 5.x-1.2 and 6.x before 6.x-1.18, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a variable name. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://antares.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://antares.tn/ |  |  |
| P4 | vulnerability | low | Low | Medium | zap | Cross-Domain JavaScript Source File Inclusion | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script> | 10017 |
| P4 | vulnerability | low | Low | High | zap | Strict-Transport-Security Header Not Set | https://antares.tn/ |  | 10035-1 |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Performance logging module in the Devel module 5.x before 5.x-1.3 and 6.x before 6.x-1.21 for Drupal allows remote authenticated users, with add url aliases and report access permissions, to inject arbitrary web script or HTML via crafted node paths in a URL. | https://antares.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://antares.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | aaaa-fingerprint | antares.tn | 2606:4700:3037::6815:2d1b, 2606:4700:3031::ac43:d014 |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | caa-fingerprint | antares.tn |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | deprecated-tls:tls_1.0 | antares.tn:443 | tls10 |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | deprecated-tls:tls_1.1 | antares.tn:443 | tls11 |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | dkim-record-detect | s1._domainkey.antares.tn | "v=DKIM1;t=s;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kDmU1YoAmYLEc3kjBGVjJIn7T6gZrbjcYWMg2SVXmAAlbuowpNXXKPEqD20F1ONleJgpioVa6e0cgEFHi27OliB+3pQjqHC2NAk2TveV1V0VmvWjGcZQVnV0buRd6F+XGlFlkFgUVNXVbDjT6KxeiPq1KzV5M+h3XSX0Mo9UnwIDAQAB"", "v=DKIM1;t=s;p=MIGfMA0GCS… |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | dmarc-detect | _dmarc.antares.tn | ""v=DMARC1;p=reject;rua=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@rua.easydmarc.com;ruf=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@ruf.easydmarc.com;aspf=s;adkim=s;fo=1;"" |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | dns-waf-detect:cloudflare | antares.tn |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | drupal-detect | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | drupal-login | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:clear-site-data | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:cross-origin-embedder-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:cross-origin-opener-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:cross-origin-resource-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:permissions-policy | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:strict-transport-security | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:x-permitted-cross-domain-policies | https://antares.tn/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | missing-sri | https://antares.tn/ | https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js, https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | mx-fingerprint | antares.tn | 10 alt3.aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 1 aspmx.l.google.com. |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | mx-service-detector:Google Apps | antares.tn |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | nameserver-fingerprint | antares.tn | sri.ns.cloudflare.com., brianna.ns.cloudflare.com. |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | spf-record-detect | antares.tn | "v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"" |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | ssl-dns-names | antares.tn:443 | antares.tn, *.antares.tn |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | ssl-issuer | antares.tn:443 | Google Trust Services |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | tls-version | antares.tn:443 | tls10, tls11, tls12, tls13 |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | txt-fingerprint | antares.tn | ""v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"",""MS=30DD2F2CD0F16D7EA3365B56D58C6E468916806D"",""ahrefs-site-verification_f15e967d15c60d7aaf91839236b91319da7e012e9f5d4a2eaa0080e4786b01cf"",""google-site-verification=BLOCvNHiYzK-BZA7Ft6cO6X36CwzP… |  |
| P5 | vulnerability | low | Non fourni | Non fourni | nuclei | weak-cipher-suites:tls-1.0 | antares.tn:443 | [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | vulnerability | low | Non fourni | Non fourni | nuclei | weak-cipher-suites:tls-1.1 | antares.tn:443 | [tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | weak-csp-detect:unsafe-script-src | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | wildcard-tls | antares.tn:443 | CN: antares.tn, SAN: [antares.tn *.antares.tn] |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | xss-deprecated-header | https://antares.tn/ | 1; mode=block |  |
