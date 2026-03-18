**A - Résumé Exécutif**

Le nombre total de vulnérabilités est de 36. Parmi elles, 15 sont considérées comme prioritaires. Ce rapport présente les vulnérabilités prioritaires identifiées, ainsi que les recommandations pour les corriger.

**B - Vulnérabilités Prioritaires**

1. **SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields."**
	* Description : SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields."
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views à 6.x-2.2 ou supérieur.
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 6.x-2.2.
	* Score CVSS : 7.5

2. **SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments."**
	* Description : SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments."
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views à 6.x-2.13 ou supérieur.
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 6.x-2.13.
	* Score CVSS : 7.5

3. **Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1.**
	* Description : Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version de la bibliothèque REST Views à 3.0.1 ou supérieur.
	* Vérification : Vérifier que la version de la bibliothèque REST Views est supérieure ou égale à 3.0.1.
	* Score CVSS : 7.5

4. **CSP: Failure to Define Directive with No Fallback**
	* Description : The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.

5. **CSP: Wildcard Directive**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
	* Vérification : Contrôler que les directives CSP n’utilisent plus de joker '*' ni de schéma trop permissif comme https: lorsqu’une liste d’hôtes précise peut être définie.

6. **CSP: script-src unsafe-inline**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que script-src ne contient plus 'unsafe-inline' et que les scripts inline nécessaires utilisent un nonce ou un hash.

7. **CSP: style-src unsafe-inline**
	* Description : Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
	* Référence : https://www.w3.org/TR/CSP/
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de style-src et migrer les styles inline vers des feuilles CSS autorisées ou des hashes lorsque nécessaire.
	* Vérification : Vérifier que style-src ne contient plus 'unsafe-inline' et que les styles requis proviennent de fichiers CSS approuvés ou de hashes explicites.

8. **The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value, which allows remote attackers to read session variables via unspecified vectors.**
	* Description : The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value, which allows remote attackers to read session variables via unspecified vectors.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2009-4533
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module Webform à 5.x-2.8 ou supérieur.
	* Vérification : Vérifier que la version du module Webform est supérieure ou égale à 5.x-2.8.
	* Score CVSS : 5.0

9. **Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views.**
	* Description : Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2010-4519
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 5.x-1.8 ou supérieur.
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 5.x-1.8.
	* Score CVSS : 6.8

10. **The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module.**
	* Description : The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2012-2081
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module Organic Groups à 6.x-2.3 ou supérieur.
	* Vérification : Vérifier que la version du module Organic Groups est supérieure ou égale à 6.x-2.3.
	* Score CVSS : 5.0

11. **The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors.**
	* Description : The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2015-5490
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 7.x-3.10 ou supérieur.
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 7.x-3.10.
	* Score CVSS : 5.0

12. **The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content, aka a "reflected file download vulnerability."**
	* Description : The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content, aka a "reflected file download vulnerability."
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-3168
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module System à 6.38 ou supérieur.
	* Vérification : Vérifier que la version du module System est supérieure ou égale à 6.38.
	* Score CVSS : 6.4

13. **The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors.**
	* Description : The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-6212
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 7.x-3.14 ou supérieur.
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 7.x-3.14.
	* Score CVSS : 5.3

14. **Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1.**
	* Description : Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1.
	* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13287
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version de la bibliothèque Views SVG Animation à 1.0.1 ou supérieur.
	* Vérification : Vérifier que la version de la bibliothèque Views SVG Animation est supérieure ou égale à 1.0.1.
	* Score CVSS : 5.4

15. **Sub Resource Integrity Attribute Missing**
	* Description : The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content.
	* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut integrity valide correspondant au contenu réellement servi.

**C - Plan de remédiation**

1. Mettre à jour la version du module Views à 6.x-2.2 ou supérieur.
2. Mettre à jour la version du module Views à 6.x-2.13 ou supérieur.
3. Mettre à jour la version de la bibliothèque REST Views à 3.0.1 ou supérieur.
4. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
5. Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
6. Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
7. Supprimer 'unsafe-inline' de style-src et migrer les styles inline vers des feuilles CSS autorisées ou des hashes lorsque nécessaire.
8. Mettre à jour la version du module Webform à 5.x-2.8 ou supérieur.
9. Mettre à jour la version du module Views à 5.x-1.8 ou supérieur.
10. Mettre à jour la version du module Organic Groups à 6.x-2.3 ou supérieur.
11. Mettre à jour la version du module Views à 7.x-3.10 ou supérieur.
12. Mettre à jour la version du module System à 6.38 ou supérieur.
13. Mettre à jour la version du module Views à 7.x-3.14 ou supérieur.
14. Mettre à jour la version de la bibliothèque Views SVG Animation à 1.0.1 ou supérieur.
15. Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

**D - Conclusion**

Le nombre total de vulnérabilités est de 36. Parmi elles, 15 sont considérées comme prioritaires. Ce rapport présente les vulnérabilités prioritaires identifiées, ainsi que les recommandations pour les corriger. Il est important de mettre en œuvre les recommandations pour améliorer la sécurité du système.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P2 | vulnerability | high | Non fourni | Non fourni | cve | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://www.biat.com.tn/ |  |  |
| P2 | vulnerability | high | Non fourni | Non fourni | cve | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://www.biat.com.tn/ |  |  |
| P2 | vulnerability | high | Non fourni | Non fourni | cve | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Medium | High | zap | CSP: Failure to Define Directive with No Fallback | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-13 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: Wildcard Directive | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-4 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: script-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-5 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: style-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-6 |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value, which allows remote attackers to read session variables via unspecified vectors. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content, aka a "reflected file download vulnerability." | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Non fourni | Non fourni | cve | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://www.biat.com.tn/ |  |  |
| P3 | vulnerability | medium | Medium | High | zap | Sub Resource Integrity Attribute Missing | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script> | 90003 |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the webform module in Drupal 4.6 before July 8, 2006 and 4.7 before July 8, 2006 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.7 and 6.x before 6.x-2.7, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a submission. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.19 for Drupal allows remote authenticated users with the "edit own webform content" or "edit all webform content" permissions to inject arbitrary web script or HTML via a component label. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | medium | Non fourni | Non fourni | cve | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://www.biat.com.tn/ |  |  |
| P4 | vulnerability | low | Low | Medium | zap | Cross-Domain JavaScript Source File Inclusion | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script> | 10017 |
| P4 | vulnerability | low | Low | High | zap | Server Leaks Version Information via "Server" HTTP Response Header Field | https://www.biat.com.tn/ | Apache/2.4.62 (Debian) | 10036-2 |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, allows remote authenticated users, with webform creation privileges, to inject arbitrary web script or HTML via a field label. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Multiple cross-site scripting (XSS) vulnerabilities in components/select.inc in the Webform module 6.x-3.x before 6.x-3.17 and 7.x-3.x before 7.x-3.17 for Drupal, when the "Select (or other)" module is enabled, allow remote authenticated users with the create webform content permission to inject arbitrary web script or HTML via vectors related to (1) checkboxes or (2) radios. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.20, 7.x-3.x before 7.x-3.20, and 7.x-4.x before 7.x-4.0-beta2 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a field label title, when two fields have the same form_key. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the view-based webform results table in the Webform module 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a webform. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.22, 7.x-3.x before 7.x-3.22, and 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a node title, which is used as the default title of a webform block. | https://www.biat.com.tn/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.23, 7.x-3.x before 7.x-3.23, and 7.x-4.x before 7.x-4.5 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a component name in the recipient (To) address of an email. | https://www.biat.com.tn/ |  |  |
