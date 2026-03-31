A - Résumé Exécutif

55 vulnérabilités ont été identifiées au total, dont 13 sont prioritaires. Le niveau de risque global est ÉLEVÉ.

B - Vulnérabilités Prioritaires

1. **SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal**
* Description : La vulnérabilité permet aux attaquants d'exécuter des commandes SQL arbitraires via des vecteurs non spécifiés liés à "un filtre exposé sur les champs de texte CCK."
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
* Score CVSS : 7.5
* Catégorie OWASP : A03:2021 - Injection
* Recommandation technique : Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
* Vérification : Rechercher les usages de concaténation SQL dans le code.

2. **SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal**
* Description : La vulnérabilité permet aux attaquants d'exécuter des commandes SQL arbitraires via des vecteurs liés à "filtres/arguments sur certains types de vues avec des configurations spécifiques d'arguments."
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
* Score CVSS : 7.5
* Catégorie OWASP : A03:2021 - Injection
* Recommandation technique : Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
* Vérification : Rechercher les usages de concaténation SQL dans le code.

3. **Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views**
* Description : La vulnérabilité permet aux attaquants d'obtenir des informations sensibles via des requêtes spécifiques.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
* Score CVSS : 7.5
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Limiter les permissions sur les displays REST de Views, retirer les champs sensibles non nécessaires.
* Vérification : Tester l’accès anonyme et authentifié aux endpoints REST.

4. **CSP: Failure to Define Directive with No Fallback**
* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive avec un fallback, ce qui permet aux attaquants d'injecter du code malveillant.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy.

5. **CSP: Wildcard Directive**
* Description : La politique de sécurité du contenu (CSP) utilise un joker qui autorise toutes les sources, ce qui permet aux attaquants d'injecter du code malveillant.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer le joker par une liste précise d’hôtes de confiance.
* Vérification : Comparer la CSP déployée avec l’inventaire réel des ressources chargées.

6. **CSP: script-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui permet aux attaquants d'injecter du code malveillant.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les scripts inline présents dans les templates HTML, migrer vers des fichiers JS statiques versionnés.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy.

7. **CSP: style-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui permet aux attaquants d'injecter du code malveillant.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end, déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy.

8. **Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation**
* Description : Les vulnérabilités permettent aux attaquants de prendre le contrôle des sessions administrateur pour effectuer des requêtes spécifiques.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2010-4519
* Score CVSS : 6.8
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Générer un jeton CSRF unique par session ou requête, vérifier ce jeton côté serveur sur tous les endpoints d’écriture ou d’action.
* Vérification : Tester les formulaires et endpoints POST/PUT/PATCH/DELETE.

9. **The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal**
* Description : La vulnérabilité permet aux attaquants d'obtenir des informations sensibles via des requêtes spécifiques.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2012-2081
* Score CVSS : 5.0
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour Organic Groups vers une version corrigée, revoir les permissions par rôle et les displays Views associés.
* Vérification : Tester les accès avec plusieurs rôles.

10. **The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal**
* Description : La vulnérabilité permet aux attaquants de prendre le contrôle des sessions administrateur pour effectuer des requêtes spécifiques.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2015-5490
* Score CVSS : 5.0
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour le module Views vers une version corrigée, revoir les permissions par rôle et les displays Views associés.
* Vérification : Tester les accès avec plusieurs rôles.

11. **Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation**
* Description : La vulnérabilité permet aux attaquants d'injecter du code malveillant via des requêtes spécifiques.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13287
* Score CVSS : 5.4
* Catégorie OWASP : A03:2021 - Injection
* Recommandation technique : Mettre à jour le module Views SVG Animation vers une version corrigée, identifier les champs de configuration ou paramètres exposés réinjectés dans la sortie HTML.
* Vérification : Contrôler la version corrigée installée.

12. **Sub Resource Integrity Attribute Missing**
* Description : La vulnérabilité permet aux attaquants d'injecter du code malveillant via des requêtes spécifiques.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
* Vérification : Inspecter le code source HTML.

13. **Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation**
* Description : Les vulnérabilités permettent aux attaquants de prendre le contrôle des sessions administrateur pour effectuer des requêtes spécifiques.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2010-4519
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Générer un jeton CSRF unique par session ou requête, vérifier ce jeton côté serveur sur tous les endpoints d’écriture ou d’action.
* Vérification : Tester les formulaires et endpoints POST/PUT/PATCH/DELETE.

C - Plan de remédiation

- Mettre à jour Drupal vers la version corrigée mentionnée pour les vulnérabilités prioritaires.
- Mettre en place des politiques de sécurité du contenu (CSP) pour prévenir l'injection de code malveillant.
- Générer et vérifier les jetons CSRF pour prévenir les attaques par prise de contrôle de session.

D - Conclusion

Le niveau de risque global est ÉLEVÉ. La vulnérabilité la plus critique est la SQL injection dans le module Views, qui nécessite une mise à jour urgente vers la version corrigée. Le délai pour remédier à ces vulnérabilités est de moins de 24 heures.

Note : Les recommandations techniques et les vérifications sont spécifiques à chaque vulnérabilité et doivent être adaptées en fonction des besoins du site web.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 3 | 16 | 8 | 28 |

    **Total :** 55 | **Prioritaires :** 13
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P2 | vulnerability | high | — | — | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://antares.tn/ | — |  |  |
| P2 | vulnerability | high | — | — | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://antares.tn/ | — |  |  |
| P2 | vulnerability | high | — | — | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://antares.tn/ | — |  |  |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-13 |  |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-4 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-5 |  |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-6 |  |
| P3 | vulnerability | medium | — | — | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://antares.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://antares.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://antares.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://antares.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://antares.tn/ | — |  |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script> | 90003 |  |
| P4 | vulnerability | low | Low | High | CSP: Notices | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… | 10055-3 |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Devel module before 5.x-0.1 for Drupal allows remote attackers to inject arbitrary web script or HTML via a site variable, related to lack of escaping of the variable table. | https://antares.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the variable editor in the Devel module 5.x before 5.x-1.2 and 6.x before 6.x-1.18, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a variable name. | https://antares.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://antares.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://antares.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://antares.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://antares.tn/ | — |  |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://antares.tn/ | <script src="https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js"></script> | 10017 |  |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://antares.tn/ | — | 10035-1 |  |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Performance logging module in the Devel module 5.x before 5.x-1.3 and 6.x before 6.x-1.21 for Drupal allows remote authenticated users, with add url aliases and report access permissions, to inject arbitrary web script or HTML via crafted node paths in a URL. | https://antares.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://antares.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | aaaa-fingerprint | antares.tn | 2606:4700:3037::6815:2d1b, 2606:4700:3031::ac43:d014 |  |  |
| P5 | information | info | — | — | caa-fingerprint | antares.tn | — |  |  |
| P5 | information | info | — | — | deprecated-tls:tls_1.0 | antares.tn:443 | tls10 |  |  |
| P5 | information | info | — | — | deprecated-tls:tls_1.1 | antares.tn:443 | tls11 |  |  |
| P5 | information | info | — | — | dkim-record-detect | s1._domainkey.antares.tn | "v=DKIM1;t=s;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kDmU1YoAmYLEc3kjBGVjJIn7T6gZrbjcYWMg2SVXmAAlbuowpNXXKPEqD20F1ONleJgpioVa6e0cgEFHi27OliB+3pQjqHC2NAk2TveV1V0VmvWjGcZQVnV0buRd6F+XGlFlkFgUVNXVbDjT6KxeiPq1KzV5M+h3XSX0Mo9UnwIDAQAB"", "v=DKIM1;t=s;p=MIGfMA0GCS… |  |  |
| P5 | information | info | — | — | dmarc-detect | _dmarc.antares.tn | ""v=DMARC1;p=reject;rua=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@rua.easydmarc.com;ruf=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@ruf.easydmarc.com;aspf=s;adkim=s;fo=1;"" |  |  |
| P5 | information | info | — | — | dns-waf-detect:cloudflare | antares.tn | — |  |  |
| P5 | information | info | — | — | drupal-detect | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | drupal-login | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:permissions-policy | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:strict-transport-security | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://antares.tn/ | — |  |  |
| P5 | information | info | — | — | missing-sri | https://antares.tn/ | https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js, https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js |  |  |
| P5 | information | info | — | — | mx-fingerprint | antares.tn | 10 alt3.aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 1 aspmx.l.google.com. |  |  |
| P5 | information | info | — | — | mx-service-detector:Google Apps | antares.tn | — |  |  |
| P5 | information | info | — | — | nameserver-fingerprint | antares.tn | sri.ns.cloudflare.com., brianna.ns.cloudflare.com. |  |  |
| P5 | information | info | — | — | spf-record-detect | antares.tn | "v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"" |  |  |
| P5 | information | info | — | — | ssl-dns-names | antares.tn:443 | antares.tn, *.antares.tn |  |  |
| P5 | information | info | — | — | ssl-issuer | antares.tn:443 | Google Trust Services |  |  |
| P5 | information | info | — | — | tls-version | antares.tn:443 | tls10, tls11, tls12, tls13 |  |  |
| P5 | information | info | — | — | txt-fingerprint | antares.tn | ""v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"",""MS=30DD2F2CD0F16D7EA3365B56D58C6E468916806D"",""ahrefs-site-verification_f15e967d15c60d7aaf91839236b91319da7e012e9f5d4a2eaa0080e4786b01cf"",""google-site-verification=BLOCvNHiYzK-BZA7Ft6cO6X36CwzP… |  |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.0 | antares.tn:443 | [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.1 | antares.tn:443 | [tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |  |
| P5 | information | info | — | — | weak-csp-detect:unsafe-script-src | https://antares.tn/ | default-src 'self' https://kick.antares.tn https://kick.antares.tn https://www.w3.org https://www.youtube.com http://www.w3.org https://www.google-analytics.com https://stats.g.doubleclick.net https://www.googletagmanager.com https://analytics.google.com https… |  |  |
| P5 | information | info | — | — | wildcard-tls | antares.tn:443 | CN: antares.tn, SAN: [antares.tn *.antares.tn] |  |  |
| P5 | information | info | — | — | xss-deprecated-header | https://antares.tn/ | 1; mode=block |  |  |
