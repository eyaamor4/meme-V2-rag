A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 11 vulnérabilités ont été retenues dans ce rapport, dont 9 sont prioritaires.
Niveau de risque global : ÉLEVÉ. Niveau source : high. Cible : https://www.biat.com.tn/ (drupal 10). Scan du : 2026-03-10 12:40:23.371000.
Validation manuelle recommandée
En outre, 3 vulnérabilité(s) potentielle(s) n'ont pu être confirmées faute de version vérifiable. Voir Annexe A.
La surface d'attaque XSS est élargie en raison de la combinaison de plusieurs vulnérabilités CSP, notamment l'absence de directive de sécurité, l'utilisation de jokers et l'exécution de scripts et de styles inline.

B - Vulnérabilités Prioritaires
1. CSP: Failure to Define Directive with No Fallback
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
- Description : La politique de sécurité du contenu (CSP) ne définit pas une directive essentielle, ce qui peut permettre l'exécution de code malveillant.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Identifier les directives CSP manquantes et les ajouter avec des valeurs restrictives.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, puis vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

2. CSP: Wildcard Directive
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
- Description : La politique de sécurité du contenu (CSP) utilise des jokers qui autorisent des sources trop larges, ce qui peut permettre l'exécution de code malveillant.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Remplacer les jokers par des listes précises d'hôtes de confiance.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, puis comparer la CSP déployée avec l'inventaire réel des ressources chargées.

3. CSP: script-src unsafe-inline
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
- Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre l'exécution de code malveillant.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Migrer les scripts inline vers des fichiers JS statiques versionnés.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, puis vérifier que script-src ne contient plus unsafe-inline.

4. CSP: style-src unsafe-inline
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
- Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut permettre l'exécution de code malveillant.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, puis vérifier que style-src ne contient plus unsafe-inline.

5. Sub Resource Integrity Attribute Missing
- Description : L'attribut d'intégrité des ressources est manquant, ce qui peut permettre l'injection de code malveillant.
- Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Recommandation : Ajouter l'attribut d'intégrité aux ressources chargées depuis des domaines externes.
- Vérification : Inspecter le code source HTML, puis vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

6. CVE-2008-6020
* Score CVSS : 7.5
- Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
- Catégorie OWASP : A03:2021 - Injection
- Recommandation : Version non confirmée — validation manuelle requise avant exploitation.
- Vérification : Rechercher les usages de concaténation SQL dans le code, puis tester les paramètres avec des payloads d'injection.

7. CVE-2011-4113
* Score CVSS : 7.5
- Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
- Catégorie OWASP : A03:2021 - Injection
- Recommandation : Version non confirmée — validation manuelle requise avant exploitation.
- Vérification : Rechercher les usages de concaténation SQL dans le code, puis tester les paramètres avec des payloads d'injection.

8. CVE-2024-13254
* Score CVSS : 7.5
- Description : Vulnérabilité d'exposition d'informations sensibles dans le module REST Views pour Drupal.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
- Catégorie OWASP : A01:2021 - Broken Access Control
- Recommandation : Inventorier les vues REST exposées publiquement, puis limiter les permissions sur les displays REST de Views.
- Vérification : Tester l'accès anonyme et authentifié aux endpoints REST, puis vérifier les champs renvoyés.

9. CVE-2012-10004
* Score CVSS : 3.5
- Description : Vulnérabilité de cross-site scripting dans le module Basic Cart pour Drupal.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2012-10004
- Catégorie OWASP : A03:2021 - Injection
- Recommandation : Version confirmée comme vulnérable — correction requise sous 60 jours.
- Vérification : Injecter un payload XSS adapté, puis vérifier que le code est exécuté.

C - Plan de remédiation
1. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP manquantes et les ajouter avec des valeurs restrictives — Délai : 7 jours
2. CSP: Wildcard Directive : Remplacer les jokers par des listes précises d'hôtes de confiance — Délai : 7 jours
3. CSP: script-src unsafe-inline : Migrer les scripts inline vers des fichiers JS statiques versionnés — Délai : 7 jours
4. CSP: style-src unsafe-inline : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées — Délai : 7 jours
5. Sub Resource Integrity Attribute Missing : Ajouter l'attribut d'intégrité aux ressources chargées depuis des domaines externes — Délai : 7 jours
6. CVE-2008-6020 : Valider manuellement la vulnérabilité avant exploitation — Délai : 30 jours
7. CVE-2011-4113 : Valider manuellement la vulnérabilité avant exploitation — Délai : 30 jours
8. CVE-2024-13254 : Inventorier les vues REST exposées publiquement et limiter les permissions — Délai : 7 jours
9. CVE-2012-10004 : Mettre à jour ou corriger le composant contrib selon le correctif fournisseur — Délai : 60 jours

D - Conclusion
Le niveau de risque global est ÉLEVÉ.
Le niveau brut source est high.
L'action prioritaire la plus critique est de remédier à la vulnérabilité CSP: Failure to Define Directive with No Fallback, qui doit être corrigée sous 7 jours.
Il est essentiel de traiter ces vulnérabilités pour protéger les données sensibles et prévenir les attaques malveillantes.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise les vulnérabilités retenues dans le rapport principal après déduplication.
    > Les CVEs à version non confirmée sont séparées en Annexe A. Parmi elles, 3 vulnérabilité(s) HIGH/CRITICAL
    > figurent en section B à titre d’alerte, avec validation manuelle recommandée.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 3 | 5 | 3 | 10 |

     *En sus : 0 critique(s), 3 élevé(s) et 14 moyen(s) potentiels détectés (version non confirmée — voir Annexe A)*

    **Niveau de risque global : ÉLEVÉ**

    **Éléments techniques listés en annexe :** 42 | **Vulnérabilités retenues dans le rapport :** 11 | **Prioritaires (section B) :** 9**

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication.
    > Le JSON source peut afficher davantage de CVEs brutes, y compris celles non confirmées en version.*
    

## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the webform module in Drupal 4.6 before July 8, 2006 and 4.7 before July 8, 2006 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.7 and 6.x before 6.x-2.7, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a submission. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value, which allows remote attackers to read session variables via unspecified vectors. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.19 for Drupal allows remote authenticated users with the "edit own webform content" or "edit all webform content" permissions to inject arbitrary web script or HTML via a component label. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content, aka a "reflected file download vulnerability." | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | medium | — | — | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, allows remote authenticated users, with webform creation privileges, to inject arbitrary web script or HTML via a field label. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in components/select.inc in the Webform module 6.x-3.x before 6.x-3.17 and 7.x-3.x before 7.x-3.17 for Drupal, when the "Select (or other)" module is enabled, allow remote authenticated users with the create webform content permission to inject arbitrary web script or HTML via vectors related to (1) checkboxes or (2) radios. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.20, 7.x-3.x before 7.x-3.20, and 7.x-4.x before 7.x-4.0-beta2 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a field label title, when two fields have the same form_key. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the view-based webform results table in the Webform module 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a webform. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.22, 7.x-3.x before 7.x-3.22, and 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a node title, which is used as the default title of a webform block. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.23, 7.x-3.x before 7.x-3.23, and 7.x-4.x before 7.x-4.5 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a component name in the recipient (To) address of an email. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.tn; | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.tn; | 10055-4 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.tn; | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.tn; | 10055-6 | — |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script>, <script src="https://use.fontawesome.com/releases/v5.5.0/js/v4-shims.js" defer crossorigin="anonymous"></script> | 90003 | — |
| P4 | vulnerability | high | — | — | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | high | — | — | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | high | — | — | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://www.biat.com.tn/ | — |  | Vulnérabilité potentielle non confirmée — version exacte non vérifiée |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script>, <script src="https://use.fontawesome.com/releases/v5.5.0/js/v4-shims.js" defer crossorigin="anonymous"></script>, <script src="//cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js"></script>, <script src="//stackpath.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script> | 10017 | — |
| P4 | vulnerability | low | Low | High | Server Leaks Version Information via "Server" HTTP Response Header Field | https://www.biat.com.tn/ | Apache/2.4.62 (Debian) | 10036-2 | — |
| P5 | vulnerability | low | — | — | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://www.biat.com.tn/ | — |  | Correspondance module/version détectée — validation manuelle recommandée |
| P5 | information | info | — | — | Technologie détectée : Apache HTTP Server | https://www.biat.com.tn/ | 2.4.62 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Bootstrap | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Debian | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Drupal | https://www.biat.com.tn/ | 10 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HSTS | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : OWL Carousel | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : PHP | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Slick | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : jQuery | https://www.biat.com.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
