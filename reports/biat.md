A - Résumé Exécutif

8 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires. Le niveau de risque global est ÉLEVÉ.

B - Vulnérabilités Prioritaires

1. **CSP: Failure to Define Directive with No Fallback**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive avec un fallback, ce qui permet à n'importe quel code d'être exécuté.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les directives CSP sans fallback qui sont ABSENTES de la politique actuelle et ajouter uniquement les directives manquantes avec des valeurs restrictives.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

2. **CSP: Wildcard Directive**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité du contenu (CSP) utilise un joker qui autorise toutes les sources.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer * par une liste précise d’hôtes de confiance et éviter les schémas génériques comme https:.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, comparer la CSP déployée avec l'inventaire réel des ressources chargées.

3. **CSP: script-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier tous les scripts inline présents dans les templates HTML et migrer les scripts inline vers des fichiers JS statiques versionnés.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline.

4. **CSP: style-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end et déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline.

5. **Sub Resource Integrity Attribute Missing**
* Description : L'attribut de sécurité du sous-ressource (SRI) est absent sur une balise script ou link.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
* Vérification : Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity=', vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

C - Plan de remédiation

1. Mettre à jour la politique de sécurité du contenu (CSP) pour inclure les directives manquantes avec des valeurs restrictives.
2. Remplacer le joker * par une liste précise d’hôtes de confiance dans la CSP.
3. Migrer les scripts inline vers des fichiers JS statiques versionnés.
4. Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
5. Ajouter l'attribut SRI sur les ressources stables et versionnées.

D - Conclusion

Le niveau de risque global est ÉLEVÉ. L'action prioritaire la plus critique est de mettre à jour la politique de sécurité du contenu (CSP) pour inclure les directives manquantes avec des valeurs restrictives. Ce doit être fait sous 24 heures.


## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 5 | 3 | 10 |

**Éléments techniques listés en annexe :** 42 | **Vulnérabilités retenues dans le rapport :** 8 | **Prioritaires (section B) :** 5


## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the webform module in Drupal 4.6 before July 8, 2006 and 4.7 before July 8, 2006 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | high | — | — | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.7 and 6.x before 6.x-2.7, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a submission. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value, which allows remote attackers to read session variables via unspecified vectors. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | high | — | — | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.19 for Drupal allows remote authenticated users with the "edit own webform content" or "edit all webform content" permissions to inject arbitrary web script or HTML via a component label. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content, aka a "reflected file download vulnerability." | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | high | — | — | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P4 | vulnerability | medium | — | — | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, allows remote authenticated users, with webform creation privileges, to inject arbitrary web script or HTML via a field label. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in components/select.inc in the Webform module 6.x-3.x before 6.x-3.17 and 7.x-3.x before 7.x-3.17 for Drupal, when the "Select (or other)" module is enabled, allow remote authenticated users with the create webform content permission to inject arbitrary web script or HTML via vectors related to (1) checkboxes or (2) radios. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.20, 7.x-3.x before 7.x-3.20, and 7.x-4.x before 7.x-4.0-beta2 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a field label title, when two fields have the same form_key. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the view-based webform results table in the Webform module 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a webform. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.22, 7.x-3.x before 7.x-3.22, and 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a node title, which is used as the default title of a webform block. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.23, 7.x-3.x before 7.x-3.23, and 7.x-4.x before 7.x-4.5 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a component name in the recipient (To) address of an email. | https://www.biat.com.tn/ | — |  | ⚠️ Faux positif probable — version non confirmée |

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-4 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-6 | — |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script>, <script src="https://use.fontawesome.com/releases/v5.5.0/js/v4-shims.js" defer crossorigin="anonymous"></script> | 90003 | — |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script>, <script src="https://use.fontawesome.com/releases/v5.5.0/js/v4-shims.js" defer crossorigin="anonymous"></script>, <script src="//cdnjs.cloudflare.com/a… | 10017 | — |
| P4 | vulnerability | low | Low | High | Server Leaks Version Information via "Server" HTTP Response Header Field | https://www.biat.com.tn/ | Apache/2.4.62 (Debian) | 10036-2 | — |
| P5 | vulnerability | low | — | — | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://www.biat.com.tn/ | — |  | ✅ Vulnérabilité confirmée sur votre installation |
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
