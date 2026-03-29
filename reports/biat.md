A - Résumé Exécutif

32 vulnérabilités ont été identifiées au total, dont 15 sont prioritaires.

B - Vulnérabilités Prioritaires

**1. SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal**
* Description : La vulnérabilité de SQL injection dans le module Views permet aux attaquants de exécuter des commandes SQL arbitraires via des vecteurs non spécifiés liés à « un filtre exposé sur les champs texte CCK ».
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
* Score CVSS : 7.5
* Catégorie OWASP : A03:2021 - Injection
* Recommandation technique : Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
* Vérification : Rechercher les usages de concaténation SQL dans le code.

**2. SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal**
* Description : La vulnérabilité de SQL injection dans le module Views permet aux attaquants de exécuter des commandes SQL arbitraires via des vecteurs liés à « les filtres/arguments sur certains types de vues avec des configurations spécifiques d’arguments ».
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
* Score CVSS : 7.5
* Catégorie OWASP : A03:2021 - Injection
* Recommandation technique : Identifier les requêtes construites dynamiquement avec concaténation, utiliser des requêtes préparées ou paramétrées via le driver natif ou l’ORM.
* Vérification : Rechercher les usages de concaténation SQL dans le code.

**3. Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views**
* Description : La vulnérabilité d’insertion de données sensibles dans les données transmises permet aux attaquants de lire des variables de session via des vecteurs non spécifiés.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
* Score CVSS : 7.5
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Limiter les permissions sur les displays REST de Views, retirer les champs sensibles.
* Vérification : Tester l’accès anonyme et authentifié aux endpoints REST.

**4. CSP: Failure to Define Directive with No Fallback**
* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive avec un fallback, ce qui permet aux attaquants d’injecter des contenus malveillants.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
* Vérification : Exécuter curl -I sur plusieurs pages HTML.

**5. CSP: Wildcard Directive**
* Description : La politique de sécurité du contenu (CSP) utilise des directives génériques, ce qui permet aux attaquants d’injecter des contenus malveillants.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer les directives génériques par des listes précises d’hôtes de confiance.
* Vérification : Comparer la CSP déployée avec l’inventaire réel des ressources chargées.

**6. CSP: script-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) utilise l’attribut `unsafe-inline`, ce qui permet aux attaquants d’injecter des contenus malveillants.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les scripts inline présents dans les templates HTML, migrer vers des fichiers JS statiques versionnés.
* Vérification : Contrôler que script-src ne contient plus `unsafe-inline`.

**7. CSP: style-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) utilise l’attribut `unsafe-inline`, ce qui permet aux attaquants d’injecter des contenus malveillants.
* Référence : https://www.w3.org/TR/CSP/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end, déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Contrôler le rendu visuel des pages après externalisation des styles.

**8. The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal**
* Description : Le module Webform ne prévient pas la mise en cache de pages contenant des placeholders pour une valeur par défaut, ce qui permet aux attaquants de lire des variables de session.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2009-4533
* Score CVSS : 5.0
* Catégorie OWASP : A02:2021 - Cryptographic Failures
* Recommandation technique : Mettre à jour Webform vers la version corrigée, désactiver ou adapter le cache des pages contenant des placeholders dépendant de la session.
* Vérification : Contrôler la version déployée du module.

**9. Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation**
* Description : Les vulnérabilités CSRF dans l’implémentation de l’interface utilisateur de Views permettent aux attaquants d’hijacker l’autorisation des administrateurs pour les requêtes qui (1) activent toutes les vues ou (2) désactivent toutes les vues.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2010-4519
* Score CVSS : 6.8
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Générer un jeton CSRF unique par session ou requête, vérifier ce jeton côté serveur sur tous les endpoints d’écriture ou d’action.
* Vérification : Tester les formulaires et endpoints POST/PUT/PATCH/DELETE.

**10. The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal**
* Description : Le module OG ne restreint pas correctement l’accès, ce qui permet aux attaquants d’obtenir des informations sensibles telles que les titres de groupes privés via une requête à travers le module Views.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2012-2081
* Score CVSS : 5.0
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour OG vers une version corrigée, revoir les permissions par rôle et les displays Views associés.
* Vérification : Tester les accès avec plusieurs rôles.

**11. The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal**
* Description : La méthode `_views_fetch_data` dans `includes/cache.inc` du module Views ne rebâtit pas la cache complète si la cache statique n’est pas vide, ce qui permet aux attaquants de contourner les filtres intentionnels et d’obtenir accès à des contenus cachés.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2015-5490
* Score CVSS : 5.0
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour le module Views vers une version corrigée.
* Vérification : Contrôler la version déployée du module.

**12. The System module in Drupal 6.x before 6.38 and 7.x before 7.43**
* Description : Le module System permet aux attaquants d’hijacker l’autorisation des administrateurs pour les requêtes qui téléchargent et exécutent des fichiers avec contenu JSON codé arbitrairement.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-3168
* Score CVSS : 6.4
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Neutraliser les entrées utilisateur réinjectées dans les noms ou contenus de fichiers.
* Vérification : Tester les paramètres d’export avec contenu injecté.

**13. The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3**
* Description : Le module Views permet aux attaquants authentifiés de contourner les restrictions d’accès intentionnelles et d’obtenir des informations sensibles sur les statistiques via des vecteurs non spécifiés.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-6212
* Score CVSS : 5.3
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour le module Views vers une version corrigée.
* Vérification : Contrôler la version déployée du module.

**14. Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation**
* Description : La vulnérabilité d’impréhension de l’entrée pendant la génération de page permet aux attaquants d’exécuter du code JavaScript arbitraire via des vecteurs non spécifiés.
* Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13287
* Score CVSS : 5.4
* Catégorie OWASP : A03:2021 - Injection
* Recommandation technique : Mettre à jour le module Views, identifier les champs de configuration ou paramètres exposés réinjectés dans la sortie HTML.
* Vérification : Contrôler la version corrigée installée.

**15. Sub Resource Integrity Attribute Missing**
* Description : L’attribut d’intégrité des sous-ressources est manquant sur une balise script ou link servie par un serveur externe, ce qui permet aux attaquants de injecter du contenu malveillant.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Identifier les scripts et feuilles CSS chargés depuis des domaines externes, ajouter l’attribut integrity.
* Vérification : Inspecter le code source HTML.

C - Plan de remédiation

1. Mettre à jour Drupal vers la version corrigée mentionnée dans chaque CVE.
2. Mettre à jour les modules et plugins vulnérables vers les versions corrigées.
3. Configurer correctement la politique de sécurité du contenu (CSP) pour éviter les attaques XSS.
4. Vérifier régulièrement les mises à jour des composants pour s’assurer qu’ils sont à jour.

D - Conclusion

Le niveau de risque global est ÉLEVÉ. Une action immédiate est requise sous 24 heures pour mettre en place un plan de remédiation complet et mettre à jour tous les composants vulnérables.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 3 | 19 | 10 | 0 |

    **Total :** 32 | **Prioritaires :** 15
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P2 | vulnerability | high | — | — | SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields." | https://www.biat.com.tn/ | — |  |  |
| P2 | vulnerability | high | — | — | SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments." | https://www.biat.com.tn/ | — |  |  |
| P2 | vulnerability | high | — | — | Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.This issue affects REST Views: from 0.0.0 before 3.0.1. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-13 |  |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-4 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-5 |  |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://www.biat.com.tn/ | default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; script-src-elem 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; style-src-attr 'self' 'unsafe-inline' 'unsafe-hashes'; img-src 'self' https: http://www.biat.com.… | 10055-6 |  |
| P3 | vulnerability | medium | — | — | The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value, which allows remote attackers to read session variables via unspecified vectors. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal allow remote attackers to hijack the authentication of administrators for requests that (1) enable all Views or (2) disable all Views. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access, which allows remote attackers to obtain sensitive information such as private group titles via a request through the Views module. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty, which allows remote attackers to bypass intended filters and obtain access to hidden content via unspecified vectors. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content, aka a "reflected file download vulnerability." | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information via unspecified vectors. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | — | — | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation allows Cross-Site Scripting (XSS).This issue affects Views SVG Animation: from 0.0.0 before 1.0.1. | https://www.biat.com.tn/ | — |  |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script> | 90003 |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the webform module in Drupal 4.6 before July 8, 2006 and 4.7 before July 8, 2006 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.7 and 6.x before 6.x-2.7, a module for Drupal, allows remote attackers to inject arbitrary web script or HTML via a submission. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 6.x before 6.x-2.11 for Drupal allow remote attackers to inject arbitrary web script or HTML via (1) a URL or (2) an aggregator feed title. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Views module 6.x before 6.x-2.12 for Drupal allows remote attackers to inject arbitrary web script or HTML via a page path. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.19 for Drupal allows remote authenticated users with the "edit own webform content" or "edit all webform content" permissions to inject arbitrary web script or HTML via a component label. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | Open redirect vulnerability in the Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal, when the Views UI submodule is enabled, allows remote authenticated users to redirect users to arbitrary web sites and conduct phishing attacks via vectors related to the break lock page for edited views. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | medium | — | — | The Views module before 6.x-2.18, 6.x-3.x before 6.x-3.2, and 7.x-3.x before 7.x-3.10 for Drupal does not properly restrict access to the default views configurations, which allows remote authenticated users to obtain sensitive information via unspecified vectors. | https://www.biat.com.tn/ | — |  |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.biat.com.tn/ | <script src="https://use.fontawesome.com/releases/v5.5.0/js/all.js" defer crossorigin="anonymous"></script> | 10017 |  |
| P4 | vulnerability | low | Low | High | Server Leaks Version Information via "Server" HTTP Response Header Field | https://www.biat.com.tn/ | Apache/2.4.62 (Debian) | 10036-2 |  |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, allows remote authenticated users, with webform creation privileges, to inject arbitrary web script or HTML via a field label. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | A vulnerability was found in backdrop-contrib Basic Cart on Drupal. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The patch is identified as a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in components/select.inc in the Webform module 6.x-3.x before 6.x-3.17 and 7.x-3.x before 7.x-3.17 for Drupal, when the "Select (or other)" module is enabled, allow remote authenticated users with the create webform content permission to inject arbitrary web script or HTML via vectors related to (1) checkboxes or (2) radios. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Multiple cross-site scripting (XSS) vulnerabilities in the Views module 7.x-3.x before 7.x-3.6 for Drupal allow remote authenticated users with certain permissions to inject arbitrary web script or HTML via certain view configuration fields. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module 6.x-3.x before 6.x-3.20, 7.x-3.x before 7.x-3.20, and 7.x-4.x before 7.x-4.0-beta2 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a field label title, when two fields have the same form_key. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the view-based webform results table in the Webform module 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a webform. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.22, 7.x-3.x before 7.x-3.22, and 7.x-4.x before 7.x-4.4 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a node title, which is used as the default title of a webform block. | https://www.biat.com.tn/ | — |  |  |
| P5 | vulnerability | low | — | — | Cross-site scripting (XSS) vulnerability in the Webform module before 6.x-3.23, 7.x-3.x before 7.x-3.23, and 7.x-4.x before 7.x-4.5 for Drupal allows remote authenticated users with certain permissions to inject arbitrary web script or HTML via a component name in the recipient (To) address of an email. | https://www.biat.com.tn/ | — |  |  |
