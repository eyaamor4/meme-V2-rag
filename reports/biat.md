**A - Résumé Exécutif**

Au total, 36 vulnérabilités ont été identifiées, dont 20 de niveau "medium", 13 de niveau "low" et 3 de niveau "high". Il n'y a pas de vulnérabilité de niveau "critical".

**B - Vulnérabilités Prioritaires**

1. **SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal**
	* Description : SQL injection vulnerability in the Views module 6.x before 6.x-2.2 for Drupal allows remote attackers to execute arbitrary SQL commands via unspecified vectors related to "an exposed filter on CCK text fields."
	* Impact potentiel : Exécution de commandes SQL arbitraires
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views à 6.x-2.2 ou supérieur
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 6.x-2.2
	* Score CVSS : 7.5

2. **SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal**
	* Description : SQL injection vulnerability in the Views module before 6.x-2.13 for Drupal allows remote attackers to execute arbitrary SQL commands via vectors related to "filters/arguments on certain types of views with specific configurations of arguments."
	* Impact potentiel : Exécution de commandes SQL arbitraires
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views à 6.x-2.13 ou supérieur
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 6.x-2.13
	* Score CVSS : 7.5

3. **Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views**
	* Description : Insertion of Sensitive Information Into Sent Data vulnerability in Drupal REST Views allows Forceful Browsing.
	* Impact potentiel : Accès non autorisé à des données sensibles
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module REST Views à 3.0.1 ou supérieur
	* Vérification : Vérifier que la version du module REST Views est supérieure ou égale à 3.0.1
	* Score CVSS : 7.5

4. **CSP: Failure to Define Directive with No Fallback**
	* Description : Le Content Security Policy (CSP) ne définit pas une directive avec un fallback.
	* Impact potentiel : Injection de code malveillant
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback
	* Vérification : Vérifier que les directives CSP ne contiennent pas de jokers '*' ni de schémas trop permissifs
	* Score CVSS : Non fourni

5. **CSP: Wildcard Directive**
	* Description : Le Content Security Policy (CSP) utilise des jokers '*' pour autoriser les ressources provenant de n'importe quel domaine.
	* Impact potentiel : Injection de code malveillant
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance
	* Vérification : Vérifier que les directives CSP ne contiennent plus de jokers '*' ni de schémas trop permissifs
	* Score CVSS : Non fourni

6. **CSP: script-src unsafe-inline**
	* Description : Le Content Security Policy (CSP) autorise les scripts inline avec 'unsafe-inline'.
	* Impact potentiel : Injection de code malveillant
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes
	* Vérification : Vérifier que script-src ne contient plus 'unsafe-inline' et que les scripts inline nécessaires utilisent un nonce ou un hash
	* Score CVSS : Non fourni

7. **CSP: style-src unsafe-inline**
	* Description : Le Content Security Policy (CSP) autorise les styles inline avec 'unsafe-inline'.
	* Impact potentiel : Injection de code malveillant
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de style-src et utiliser des nonces ou des hashes pour autoriser uniquement les styles inline légitimes
	* Vérification : Vérifier que style-src ne contient plus 'unsafe-inline' et que les styles inline nécessaires utilisent un nonce ou un hash
	* Score CVSS : Non fourni

8. **The Webform module 5.x before 5.x-2.8 and 6.x before 6.x-2.8, a module for Drupal, does not prevent caching of a page that contains token placeholders for a default value**
	* Description : Le module Webform ne prévient pas la mise en cache de pages contenant des placeholders de valeurs par défaut.
	* Impact potentiel : Lecture de variables de session
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module Webform à 5.x-2.8 ou supérieur
	* Vérification : Vérifier que la version du module Webform est supérieure ou égale à 5.x-2.8
	* Score CVSS : 5.0

9. **Multiple cross-site request forgery (CSRF) vulnerabilities in the Views UI implementation in the Views module 5.x before 5.x-1.8 and 6.x before 6.x-2.11 for Drupal**
	* Description : Les vulnérabilités CSRF multiples dans l'implémentation de l'interface utilisateur de Views dans le module Views 5.x avant 5.x-1.8 et 6.x avant 6.x-2.11 pour Drupal permettent aux attaquants de se faire passer pour les administrateurs pour des requêtes qui (1) activent toutes les vues ou (2) désactivent toutes les vues.
	* Impact potentiel : Authentification des administrateurs
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 5.x-1.8 ou supérieur
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 5.x-1.8
	* Score CVSS : 6.8

10. **The Organic Groups (OG) module 6.x-2.x before 6.x-2.3 for Drupal does not properly restrict access**
	* Description : Le module Organic Groups (OG) 6.x-2.x avant 6.x-2.3 pour Drupal ne restreint pas correctement l'accès.
	* Impact potentiel : Accès non autorisé à des groupes privés
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module Organic Groups à 6.x-2.3 ou supérieur
	* Vérification : Vérifier que la version du module Organic Groups est supérieure ou égale à 6.x-2.3
	* Score CVSS : 5.0

11. **The _views_fetch_data method in includes/cache.inc in the Views module 7.x-3.5 through 7.x-3.10 for Drupal does not rebuild the full cache if the static cache is not empty**
	* Description : La méthode _views_fetch_data dans includes/cache.inc dans le module Views 7.x-3.5 à 7.x-3.10 pour Drupal ne reconstruit pas la mise en cache complète si la mise en cache statique n'est pas vide.
	* Impact potentiel : Bypass des filtres intentionnels
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 7.x-3.10 ou supérieur
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 7.x-3.10
	* Score CVSS : 5.0

12. **The System module in Drupal 6.x before 6.38 and 7.x before 7.43 might allow remote attackers to hijack the authentication of site administrators for requests that download and run files with arbitrary JSON-encoded content**
	* Description : Le module System dans Drupal 6.x avant 6.38 et 7.x avant 7.43 pourrait permettre aux attaquants de se faire passer pour les administrateurs pour des requêtes qui téléchargent et exécutent des fichiers avec du contenu JSON codé arbitrairement.
	* Impact potentiel : Authentification des administrateurs
	* Catégorie OWASP : Non fourni
	* Recommandation technique : Mettre à jour la version du module System à 6.38 ou supérieur
	* Vérification : Vérifier que la version du module System est supérieure ou égale à 6.38
	* Score CVSS : 6.4

13. **The Views module 7.x-3.x before 7.x-3.14 in Drupal 7.x and the Views module in Drupal 8.x before 8.1.3 might allow remote authenticated users to bypass intended access restrictions and obtain sensitive Statistics information**
	* Description : Le module Views 7.x-3.x avant 7.x-3.14 dans Drupal 7.x et le module Views dans Drupal 8.x avant 8.1.3 pourrait permettre aux utilisateurs authentifiés à distance de contourner les restrictions d'accès intentionnelles et d'obtenir des informations sensibles sur les statistiques.
	* Impact potentiel : Accès non autorisé à des informations sensibles
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Mettre à jour la version du module Views à 7.x-3.14 ou supérieur
	* Vérification : Vérifier que la version du module Views est supérieure ou égale à 7.x-3.14
	* Score CVSS : 5.3

14. **Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Drupal Views SVG Animation**
	* Description : La vulnérabilité d'input non neutralisé pendant la génération de page ('Cross-site Scripting') dans Drupal Views SVG Animation permet l'injection de code malveillant.
	* Impact potentiel : Injection de code malveillant
	* Catégorie OWASP : A03:2021 - Injection
	* Recommandation technique : Mettre à jour la version du module Views SVG Animation à 1.0.1 ou supérieur
	* Vérification : Vérifier que la version du module Views SVG Animation est supérieure ou égale à 1.0.1
	* Score CVSS : 5.4

15. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut d'intégrité des sous-ressources est manquant.
	* Impact potentiel : Injection de code malveillant
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter l'attribut d'intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN
	* Vérification : Vérifier que chaque ressource externe concernée contient un attribut d'intégrité valide correspondant au contenu réellement servi
	* Score CVSS : Non fourni

**C - Plan de remédiation**

1. Mettre à jour la version du module Views à 6.x-2.2 ou supérieur pour résoudre la vulnérabilité SQL injection.
2. Mettre à jour la version du module Views à 6.x-2.13 ou supérieur pour résoudre la vulnérabilité SQL injection.
3. Mettre à jour la version du module REST Views à 3.0.1 ou supérieur pour résoudre la vulnérabilité d'insertion de données sensibles.
4. Définir explicitement les directives CSP sans fallback pour résoudre la vulnérabilité de configuration de sécurité.
5. Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour résoudre la vulnérabilité de configuration de sécurité.
6. Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes pour résoudre la vulnérabilité de configuration de sécurité.
7. Supprimer 'unsafe-inline' de style-src et utiliser des nonces ou des hashes pour autoriser uniquement les styles inline légitimes pour résoudre la vulnérabilité de configuration de sécurité.
8. Mettre à jour la version du module Webform à 5.x-2.8 ou supérieur pour résoudre la vulnérabilité de lecture de variables de session.
9. Mettre à jour la version du module Views à 5.x-1.8 ou supérieur pour résoudre la vulnérabilité CSRF.
10. Mettre à jour la version du module System à 6.38 ou supérieur pour résoudre la vulnérabilité d'authentification des administrateurs.
11. Mettre à jour la version du module Views à 7.x-3.10 ou supérieur pour résoudre la vulnérabilité de bypass des filtres intentionnels.
12. Mettre à jour la version du module Views à 7.x-3.14 ou supérieur pour résoudre la vulnérabilité d'accès non autorisé à des informations sensibles.
13. Mettre à jour la version du module Views SVG Animation à 1.0.1 ou supérieur pour résoudre la vulnérabilité d'injection de code malveillant.
14. Ajouter l'attribut d'intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN pour résoudre la vulnérabilité d'injection de code malveillant.

**D - Conclusion**

Il existe 15 vulnérabilités prioritaires qui nécessitent des remèdes. Il est essentiel de mettre à jour les versions des modules pour résoudre ces vulnérabilités. Il est également important de définir explicitement les directives CSP sans fallback et de remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance. Enfin, il est crucial d'ajouter l'attribut d'intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

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
