A - Résumé Exécutif

28 vulnérabilités ont été identifiées au total, dont 8 sont prioritaires. La surface d'attaque XSS est complète en raison de la présence simultanée de plusieurs findings CSP (unsafe-inline + SRI manquant + wildcard), ce qui augmente le risque combiné.

B - Vulnérabilités Prioritaires

1. **CSP: Failure to Define Directive with No Fallback**
* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive avec un fallback, permettant ainsi à n'importe quel code d'être exécuté.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

2. **CSP: Wildcard Directive**
* Description : La politique de sécurité du contenu (CSP) utilise un joker qui autorise toutes les sources, permettant ainsi à n'importe quel code d'être exécuté.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer * par une liste précise d’hôtes de confiance.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

3. **CSP: script-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut être utilisé pour injecter du code malveillant.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

4. **CSP: style-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut être utilisé pour injecter du code malveillant.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

5. **CVE-2023-5561**
* Score CVSS : 5.3
* Description : WordPress ne restreint pas correctement les champs de recherche utilisateurs via l'API REST, permettant ainsi à des attaquants non authentifiés de discerner les adresses e-mail des utilisateurs qui ont publié des articles publics sur un site affecté.
* Référence : https://lists.debian.org/debian-lts-announce/2023/11/msg00014.html
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour WordPress vers la version corrigée mentionnée.
* Vérification : Tester les vues avec plusieurs rôles.

6. **CVE-2024-2473**
* Score CVSS : 5.3
* Description : Le plugin WPS Hide Login pour WordPress est vulnérable à une fuite de page de connexion en toutes versions jusqu'à et y compris 1.9.15.2, ce qui permet aux attaquants d'identifier facilement toute page de connexion qui aurait été cachée par le plugin.
* Référence : https://plugins.trac.wordpress.org/changeset/3099109/wps-hide-login
* Catégorie OWASP : A07:2021 - Identification and Authentication Failures
* Recommandation technique : Mettre à jour le plugin WPS Hide Login vers la version corrigée mentionnée.
* Vérification : Tester les vues avec plusieurs rôles.

7. **Missing Anti-clickjacking Header**
* Description : La réponse ne protège pas contre les attaques de "ClickJacking". Elle devrait inclure soit une politique de sécurité du contenu (CSP) avec la directive 'frame-ancestors' ou X-Frame-Options.
* Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
* Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options

8. **Sub Resource Integrity Attribute Missing**
* Description : L'attribut d'intégrité est manquant sur une balise script ou link servie par un serveur externe. Cet attribut empêche les attaquants qui ont accès à ce serveur de injecter du contenu malveillant.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
* Vérification : Inspecter le code source HTML.

C - Plan de remédiation

- Mettre à jour WordPress vers la version corrigée mentionnée pour CVE-2023-5561.
- Mettre à jour le plugin WPS Hide Login vers la version corrigée mentionnée pour CVE-2024-2473.
- Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP pour les findings CSP.
- Remplacer * par une liste précise d’hôtes de confiance pour le finding CSP: Wildcard Directive.
- Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés pour le finding CSP: script-src unsafe-inline.
- Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées pour le finding CSP: style-src unsafe-inline.

D - Conclusion

Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique consiste à mettre à jour WordPress vers la version corrigée mentionnée pour CVE-2023-5561. Ce doit être fait dans les 30 jours.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 8 | 4 | 16 |

    **Total :** 28 | **Prioritaires :** 8
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://manysports.tn/ | upgrade-insecure-requests | 10055-13 |  |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://manysports.tn/ | upgrade-insecure-requests | 10055-4 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://manysports.tn/ | upgrade-insecure-requests | 10055-5 |  |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://manysports.tn/ | upgrade-insecure-requests | 10055-6 |  |
| P3 | vulnerability | medium | — | — | CVE-2023-5561 | https://manysports.tn/?rest_route=/wp/v2/users&search=@ | route="?rest_route=/wp/v2/users&" |  |  |
| P3 | vulnerability | medium | — | — | CVE-2024-2473 | https://manysports.tn/wp-admin/?action=postpass | — |  |  |
| P3 | vulnerability | medium | Medium | Medium | Missing Anti-clickjacking Header | https://manysports.tn/ | x-frame-options | 10020-1 |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://manysports.tn/ | <link rel="preload" as="style" href="https://fonts.googleapis.com/css?family=Mulish:200,300,400,500,600,700,800,900,200italic,300italic,400italic,500italic,600italic,700italic,800italic,900italic&#038;display=swap&#038;ver=1752201721" /> | 90003 |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://manysports.tn/ | <script type="text/javascript" src="https://stats.wp.com/s-202611.js" id="woocommerce-analytics-js" defer="defer" data-wp-strategy="defer"></script> | 10017 |  |
| P4 | vulnerability | low | Low | Medium | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | https://manysports.tn/ | x-powered-by: PHP/8.2.30 | 10037 |  |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://manysports.tn/ | — | 10035-1 |  |
| P4 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | https://manysports.tn/ | x-content-type-options | 10021 |  |
| P5 | information | info | — | — | Plugin détecté : automattic-for-agencies-client | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : blaze-ads | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : contact-form-7 | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : elementor | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : filebird | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : font-awesome | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : google-site-kit | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : hostinger | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : jetpack | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : jetpack-search | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : litespeed-cache | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : mainichi-shopify-products-connect | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : simple-history | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : woocommerce | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : wordpress-seo | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : wp-store-lite | https://manysports.tn/ | — |  |  |
