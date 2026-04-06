A - Résumé Exécutif
14 vulnérabilités ont été retenues dans ce rapport, dont 8 sont prioritaires.

B - Vulnérabilités Prioritaires
**CSP: Failure to Define Directive with No Fallback**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) ne définit pas une directive sans fallback, ce qui peut permettre l'exécution de code malveillant.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src, contrôler dans les outils navigateur que les violations CSP sont bien remontées.

**CSP: Wildcard Directive**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) utilise des directives avec des joker (*), ce qui peut permettre l'exécution de code malveillant à partir de sources non fiables.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer les joker (*) par des listes précises d'hôtes de confiance et éviter les schémas génériques.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, comparer la CSP déployée avec l'inventaire réel des ressources chargées, supprimer progressivement les sources non justifiées puis tester les parcours applicatifs.

**CSP: script-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre l'exécution de code malveillant.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline, contrôler dans le HTML que les scripts inline restants portent un nonce ou hash valide.

**CSP: style-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) permet l'injection de styles inline, ce qui peut permettre l'exécution de code malveillant.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline, contrôler le rendu visuel des pages après externalisation des styles.

**CVE-2023-5561**
* Score CVSS : 5.3
* Description : Une vulnérabilité dans WordPress permet à un attaquant non authentifié de découvrir les adresses e-mail des utilisateurs qui ont publié des articles publics sur le site.
* Référence : 
  - https://lists.debian.org/debian-lts-announce/2023/11/msg00014.html
  - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
  - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour WordPress à une version corrigée.
* Vérification : Tester les vues avec plusieurs rôles, manipuler les paramètres exposés et filtres, vérifier l’absence d’accès au contenu caché.

**CVE-2024-2473**
* Score CVSS : 5.3
* Description : Une vulnérabilité dans le plugin WPS Hide Login permet à un attaquant de découvrir la page de connexion cachée.
* Référence : 
  - https://plugins.trac.wordpress.org/changeset/3099109/wps-hide-login
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/fd21c7d3-a5f1-4c3a-b6ab-0a979f070a62?source=cve
* Catégorie OWASP : A07:2021 - Identification and Authentication Failures
* Recommandation technique : Mettre à jour le plugin WPS Hide Login à une version corrigée.
* Vérification : Tester les vues avec plusieurs rôles, manipuler les paramètres exposés et filtres, vérifier l’absence d’accès au contenu caché.

**Missing Anti-clickjacking Header**
* **Paramètre/Ressource affecté(e) :** `x-frame-options`
* Description : Le site ne protège pas contre les attaques de type ClickJacking.
* Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
* Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options, contrôler la présence de X-Frame-Options ou de frame-ancestors dans la CSP, tester l’intégration de la page dans une iframe depuis un domaine tiers.

**Sub Resource Integrity Attribute Missing**
* Description : L'attribut integrity est manquant sur un script ou une feuille de style chargés depuis un serveur externe.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter l'attribut integrity.
* Vérification : Inspecter le code source HTML, vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin, recalculer le hash en cas de mise à jour de la dépendance.

C - Plan de remédiation
1. **CSP: Failure to Define Directive with No Fallback** : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives.
2. **CSP: Wildcard Directive** : Remplacer les joker (*) par des listes précises d'hôtes de confiance.
3. **CSP: script-src unsafe-inline** : Migrer les scripts inline vers des fichiers JS statiques versionnés.
4. **CSP: style-src unsafe-inline** : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
5. **CVE-2023-5561** : Mettre à jour WordPress à une version corrigée.
6. **CVE-2024-2473** : Mettre à jour le plugin WPS Hide Login à une version corrigée.
7. **Missing Anti-clickjacking Header** : Définir X-Frame-Options à DENY ou SAMEORIGIN.
8. **Sub Resource Integrity Attribute Missing** : Ajouter l'attribut integrity sur les scripts et feuilles CSS chargés depuis des serveurs externes.

D - Conclusion
Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique est de mettre à jour WordPress à une version corrigée pour la vulnérabilité CVE-2023-5561. Il est recommandé de traiter ces vulnérabilités dans les 30 jours.


## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 9 | 5 | 28 |

**Éléments techniques listés en annexe :** 42 | **Vulnérabilités retenues dans le rapport :** 14 | **Prioritaires (section B) :** 8


## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://manysports.tn/ | upgrade-insecure-requests | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://manysports.tn/ | upgrade-insecure-requests | 10055-4 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://manysports.tn/ | upgrade-insecure-requests | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://manysports.tn/ | upgrade-insecure-requests | 10055-6 | — |
| P3 | vulnerability | medium | — | — | CVE-2023-5561 | https://manysports.tn/?rest_route=/wp/v2/users&search=@ | route="?rest_route=/wp/v2/users&" |  | — |
| P3 | vulnerability | medium | — | — | CVE-2024-2473 | https://manysports.tn/wp-admin/?action=postpass | — |  | — |
| P3 | vulnerability | medium | Medium | Medium | Missing Anti-clickjacking Header | https://manysports.tn/ | x-frame-options | 10020-1 | — |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://manysports.tn/ | <link rel="preload" as="style" href="https://fonts.googleapis.com/css?family=Mulish:200,300,400,500,600,700,800,900,200italic,300italic,400italic,500italic,600italic,700italic,800italic,900italic&#038;display=swap&#038;ver=1752201721" />, <link rel="stylesheet… | 90003 | — |
| P4 | vulnerability | medium | Medium | Low | Absence of Anti-CSRF Tokens | https://manysports.tn/ | <form name="ts-login-form" id="ts-login-form" action="https://manysports.tn/wp-login.php" method="post"> | 10202 | — |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://manysports.tn/ | <script type="text/javascript" src="https://stats.wp.com/s-202611.js" id="woocommerce-analytics-js" defer="defer" data-wp-strategy="defer"></script>, <script type="text/javascript" src="https://stats.wp.com/e-202611.js" id="jetpack-stats-js" defer="defer" data… | 10017 | — |
| P4 | vulnerability | low | Low | Medium | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | https://manysports.tn/ | x-powered-by: PHP/8.2.30 | 10037 | — |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://manysports.tn/ | — | 10035-1 | — |
| P4 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | https://manysports.tn/ | x-content-type-options | 10021 | — |
| P5 | information | info | — | — | Plugin détecté : automattic-for-agencies-client | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : blaze-ads | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : contact-form-7 | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : elementor | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : filebird | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : font-awesome | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : google-site-kit | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : hostinger | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : jetpack | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : jetpack-search | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : litespeed-cache | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : mainichi-shopify-products-connect | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : simple-history | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : woocommerce | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : wordpress-seo | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Plugin détecté : wp-store-lite | https://manysports.tn/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Technologie détectée : Elementor | https://manysports.tn/ | 3.35.5 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HTTP/3 | https://manysports.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Hostinger | https://manysports.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : LiteSpeed | https://manysports.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Litespeed Cache | https://manysports.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : MySQL | https://manysports.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : PHP | https://manysports.tn/ | Version non fournie, 8.2.30 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Redux Framework | https://manysports.tn/ | 4.5.10 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Site Kit | https://manysports.tn/ | 1.173.0 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Slider Revolution | https://manysports.tn/ | 6.7.29 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : WooCommerce | https://manysports.tn/ | 10.5.3 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : WordPress | https://manysports.tn/ | 6.9.1 |  | Technologie détectée via Webanalyze |
| P5 | vulnerability | low | Low | Low | Timestamp Disclosure - Unix | https://manysports.tn/ | 1752201721 | 10096 | — |
