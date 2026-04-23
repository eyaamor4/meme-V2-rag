A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 14 vulnérabilités ont été retenues dans ce rapport, dont 8 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://manysports.tn/ (wordpress 6.9.1). Scan du : 2026-03-10 12:21:55 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client, notamment l'absence de certaines directives de sécurité et l'utilisation de scripts et styles inline. Cela signifie que la surface d'attaque XSS est élargie et que le risque combiné est plus élevé.

B - Vulnérabilités Prioritaires
- CSP: Failure to Define Directive with No Fallback
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) ne définit pas une directive essentielle, ce qui peut permettre à un attaquant d'exécuter du code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

- CSP: script-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre à un attaquant d'exécuter du code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline.

- CSP: style-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut permettre à un attaquant d'exécuter du code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline.

- Sub Resource Integrity Attribute Missing
  - Description : L'attribut d'intégrité des ressources est manquant, ce qui peut permettre à un attaquant d'injecter du code malveillant.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
  - Sévérité : MEDIUM
  - Recommandation : Ajouter l'attribut d'intégrité aux ressources chargées depuis des domaines externes.
  - Vérification : Inspecter le code source HTML, vérifier la présence de l'attribut d'intégrité sur les balises script et link externes.

- CSP: Wildcard Directive
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) utilise une directive générique, ce qui peut permettre à un attaquant d'exécuter du code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Remplacer la directive générique par une liste précise d'hôtes de confiance.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, comparer la CSP déployée avec l'inventaire réel des ressources chargées.

- Missing Anti-clickjacking Header
  - Paramètre/Ressource affecté(e) : x-frame-options
  - Description : L'en-tête de protection contre les attaques de clickjacking est manquant, ce qui peut permettre à un attaquant d'exécuter du code malveillant.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Définir l'en-tête X-Frame-Options à DENY ou SAMEORIGIN.
  - Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options, tester l'intégration de la page dans une iframe depuis un domaine tiers.

- CVE-2023-5561
  - Description : Une vulnérabilité dans WordPress permet à un attaquant de découvrir les adresses e-mail des utilisateurs qui ont publié des articles publics.
  - Référence : 
    - https://lists.debian.org/debian-lts-announce/2023/11/msg00014.html
    - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
    - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
  - Catégorie OWASP : A01:2021 - Broken Access Control
  - Sévérité : MEDIUM
  - Recommandation : Mettre à jour WordPress vers une version corrigée.
  - Vérification : Tester les vues avec plusieurs rôles, manipuler les paramètres exposés et filtres.

- CVE-2024-2473
* Score CVSS : 5.3
  - Description : Une vulnérabilité dans le plugin WPS Hide Login permet à un attaquant de découvrir la page de connexion cachée.
  - Référence : 
    - https://github.com/whattheslime/wps-show-login
    - https://plugins.trac.wordpress.org/changeset/3099109/wps-hide-login
    - https://www.wordfence.com/threat-intel/vulnerabilities/id/fd21c7d3-a5f1-4c3a-b6ab-0a979f070a62?source=cve
  - Catégorie OWASP : A07:2021 - Identification and Authentication Failures
  - Sévérité : MEDIUM
  - Recommandation : Mettre à jour le plugin WPS Hide Login vers une version corrigée.
  - Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options, tester l'intégration de la page dans une iframe depuis un domaine tiers.

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider n'a été identifiée.

D - Plan de remédiation
1. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives — Délai : 30 jours
2. CSP: script-src unsafe-inline : Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible — Délai : 30 jours
3. CSP: style-src unsafe-inline : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
4. Sub Resource Integrity Attribute Missing : Ajouter l'attribut d'intégrité aux ressources chargées depuis des domaines externes — Délai : 30 jours
5. CSP: Wildcard Directive : Remplacer la directive générique par une liste précise d'hôtes de confiance — Délai : 30 jours
6. Missing Anti-clickjacking Header : Définir l'en-tête X-Frame-Options à DENY ou SAMEORIGIN — Délai : 30 jours
7. CVE-2023-5561 : Mettre à jour WordPress vers une version corrigée — Délai : 30 jours
8. CVE-2024-2473 : Mettre à jour le plugin WPS Hide Login vers une version corrigée — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ. L'action prioritaire principale est de remédier à la vulnérabilité CSP: Failure to Define Directive with No Fallback, qui doit être effectuée dans les 30 jours. Il est essentiel de traiter ces vulnérabilités pour réduire la surface d'attaque et protéger les données sensibles.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 9 | 5 | 28 |

    **Niveau de risque global : MODÉRÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 14  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 28  
    **Prioritaires confirmées (section B) :** 8 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | Absence of Anti-CSRF Tokens | medium | <form name="ts-login-form" id="ts-login-form" action="https://manysports.tn/wp-login.php" method="post"> | 10202 |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | low | x-powered-by: PHP/8.2.30 | 10037 |
| P4 | Strict-Transport-Security Header Not Set | low | — | 10035-1 |
| P4 | Timestamp Disclosure - Unix | low | 1752201721 | 10096 |
| P5 | Plugin détecté : automattic-for-agencies-client | info | — |  |
| P5 | Plugin détecté : blaze-ads | info | — |  |
| P5 | Plugin détecté : contact-form-7 | info | — |  |
| P5 | Plugin détecté : elementor | info | — |  |
| P5 | Plugin détecté : filebird | info | — |  |
| P5 | Plugin détecté : font-awesome | info | — |  |
| P5 | Plugin détecté : google-site-kit | info | — |  |
| P5 | Plugin détecté : hostinger | info | — |  |
| P5 | Plugin détecté : jetpack | info | — |  |
| P5 | Plugin détecté : jetpack-search | info | — |  |
| P5 | Plugin détecté : litespeed-cache | info | — |  |
| P5 | Plugin détecté : mainichi-shopify-products-connect | info | — |  |
| P5 | Plugin détecté : simple-history | info | — |  |
| P5 | Plugin détecté : woocommerce | info | — |  |
| P5 | Plugin détecté : wordpress-seo | info | — |  |
| P5 | Plugin détecté : wp-store-lite | info | — |  |
| P5 | Technologie détectée : Elementor | info | 3.35.5 |  |
| P5 | Technologie détectée : HTTP/3 | info | Version non fournie |  |
| P5 | Technologie détectée : Hostinger | info | Version non fournie |  |
| P5 | Technologie détectée : LiteSpeed | info | Version non fournie |  |
| P5 | Technologie détectée : Litespeed Cache | info | Version non fournie |  |
| P5 | Technologie détectée : MySQL | info | Version non fournie |  |
| P5 | Technologie détectée : PHP | info | Version non fournie, 8.2.30 |  |
| P5 | Technologie détectée : Redux Framework | info | 4.5.10 |  |
| P5 | Technologie détectée : Site Kit | info | 1.173.0 |  |
| P5 | Technologie détectée : Slider Revolution | info | 6.7.29 |  |
| P5 | Technologie détectée : WooCommerce | info | 10.5.3 |  |
| P5 | Technologie détectée : WordPress | info | 6.9.1 |  |
| P5 | X-Content-Type-Options Header Missing | low | — | 10021 |
