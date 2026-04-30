A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 14 vulnérabilités ont été retenues dans ce rapport, dont 8 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://manysports.tn/ (wordpress 6.9.1). Scan du : 2026-03-10 12:21:55 UTC.
La surface d’attaque côté navigateur est élargie.

B - Vulnérabilités Prioritaires
[CSP: Failure to Define Directive with No Fallback]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) ne définit pas une des directives qui n'a pas de fallback. L'absence ou l'exclusion de ces directives est la même que d'autoriser n'importe quoi.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir les directives manquantes avec des valeurs restrictives.
- Vérification : 
  Exécuter : curl -I https://manysports.tn/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP récupéré.
  Vérifier explicitement la présence des directives form-action, frame-ancestors, base-uri et object-src.

[CSP: script-src unsafe-inline]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) permet l'exécution de scripts inline.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible.
- Vérification : 
  Exécuter : curl -I https://manysports.tn/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Identifier la directive script-src dans la politique.

[CSP: style-src unsafe-inline]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) permet l'injection de styles inline.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
- Vérification : 
  Exécuter : curl -I https://manysports.tn/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Identifier la directive style-src dans la politique.

[Sub Resource Integrity Attribute Missing]
- Description : L'attribut d'intégrité est manquant sur les balises script et link chargées depuis des serveurs externes.
- Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Ajouter l'attribut integrity sur les ressources externes.
- Vérification : 
  Exécuter : curl -s https://manysports.tn/ | grep -i integrity
  Identifier les balises script et link qui chargent des ressources externes.
  Vérifier si ces balises contiennent un attribut integrity.

[CSP: Wildcard Directive]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) contient une directive avec un joker (*).
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Remplacer le joker par une liste précise d'hôtes de confiance.
- Vérification : 
  Exécuter : curl -I https://manysports.tn/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Rechercher explicitement le caractère '*' dans les directives concernées.

[Missing Anti-clickjacking Header]
  - Paramètre/Ressource affecté(e) : x-frame-options
- Description : L'en-tête X-Frame-Options est manquant pour protéger contre les attaques de type ClickJacking.
- Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : 
  Exécuter curl -I https://manysports.tn/ | grep -i x-frame-options
  Contrôler la présence de X-Frame-Options ou de frame-ancestors dans la CSP.
  Tester l’intégration de la page dans une iframe depuis un domaine tiers.

[CVE-2023-5561]
- Description : WordPress ne restreint pas correctement les champs d'utilisateurs accessibles via l'API REST, permettant à des attaquants non authentifiés de découvrir les adresses e-mail des utilisateurs ayant publié des articles publics sur un site affecté via une attaque de type Oracle.
- Référence : 
  - https://lists.debian.org/debian-lts-announce/2023/11/msg00014.html
  - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
  - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
- Catégorie OWASP : A01:2021 - Broken Access Control
- Sévérité : MEDIUM
- Recommandation : Mettre à jour WordPress vers une version corrigée.
- Vérification : 
  Validation manuelle requise : vérifier la version exacte du composant concerné et la comparer avec la version corrigée indiquée dans la référence CVE.

[CVE-2024-2473]
* Score CVSS : 5.3
- Description : Le plugin WPS Hide Login pour WordPress est vulnérable à la divulgation de la page de connexion dans toutes les versions jusqu'à et y compris 1.9.15.2. Cela est dû à un contournement créé lorsque le paramètre 'action=postpass' est fourni. Cela permet aux attaquants de découvrir facilement n'importe quelle page de connexion qui aurait pu être masquée par le plugin.
- Référence : 
  - https://github.com/whattheslime/wps-show-login
  - https://plugins.trac.wordpress.org/changeset/3099109/wps-hide-login
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/fd21c7d3-a5f1-4c3a-b6ab-0a979f070a62?source=cve
- Catégorie OWASP : A07:2021 - Identification and Authentication Failures
- Sévérité : MEDIUM
- Recommandation : Mettre à jour le plugin WPS Hide Login vers une version corrigée.
- Vérification : 
  Validation manuelle requise : vérifier la version exacte du composant concerné et la comparer avec la version corrigée indiquée dans la référence CVE.

C - Vulnérabilités Potentielles à Valider
Cette section est OPTIONNELLE.

D - Plan de remédiation
1. [CSP: Failure to Define Directive with No Fallback] : Définir les directives manquantes avec des valeurs restrictives — Délai : 30 jours
2. [CSP: script-src unsafe-inline] : Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible — Délai : 30 jours
3. [CSP: style-src unsafe-inline] : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
4. [Sub Resource Integrity Attribute Missing] : Ajouter l'attribut integrity sur les ressources externes — Délai : 30 jours
5. [CSP: Wildcard Directive] : Remplacer le joker par une liste précise d'hôtes de confiance — Délai : 30 jours
6. [Missing Anti-clickjacking Header] : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 30 jours
7. [CVE-2023-5561] : Mettre à jour WordPress vers une version corrigée — Délai : 30 jours
8. [CVE-2024-2473] : Mettre à jour le plugin WPS Hide Login vers une version corrigée — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de définir les directives manquantes avec des valeurs restrictives pour [CSP: Failure to Define Directive with No Fallback], avec un délai de 30 jours.


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
