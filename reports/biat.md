A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 8 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.biat.com.tn/ (drupal 10). Scan du : 2026-03-10 12:40:23 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client, notamment l'absence de directives de sécurité adéquates dans la politique de sécurité du contenu (CSP) et l'utilisation de scripts et de styles inline non sécurisés. Cela signale que la surface d'attaque XSS est élargie et que le risque combiné est plus élevé.

B - Vulnérabilités Prioritaires
- CSP: Failure to Define Directive with No Fallback
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) ne définit pas une directive essentielle sans fallback, ce qui équivaut à autoriser n’importe quoi.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
  - Vérification : Exécuter `curl -I https://www.biat.com.tn/ | grep -i content-security-policy`, lire la valeur complète de l’en-tête CSP et vérifier explicitement la présence des directives form-action, frame-ancestors, base-uri et object-src. Si une directive essentielle est absente, la vulnérabilité est confirmée.

- CSP: script-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) autorise l'exécution de scripts inline, ce qui peut permettre des attaques de type XSS.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés lorsque possible.
  - Vérification : Exécuter `curl -I https://www.biat.com.tn/ | grep -i content-security-policy`, lire la valeur complète de l’en-tête CSP et identifier la directive script-src. Si 'unsafe-inline' est présent, la vulnérabilité est confirmée.

- CSP: style-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) autorise l'injection de styles inline, ce qui peut permettre des attaques de type XSS.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les styles inline dans les templates et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
  - Vérification : Exécuter `curl -I https://www.biat.com.tn/ | grep -i content-security-policy`, lire la valeur complète de l’en-tête CSP et identifier la directive style-src. Si 'unsafe-inline' est présent, la vulnérabilité est confirmée.

- Sub Resource Integrity Attribute Missing
  - Description : L'attribut d'intégrité des ressources est manquant sur les balises script ou link chargées depuis des serveurs externes, ce qui permet à un attaquant ayant accès à ces serveurs d'injecter du contenu malveillant.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
  - Sévérité : MEDIUM
  - Recommandation : Identifier les scripts et les feuilles CSS chargés depuis des domaines externes et ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
  - Vérification : Exécuter `curl -s https://www.biat.com.tn/ | grep -i integrity`, identifier les balises script et link qui chargent des ressources externes et vérifier si ces balises contiennent un attribut integrity et crossorigin. Si l'attribut est absent, la vulnérabilité est confirmée.

- CSP: Wildcard Directive
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) utilise une directive générique (*), ce qui autorise des sources trop larges et peut permettre des attaques.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Remplacer la directive générique (*) par une liste précise d’hôtes de confiance.
  - Vérification : Exécuter `curl -I https://www.biat.com.tn/ | grep -i content-security-policy`, lire la valeur complète de l’en-tête CSP et rechercher explicitement le caractère '*' dans les directives concernées. Si le caractère '*' est présent, la vulnérabilité est confirmée.

C - Vulnérabilités Potentielles à Valider
- CVE-2008-6020
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant à des attaquants distants d'exécuter des commandes SQL arbitraires via des vecteurs non spécifiés liés à un filtre exposé sur les champs de texte CCK. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
  - Catégorie OWASP : A03:2021 - Injection
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

- CVE-2011-4113
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant à des attaquants distants d'exécuter des commandes SQL arbitraires via des vecteurs liés aux filtres/arguments sur certains types de vues avec des configurations d'arguments spécifiques. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
  - Catégorie OWASP : A03:2021 - Injection
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

- CVE-2024-13254
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'insertion d'informations sensibles dans les données envoyées dans Drupal REST Views, permettant la navigation forcée. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
  - Catégorie OWASP : A01:2021 - Broken Access Control
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

D - Plan de remédiation
1. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives — Délai : 30 jours
2. CSP: script-src unsafe-inline : Migrer les scripts inline vers des fichiers JS statiques versionnés — Délai : 30 jours
3. CSP: style-src unsafe-inline : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
4. Sub Resource Integrity Attribute Missing : Ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées — Délai : 30 jours
5. CSP: Wildcard Directive : Remplacer la directive générique (*) par une liste précise d’hôtes de confiance — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de remédier à la vulnérabilité "CSP: Failure to Define Directive with No Fallback" dans les 30 jours, en raison de son impact sur la sécurité de la politique de sécurité du contenu.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d'attaque et améliorer la sécurité globale du site web.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 5 | 3 | 10 |

    **Niveau de risque global : MODÉRÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 8  
    **Vulnérabilités potentielles à valider :** 3  
    **Éléments informationnels :** 10  
    **Prioritaires confirmées (section B) :** 5 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | CVE-2012-10004 | low | — |  |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | Server Leaks Version Information via "Server" HTTP Response Header Field | low | Version du serveur exposée : Apache/2.4.62 (Debian) | 10036-2 |
| P5 | Technologie détectée : Apache HTTP Server | info | 2.4.62 |  |
| P5 | Technologie détectée : Bootstrap | info | Version non fournie |  |
| P5 | Technologie détectée : Debian | info | Version non fournie |  |
| P5 | Technologie détectée : Drupal | info | 10 |  |
| P5 | Technologie détectée : Google Tag Manager | info | Version non fournie |  |
| P5 | Technologie détectée : HSTS | info | Version non fournie |  |
| P5 | Technologie détectée : OWL Carousel | info | Version non fournie |  |
| P5 | Technologie détectée : PHP | info | Version non fournie |  |
| P5 | Technologie détectée : Slick | info | Version non fournie |  |
| P5 | Technologie détectée : jQuery | info | Version non fournie |  |
