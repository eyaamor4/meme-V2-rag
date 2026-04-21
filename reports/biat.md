A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 8 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.biat.com.tn/ (drupal 10). Scan du : 2026-03-10 12:40:23 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client, notamment l'absence de certaines directives de sécurité dans la politique de sécurité du contenu (CSP) et l'utilisation de scripts et styles inline, ce qui signale que la surface d'attaque XSS est élargie et que le risque combiné est plus élevé.
Étant donné que le secteur est bancaire, les implications réglementaires liées à la BCT (Banque Centrale de Tunisie) et au PCI-DSS pour les vulnérabilités SQLi et RCE doivent être prises en compte.

B - Vulnérabilités Prioritaires
- CSP: Failure to Define Directive with No Fallback
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) ne définit pas une directive essentielle, ce qui peut permettre l'exécution de contenu non autorisé.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src, et contrôler dans les outils navigateur que les violations CSP sont bien remontées.

- CSP: script-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut faciliter les attaques de type XSS.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés lorsque possible.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline, et contrôler dans le HTML que les scripts inline restants portent un nonce ou hash valide.

- CSP: style-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut faciliter les attaques de type XSS.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline, et contrôler le rendu visuel des pages après externalisation des styles.

- Sub Resource Integrity Attribute Missing
  - Description : L'attribut d'intégrité des ressources est manquant sur un script ou une balise de lien servi par un serveur externe, ce qui peut permettre à un attaquant d'injecter du contenu malveillant.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
  - Sévérité : MEDIUM
  - Recommandation : Identifier les scripts et les feuilles CSS chargés depuis des domaines externes et ajouter l'attribut d'intégrité et crossorigin="anonymous" sur les ressources stables et versionnées.
  - Vérification : Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity=', vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin, et recalculer le hash en cas de mise à jour de la dépendance.

- CSP: Wildcard Directive
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) utilise une directive générique qui autorise des sources trop larges, ce qui peut faciliter les attaques.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Remplacer la directive générique par une liste précise d'hôtes de confiance et éviter les schémas génériques.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, comparer la CSP déployée avec l'inventaire réel des ressources chargées, et supprimer progressivement les sources non justifiées.

C - Vulnérabilités Potentielles à Valider
- CVE-2008-6020
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant aux attaquants distants d'exécuter des commandes SQL arbitraires. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
  - Catégorie OWASP : A03:2021 - Injection
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

- CVE-2011-4113
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant aux attaquants distants d'exécuter des commandes SQL arbitraires. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
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
4. Sub Resource Integrity Attribute Missing : Ajouter l'attribut d'intégrité et crossorigin="anonymous" sur les ressources stables et versionnées — Délai : 30 jours
5. CSP: Wildcard Directive : Remplacer la directive générique par une liste précise d'hôtes de confiance — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de remédier à la vulnérabilité "CSP: Failure to Define Directive with No Fallback" dans les 30 jours, en identifiant les directives CSP sans fallback et en les ajoutant avec des valeurs restrictives.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d'attaque et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

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

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | — | — | CVE-2012-10004 | — |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | vulnerability | low | Low | High | Server Leaks Version Information via "Server" HTTP Response Header Field | Version du serveur exposée : Apache/2.4.62 (Debian) | 10036-2 |
| P5 | information | info | — | — | Technologie détectée : Apache HTTP Server | 2.4.62 |  |
| P5 | information | info | — | — | Technologie détectée : Bootstrap | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Debian | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Drupal | 10 |  |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : HSTS | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : OWL Carousel | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : PHP | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Slick | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : jQuery | Version non fournie |  |
