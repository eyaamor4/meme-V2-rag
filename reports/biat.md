A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 8 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.biat.com.tn/ (drupal 10). Scan du : 2026-03-10 12:40:23 UTC.
La surface d’attaque côté navigateur est élargie.

B - Vulnérabilités Prioritaires
[CSP: Failure to Define Directive with No Fallback]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) ne définit pas une des directives qui n'a pas de fallback. L'absence ou l'exclusion de ces directives est la même que permettre tout.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle parmi : form-action, frame-ancestors, base-uri, object-src. Ajouter uniquement les directives manquantes avec des valeurs restrictives. Ne pas recommander l'ajout d'une directive déjà définie dans le CSP existant.
- Vérification : 
  Exécuter : curl -I https://www.biat.com.tn/ | grep -i content-security-policy
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
- Recommandation : Identifier tous les scripts inline présents dans les templates HTML. Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible. Utiliser des nonces dynamiques par réponse pour les scripts inline légitimes restants. À défaut, utiliser des hashes CSP strictement calculés sur les blocs inline stables.
- Vérification : 
  Exécuter : curl -I https://www.biat.com.tn/ | grep -i content-security-policy
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
- Recommandation : Identifier les styles inline dans les templates et composants front-end. Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées. Conserver uniquement des hashes CSP pour les fragments inline impossibles à externaliser. Nettoyer les librairies ou widgets qui injectent du style inline non indispensable.
- Vérification : 
  Exécuter : curl -I https://www.biat.com.tn/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Identifier la directive style-src dans la politique.

[Sub Resource Integrity Attribute Missing]
- Description : L'attribut d'intégrité est manquant sur les balises script et link chargées depuis des serveurs externes.
- Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes. Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées. Héberger localement les ressources externes critiques si leur contenu varie fréquemment. Réduire le nombre de dépendances tierces non indispensables.
- Vérification : 
  Exécuter : curl -s https://www.biat.com.tn/ | grep -i integrity
  Identifier les balises script et link qui chargent des ressources externes (CDN, domaine tiers, URL absolue ou //domain).
  Vérifier si ces balises contiennent un attribut integrity et crossorigin.

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
- Recommandation : Remplacer * par une liste précise d’hôtes de confiance. Éviter les schémas génériques comme https: quand les domaines réels sont connus. Séparer les besoins par type de ressource : script-src, style-src, img-src, font-src, connect-src, frame-src. Supprimer les doublons et les domaines non utilisés.
- Vérification : 
  Exécuter : curl -I https://www.biat.com.tn/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Rechercher explicitement le caractère '*' dans les directives concernées.

C - Vulnérabilités Potentielles à Valider
[CVE-2008-6020]
- Statut : À valider manuellement
- Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
- Catégorie OWASP : A03:2021 - Injection
- Sévérité : HIGH
- Délai : À valider manuellement avant planification

[CVE-2011-4113]
- Statut : À valider manuellement
- Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
- Catégorie OWASP : A03:2021 - Injection
- Sévérité : HIGH
- Délai : À valider manuellement avant planification

[CVE-2024-13254]
- Statut : À valider manuellement
- Description : Insertion de données sensibles dans les données envoyées. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
- Catégorie OWASP : A01:2021 - Broken Access Control
- Sévérité : HIGH
- Délai : À valider manuellement avant planification

D - Plan de remédiation
1. [CSP: Failure to Define Directive with No Fallback] : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle parmi : form-action, frame-ancestors, base-uri, object-src. Ajouter uniquement les directives manquantes avec des valeurs restrictives. — Délai : 30 jours
2. [CSP: script-src unsafe-inline] : Identifier tous les scripts inline présents dans les templates HTML. Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible. — Délai : 30 jours
3. [CSP: style-src unsafe-inline] : Identifier les styles inline dans les templates et composants front-end. Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées. — Délai : 30 jours
4. [Sub Resource Integrity Attribute Missing] : Identifier les scripts et feuilles CSS chargés depuis des domaines externes. Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées. — Délai : 30 jours
5. [CSP: Wildcard Directive] : Remplacer * par une liste précise d’hôtes de confiance. Éviter les schémas génériques comme https: quand les domaines réels sont connus. — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de remédier à la vulnérabilité [CSP: Failure to Define Directive with No Fallback] dans un délai de 30 jours.
Il est essentiel de traiter les vulnérabilités de sécurité côté client pour réduire la surface d'attaque.
La validation manuelle des vulnérabilités potentielles à valider est nécessaire pour déterminer leur applicabilité et planifier les remédiations appropriées.


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
