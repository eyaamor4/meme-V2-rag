A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 3 vulnérabilités ont été retenues dans ce rapport, dont 1 sont prioritaires.
Niveau de risque global : FAIBLE. Niveau source : medium. Cible : http://www.acti.fr/ (wordpress 6.4.3). Scan du : 2026-03-10 14:01:17.187000.

B - Vulnérabilités Prioritaires
Content Security Policy (CSP) Header Not Set
- Description : La politique de sécurité de contenu (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certains types d'attaques, notamment les attaques de scriptage inter-site (XSS) et les attaques d'injection de données. Ces attaques sont utilisées pour tout, depuis le vol de données jusqu'à la modification de site ou la distribution de logiciels malveillants.
- Référence : 
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Définir une politique CSP de base avec default-src 'self', déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors, et éviter unsafe-inline et unsafe-eval sauf contrainte technique clairement identifiée.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, contrôler la présence de l'en-tête Content-Security-Policy, et tester l'application pour détecter d'éventuelles régressions fonctionnelles liées à la CSP.

C - Plan de remédiation
1. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires — Délai : 30 jours

D - Conclusion
Le niveau de risque global est FAIBLE. Le niveau brut source est medium. L'action prioritaire la plus critique est de définir une politique CSP de base avec default-src 'self' et de déclarer explicitement les directives nécessaires, avec un délai de 30 jours. Cette action est prioritaire pour atténuer les risques liés à la sécurité de contenu.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise les vulnérabilités retenues dans le rapport principal après déduplication.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 1 | 2 | 9 |

    
    **Niveau de risque global : FAIBLE**

    **Éléments techniques listés en annexe :** 12 | **Vulnérabilités retenues dans le rapport :** 3 | **Prioritaires (section B) :** 1**

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication.*
    

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | Content Security Policy (CSP) Header Not Set | http://www.acti.fr/ | — | 10038-1 | — |
| P4 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | http://www.acti.fr/ | set-cookie: WEBSRVID | 10010 | — |
| P4 | vulnerability | low | Low | Medium | Cookie without SameSite Attribute | http://www.acti.fr/ | set-cookie: WEBSRVID | 10054-1 | — |
| P5 | information | info | — | — | Plugin détecté : wordpress-seo | http://www.acti.fr/ | — |  | Plugin installé — aucune CVE connue associée |
| P5 | information | info | — | — | Technologie détectée : Apache HTTP Server | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HSTS | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : MySQL | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : PHP | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : WP-Optimize | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : WordPress | http://www.acti.fr/ | Version non fournie, 6.4.3 |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Yoast SEO | http://www.acti.fr/ | Version non fournie |  | Technologie détectée via Webanalyze |
