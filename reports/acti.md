A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 3 vulnérabilités ont été retenues dans ce rapport, dont 1 sont prioritaires.
Niveau de risque global : FAIBLE. Cible : http://www.acti.fr/ (wordpress 6.4.3). Scan du : 2026-03-10 14:01:17 UTC.
La surface d'attaque côté navigateur est élargie en raison de la présence de vulnérabilités liées à la sécurité côté client, notamment l'absence de Content Security Policy (CSP).

B - Vulnérabilités Prioritaires
Content Security Policy (CSP) Header Not Set
- Description : La politique de sécurité de contenu (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certains types d'attaques, notamment les attaques de scriptage inter-site (XSS) et les attaques d'injection de données. 
- Référence : 
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, contrôler la présence de l'en-tête Content-Security-Policy et tester l'application pour détecter d'éventuelles régressions fonctionnelles liées à la CSP.

C - Vulnérabilités Potentielles à Valider
Cette section n'est pas applicable dans ce cas, car il n'y a pas de vulnérabilités potentielles à valider.

D - Plan de remédiation
1. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires — Délai : 30 jours

E - Conclusion
Le niveau de risque global est FAIBLE.
L'action prioritaire principale est de définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires, avec un délai de 30 jours.
Il est essentiel de remédier à cette vulnérabilité pour réduire la surface d'attaque côté navigateur et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 1 | 2 | 9 |

    **Niveau de risque global : FAIBLE**

    **Vulnérabilités confirmées retenues dans le rapport :** 3  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 9  
    **Prioritaires confirmées (section B) :** 1 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P5 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | set-cookie: WEBSRVID | 10010 |
| P5 | vulnerability | low | Low | Medium | Cookie without SameSite Attribute | set-cookie: WEBSRVID | 10054-1 |
| P5 | information | info | — | — | Plugin détecté : wordpress-seo | — |  |
| P5 | information | info | — | — | Technologie détectée : Apache HTTP Server | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : HSTS | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : MySQL | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : PHP | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : WP-Optimize | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : WordPress | Version non fournie, 6.4.3 |  |
| P5 | information | info | — | — | Technologie détectée : Yoast SEO | Version non fournie |  |
