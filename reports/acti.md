A - Résumé Exécutif

3 vulnérabilités ont été retenues dans ce rapport, dont 1 est prioritaire.

B - Vulnérabilités Prioritaires

**Content Security Policy (CSP) Header Not Set**
* Description : La politique de sécurité du contenu n'est pas définie, ce qui peut permettre des attaques XSS et d'autres types d'attaques.
* Référence :
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.
* Vérification :
  Exécuter la commande suivante pour vérifier l'en-tête Content-Security-Policy : `curl -I https://[site] | grep -i content-security-policy`

C - Plan de remédiation

1. [Content Security Policy (CSP) Header Not Set] : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.

D - Conclusion

Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique consiste à mettre en place une politique CSP de base pour prévenir les attaques XSS. Ce travail doit être réalisé dans les 30 jours.


## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 1 | 2 | 9 |

**Éléments techniques listés en annexe :** 12 | **Vulnérabilités retenues dans le rapport :** 3 | **Prioritaires (section B) :** 1


## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

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
