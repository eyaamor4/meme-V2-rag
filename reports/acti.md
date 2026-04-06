A - Résumé Exécutif
3 vulnérabilités ont été retenues dans ce rapport, dont 1 sont prioritaires.

B - Vulnérabilités Prioritaires
**Content Security Policy (CSP) Header Not Set**
* Description : La politique de sécurité de contenu (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certains types d'attaques, notamment les attaques de scriptage intersite (XSS) et les attaques d'injection de données. Ces attaques sont utilisées pour tout, depuis le vol de données jusqu'à la défiguration de site ou la distribution de logiciels malveillants. La CSP fournit un ensemble d'en-têtes HTTP standard qui permettent aux propriétaires de sites Web de déclarer les sources approuvées de contenu que les navigateurs devraient être autorisés à charger sur cette page — les types couverts sont JavaScript, CSS, les cadres HTML, les polices, les images et les objets incorporables tels que les applets Java, ActiveX, les fichiers audio et vidéo.
* Référence : 
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir une politique CSP de base avec default-src 'self', déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors, et éviter unsafe-inline et unsafe-eval sauf contrainte technique clairement identifiée.
* Vérification :
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Contrôler la présence de l'en-tête Content-Security-Policy.
  - Tester l'application pour détecter d'éventuelles régressions fonctionnelles liées à la CSP.

C - Plan de remédiation
1. **Content Security Policy (CSP) Header Not Set** : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.

D - Conclusion
Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique est de définir une politique CSP de base pour atténuer les risques d'attaques XSS et d'injection de données. Il est recommandé de prendre cette action dans les 30 jours.


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
