A - Résumé Exécutif
10 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires. La surface d'attaque XSS est plus large en raison de la combinaison de plusieurs findings CSP, ce qui augmente le risque combiné.

B - Vulnérabilités Prioritaires
**CSP: Failure to Define Directive with No Fallback**
* **Paramètre/Ressource affecté(e) :** `content-security-policy`
* Description : La politique de sécurité de contenu (CSP) ne définit pas une directive qui n'a pas de fallback, ce qui est équivalent à autoriser tout.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

**CSP: Wildcard Directive**
* **Paramètre/Ressource affecté(e) :** `content-security-policy`
* Description : La directive CSP utilise un joker qui autorise des sources trop larges.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer le joker par une liste précise d'hôtes de confiance.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, comparer la CSP déployée avec l'inventaire réel des ressources chargées.

**CSP: script-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `content-security-policy`
* Description : La directive script-src permet l'exécution de scripts inline.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline.

**CSP: style-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `content-security-policy`
* Description : La directive style-src permet l'injection de styles inline.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline.

**Sub Resource Integrity Attribute Missing**
* Description : L'attribut d'intégrité de ressource est manquant sur un script ou un lien servi par un serveur externe.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter l'attribut d'intégrité sur les ressources stables et versionnées.
* Vérification : Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity=', vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

C - Plan de remédiation
1. **CSP: Failure to Define Directive with No Fallback** : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives.
2. **CSP: Wildcard Directive** : Remplacer le joker par une liste précise d'hôtes de confiance.
3. **CSP: script-src unsafe-inline** : Migrer les scripts inline vers des fichiers JS statiques versionnés.
4. **CSP: style-src unsafe-inline** : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
5. **Sub Resource Integrity Attribute Missing** : Ajouter l'attribut d'intégrité sur les ressources stables et versionnées.

D - Conclusion
Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique est de remédier à la vulnérabilité **CSP: Failure to Define Directive with No Fallback**. Il est recommandé de prendre des mesures correctives dans les 30 jours.


## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 6 | 4 | 15 |

**Éléments techniques listés en annexe :** 25 | **Vulnérabilités retenues dans le rapport :** 10 | **Prioritaires (section B) :** 5


## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-4 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-6 | — |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://www.little-mouse.co.uk/ | <link rel="preload" href="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js" as="script">, <script src="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js"></script>, <link rel="preload" href="https://cdn.shopify.com/ex… | 90003 | — |
| P4 | vulnerability | medium | Medium | Low | Absence of Anti-CSRF Tokens | https://www.little-mouse.co.uk/ | <form action="/cart" id="CartDrawer-Form" class="cart__contents cart-drawer__form" method="post" >, <form method="post" action="/localization" id="HeaderCountryMobileForm" accept-charset="UTF-8" class="localization-form" enctype="multipart/form-data">, <form m… | 10202 | — |
| P4 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | https://www.little-mouse.co.uk/ | set-cookie: localization, set-cookie: cart_currency | 10010 | — |
| P4 | vulnerability | low | Low | Medium | Cookie Without Secure Flag | https://www.little-mouse.co.uk/ | set-cookie: localization, set-cookie: cart_currency | 10011 | — |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.little-mouse.co.uk/ | <script src="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js"></script>, <script async="async" src="https://shop.app/checkouts/internal/preloads.js?locale=en-GB&shop_id=13607291" crossorigin="anonymous"></script>, <script async src="http… | 10017 | — |
| P5 | information | info | — | — | Technologie détectée : Cloudflare | https://www.little-mouse.co.uk/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | https://www.little-mouse.co.uk/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HSTS | https://www.little-mouse.co.uk/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HTTP/3 | https://www.little-mouse.co.uk/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Shopify | https://www.little-mouse.co.uk/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | vulnerability | low | Low | Low | Timestamp Disclosure - Unix | https://www.little-mouse.co.uk/ | 1747081266, 1747230638, 1773146243, 1742382692, 1630358641, 1706708225, 1769612355, 1519747449, 1769647766, 1769596599, 1769600864, 1769595130, 1769595129, 1769595134, 1769597692, 1769604427, 1769606950, 1670257553, 1770299147, 1770390414, 1769593756, 17696009… | 10096 | — |
| P5 | information | info | — | — | aaaa-fingerprint | www.little-mouse.co.uk | 2620:127:f00f:e:: |  | — |
| P5 | information | info | — | — | caa-fingerprint | www.little-mouse.co.uk | ssl.com, digicert.com, globalsign.com, letsencrypt.org, pki.goog |  | — |
| P5 | information | info | — | — | dns-saas-service-detection | www.little-mouse.co.uk | shops.myshopify.com |  | — |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://www.little-mouse.co.uk/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:content-security-policy | https://www.little-mouse.co.uk/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:strict-transport-security | https://www.little-mouse.co.uk/ | — |  | — |
| P5 | information | info | — | — | ssl-dns-names | www.little-mouse.co.uk:443 | www.little-mouse.co.uk |  | — |
| P5 | information | info | — | — | ssl-issuer | www.little-mouse.co.uk:443 | Google Trust Services |  | — |
| P5 | information | info | — | — | tls-version | www.little-mouse.co.uk:443 | tls12, tls13 |  | — |
| P5 | information | info | — | — | xss-deprecated-header | https://www.little-mouse.co.uk/ | 1; mode=block |  | — |
