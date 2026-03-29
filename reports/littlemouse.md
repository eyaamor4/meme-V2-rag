A - Résumé Exécutif

18 vulnérabilités ont été identifiées au total, dont 5 sont prioritaires.

B - Vulnérabilités Prioritaires

**1. CSP: Failure to Define Directive with No Fallback**
* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive qui n'a pas de fallback. Cela signifie que les attaques peuvent être menées sans être détectées.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
* Vérification : Exécuter curl -I sur plusieurs pages HTML et vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

**2. CSP: Wildcard Directive**
* Description : La politique de sécurité du contenu (CSP) utilise une directive wildcard qui permet à n'importe quel site Web d'accéder aux ressources.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer * par une liste précise d’hôtes de confiance.
* Vérification : Comparer la CSP déployée avec l’inventaire réel des ressources chargées.

**3. CSP: script-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) utilise la directive script-src unsafe-inline, ce qui signifie que les scripts inline sont autorisés sans vérification.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés.
* Vérification : Vérifier que script-src ne contient plus unsafe-inline.

**4. CSP: style-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) utilise la directive style-src unsafe-inline, ce qui signifie que les styles inline sont autorisés sans vérification.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Contrôler le rendu visuel des pages après externalisation des styles.

**5. Sub Resource Integrity Attribute Missing**
* Description : L'attribut de sécurité SRI (Sub Resource Integrity) est manquant sur une ressource externe, ce qui signifie que les attaques peuvent être menées sans être détectées.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
* Vérification : Inspecter le code source HTML pour vérifier la présence de l'attribut integrity.

C - Plan de remédiation

1. CSP: Failure to Define Directive with No Fallback
  - Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
2. CSP: Wildcard Directive
  - Remplacer * par une liste précise d’hôtes de confiance.
3. CSP: script-src unsafe-inline
  - Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés.
4. CSP: style-src unsafe-inline
  - Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
5. Sub Resource Integrity Attribute Missing
  - Ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées.

D - Conclusion

Le niveau de risque global est MODÉRÉ. Une action immédiate est requise pour corriger la politique de sécurité du contenu (CSP) et ajouter l'attribut SRI sur les ressources externes. Les corrections doivent être effectuées dans les 7 jours.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 5 | 3 | 10 |

    **Total :** 18 | **Prioritaires :** 5
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-13 |  |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-4 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-5 |  |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-6 |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://www.little-mouse.co.uk/ | <link rel="preload" href="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js" as="script"> | 90003 |  |
| P4 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | https://www.little-mouse.co.uk/ | set-cookie: localization | 10010 |  |
| P4 | vulnerability | low | Low | Medium | Cookie Without Secure Flag | https://www.little-mouse.co.uk/ | set-cookie: localization | 10011 |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.little-mouse.co.uk/ | <script src="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js"></script> | 10017 |  |
| P5 | information | info | — | — | aaaa-fingerprint | www.little-mouse.co.uk | 2620:127:f00f:e:: |  |  |
| P5 | information | info | — | — | caa-fingerprint | www.little-mouse.co.uk | ssl.com, digicert.com, globalsign.com, letsencrypt.org, pki.goog |  |  |
| P5 | information | info | — | — | dns-saas-service-detection | www.little-mouse.co.uk | shops.myshopify.com |  |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://www.little-mouse.co.uk/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:content-security-policy | https://www.little-mouse.co.uk/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:strict-transport-security | https://www.little-mouse.co.uk/ | — |  |  |
| P5 | information | info | — | — | ssl-dns-names | www.little-mouse.co.uk:443 | www.little-mouse.co.uk |  |  |
| P5 | information | info | — | — | ssl-issuer | www.little-mouse.co.uk:443 | Google Trust Services |  |  |
| P5 | information | info | — | — | tls-version | www.little-mouse.co.uk:443 | tls12, tls13 |  |  |
| P5 | information | info | — | — | xss-deprecated-header | https://www.little-mouse.co.uk/ | 1; mode=block |  |  |
