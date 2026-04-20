A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 7 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://owasp.org/ (inconnu Non fourni). Scan du : 2026-02-06 08:22:54 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client, notamment des problèmes de Content Security Policy (CSP).

B - Vulnérabilités Prioritaires
1. Cross-Domain Misconfiguration
- Description : La configuration de partage de ressources cross-domaine (CORS) est incorrecte, ce qui peut permettre le chargement de données à partir de domaines non autorisés.
- Référence : https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy
- Catégorie OWASP : A01:2021 - Broken Access Control
- Sévérité : MEDIUM
- Recommandation : Identifier les endpoints réellement destinés à un accès cross-origin et remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.
- Vérification : Tester les endpoints depuis une origine autorisée et une origine non autorisée.

2. CSP: Failure to Define Directive with No Fallback
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) ne définit pas une directive essentielle, ce qui peut permettre l'exécution de code non autorisé.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy et vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

3. CSP: script-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre des attaques de type XSS.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy et vérifier que script-src ne contient plus unsafe-inline.

4. CSP: style-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) permet l'injection de styles inline, ce qui peut permettre des attaques de type XSS.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy et vérifier que style-src ne contient plus unsafe-inline.

5. CSP: script-src unsafe-eval
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité de contenu (CSP) permet l'exécution dynamique de code via eval, ce qui peut permettre des attaques de type XSS.
- Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Rechercher les usages de eval et les refactoriser pour éviter l’exécution dynamique de code.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy et vérifier que script-src ne contient plus unsafe-eval.

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider n'a été identifiée.

D - Plan de remédiation
1. Cross-Domain Misconfiguration : Identifier les endpoints réellement destinés à un accès cross-origin et remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée — Délai : 30 jours
2. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives — Délai : 30 jours
3. CSP: script-src unsafe-inline : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés — Délai : 30 jours
4. CSP: style-src unsafe-inline : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
5. CSP: script-src unsafe-eval : Rechercher les usages de eval et les refactoriser pour éviter l’exécution dynamique de code — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de remédier à la vulnérabilité Cross-Domain Misconfiguration, avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d’attaque côté navigateur et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 5 | 2 | 25 |

    **Niveau de risque global : MODÉRÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 7  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 25  
    **Prioritaires confirmées (section B) :** 5 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | vulnerability | low | — | — | google-calendar-exposure:calendar-url | https://calendar.google.com/calendar/embed?src=hl6cjgs6ep1h7oniqgueu2bhbo%40group.calendar.google.com&amp;ctz=America%2FChicago |  |
| P5 | information | info | Informational | Low | Information Disclosure - Suspicious Comments | from | 10027 |
| P5 | information | info | Informational | Medium | Modern Web Application | <a href="#" class="menu-toggler" aria-hidden="true"> <i class="fa fa-bars"></i> </a> | 10109 |
| P5 | information | info | Informational | Low | Re-examine Cache-control Directives | max-age=600 | 10015 |
| P5 | information | info | Informational | Medium | Retrieved from Cache | HIT | 10050-1 |
| P5 | information | info | — | — | Technologie détectée : Amazon S3 | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Amazon Web Services | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Cloudflare | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Fastly | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : GitHub Pages | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : HSTS | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Varnish | Version non fournie |  |
| P5 | information | info | — | — | caa-fingerprint | — |  |
| P5 | information | info | — | — | csp-script-src-wildcard | — |  |
| P5 | information | info | — | — | dkim-record-detect | "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5isI707a9CxKrh9pFfCqdXsY15Ig8oaPkg4NhsNJskXdJ0zpM5Hes3WH2WxyjzAQfJMh03R8NeY4k5uBN8Vp1vZ6rwB6f34NiGEK6uyDKMEP/ak7CdjmC… |  |
| P5 | information | info | — | — | dmarc-detect | ""v=DMARC1; p=quarantine; rua=mailto:88b4c392605549efbbfedf60d5b5ba94@dmarc-reports.cloudflare.net,mailto:owasp-dmarc-reports@owasp.com"" |  |
| P5 | information | info | — | — | dns-waf-detect:cloudflare | — |  |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-digest | — |  |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-path | — |  |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-ttl | — |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | — |  |
| P5 | information | info | — | — | missing-sri | https://www.google-analytics.com/analytics.js, https://owasp.org/www--site-theme/assets/js/jquery-3.7.1.min.js, https://owasp.org/www--site-theme/assets/js/util.js, https://owasp.o… |  |
| P5 | information | info | — | — | mx-fingerprint | 1 aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 10 alt4.aspmx.l.google.com. |  |
| P5 | information | info | — | — | mx-service-detector:Google Apps | — |  |
| P5 | information | info | — | — | nameserver-fingerprint | fay.ns.cloudflare.com., west.ns.cloudflare.com. |  |
| P5 | information | info | — | — | spf-record-detect | "v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"" |  |
| P5 | information | info | — | — | ssl-dns-names | *.owasp.org, owasp.org |  |
| P5 | information | info | — | — | ssl-issuer | Google Trust Services |  |
| P5 | information | info | — | — | tls-version | tls12 |  |
| P5 | information | info | — | — | txt-fingerprint | ""google-site-verification=I9qx_X9EKlR_rfceG25-iXHBXJvLrmeNbkEdy182iI"",""v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"",""google-site-verific… |  |
| P5 | information | info | — | — | weak-csp-detect:default-src-directive | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.tw… |  |
| P5 | information | info | — | — | weak-csp-detect:script-src-directive | Politique CSP autorise 'unsafe-inline' pour les scripts |  |
| P5 | information | info | — | — | wildcard-tls | CN: owasp.org, SAN: [owasp.org *.owasp.org] |  |
