A - Résumé Exécutif

34 vulnérabilités ont été identifiées au total, dont 5 sont prioritaires.

B - Vulnérabilités Prioritaires

1. **CSP: Failure to Define Directive with No Fallback**
* Description : La politique de sécurité du contenu (CSP) ne définit pas l'une des directives qui n'a pas de fallback. L'absence ou la suppression d'elles est la même que permettre tout.
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

2. **CSP: script-src unsafe-eval**
* Description : L'exécution dynamique de code via eval est autorisée par la politique de sécurité du contenu (CSP).
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Rechercher dans le code et les dépendances les usages de eval, new Function, setTimeout avec chaîne ou équivalent.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

3. **CSP: script-src unsafe-inline**
* Description : L'exécution de scripts inline est autorisée par la politique de sécurité du contenu (CSP).
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier tous les scripts inline présents dans les templates HTML.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

4. **CSP: style-src unsafe-inline**
* Description : L'injection de styles inline est autorisée par la politique de sécurité du contenu (CSP).
* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end.
* Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy

5. **Cross-Domain Misconfiguration**
* Description : La politique de sécurité du contenu (CSP) autorise l'accès cross-origin.
* Référence : https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.
* Vérification : Tester les endpoints depuis une origine autorisée et une origine non autorisée.

C - Plan de remédiation

- Mettre à jour la politique de sécurité du contenu (CSP) pour inclure les directives manquantes.
- Rechercher et corriger les usages de eval, new Function, setTimeout avec chaîne ou équivalent dans le code et les dépendances.
- Identifier et supprimer les scripts inline présents dans les templates HTML.
- Identifier et supprimer les styles inline dans les templates et composants front-end.
- Remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.

D - Conclusion

Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique est de mettre à jour la politique de sécurité du contenu (CSP) pour inclure les directives manquantes. Le délai exact correspondant est dans les 30 jours.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 5 | 2 | 27 |

    **Total :** 34 | **Prioritaires :** 5
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-13 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-eval | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-10 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-5 |  |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-6 |  |
| P3 | vulnerability | medium | Medium | Medium | Cross-Domain Misconfiguration | https://owasp.org/ | Access-Control-Allow-Origin: * | 10098 |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://owasp.org/ | <script async src='https://www.google-analytics.com/analytics.js'></script> | 10017 |  |
| P5 | information | info | Informational | Medium | Modern Web Application | https://owasp.org/ | <a href="#" class="menu-toggler" aria-hidden="true"> <i class="fa fa-bars"></i> </a> | 10109 |  |
| P5 | information | info | Informational | Medium | Retrieved from Cache | https://owasp.org/ | HIT | 10050-1 |  |
| P5 | information | info | — | — | caa-fingerprint | owasp.org | — |  |  |
| P5 | information | info | — | — | csp-script-src-wildcard | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | dkim-record-detect | google._domainkey.owasp.org | "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5isI707a9CxKrh9pFfCqdXsY15Ig8oaPkg4NhsNJskXdJ0zpM5Hes3WH2WxyjzAQfJMh03R8NeY4k5uBN8Vp1vZ6rwB6f34NiGEK6uyDKMEP/ak7CdjmCWK8gnmznDrfK0OJCu+sngzLqQJ1gaXSBbj+XUmazvtoDph6g/Qql+Gj5osAZDLj8ZjQot8/7W1GX" "Q… |  |  |
| P5 | information | info | — | — | dmarc-detect | _dmarc.owasp.org | ""v=DMARC1; p=quarantine; rua=mailto:88b4c392605549efbbfedf60d5b5ba94@dmarc-reports.cloudflare.net,mailto:owasp-dmarc-reports@owasp.com"" |  |  |
| P5 | information | info | — | — | dns-waf-detect:cloudflare | owasp.org | — |  |  |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-digest | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-path | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-ttl | https://owasp.org/ | — |  |  |
| P5 | vulnerability | low | — | — | google-calendar-exposure:calendar-url | https://owasp.org/ | https://calendar.google.com/calendar/embed?src=hl6cjgs6ep1h7oniqgueu2bhbo%40group.calendar.google.com&amp;ctz=America%2FChicago |  |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://owasp.org/ | — |  |  |
| P5 | information | info | — | — | missing-sri | https://owasp.org/ | https://www.google-analytics.com/analytics.js, https://owasp.org/www--site-theme/assets/js/jquery-3.7.1.min.js, https://owasp.org/www--site-theme/assets/js/util.js, https://owasp.org/www--site-theme/assets/js/yaml.min.js, https://owasp.org/www--site-theme/asse… |  |  |
| P5 | information | info | — | — | mx-fingerprint | owasp.org | 1 aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 10 alt4.aspmx.l.google.com. |  |  |
| P5 | information | info | — | — | mx-service-detector:Google Apps | owasp.org | — |  |  |
| P5 | information | info | — | — | nameserver-fingerprint | owasp.org | fay.ns.cloudflare.com., west.ns.cloudflare.com. |  |  |
| P5 | information | info | — | — | spf-record-detect | owasp.org | "v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"" |  |  |
| P5 | information | info | — | — | ssl-dns-names | owasp.org:443 | *.owasp.org, owasp.org |  |  |
| P5 | information | info | — | — | ssl-issuer | owasp.org:443 | Google Trust Services |  |  |
| P5 | information | info | — | — | tls-version | owasp.org:443 | tls12, tls13 |  |  |
| P5 | information | info | — | — | txt-fingerprint | owasp.org | ""google-site-verification=I9qx_X9EKlR_rfceG25-iXHBXJvLrmeNbkEdy182iI"",""v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"",""google-site-verification=_slXlbOCopK1Ss9VQEoxdsNxpScVKvXVB_JtPpyL3eQ"",""google-site-verification=h… |  |  |
| P5 | information | info | — | — | weak-csp-detect:default-src-directive | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… |  |  |
| P5 | information | info | — | — | weak-csp-detect:script-src-directive | https://owasp.org/ | script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.w… |  |  |
| P5 | information | info | — | — | wildcard-tls | owasp.org:443 | CN: owasp.org, SAN: [owasp.org *.owasp.org] |  |  |
