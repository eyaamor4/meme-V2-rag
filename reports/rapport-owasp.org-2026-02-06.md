A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 7 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Niveau source : medium. Cible : https://owasp.org/ (inconnu Non fourni). Scan du : 2026-02-06 08:22:54.933000.
Puisque 0 vulnérabilités potentielles n'ont pas pu être confirmées, aucune validation manuelle n'est recommandée.
De plus, la présence de plusieurs findings CSP (unsafe-inline, script-src unsafe-eval, etc.) signale que la surface d'attaque XSS est élargie et que le risque combiné est plus élevé.

B - Vulnérabilités Priorit*

aires
- CSP: Failure to Define Directive with No Fallback
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
  - Description : La politique de sécurité du contenu (CSP) ne définit pas une directive sans fallback, ce qui peut permettre l'exécution de code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Recommandation : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.
- CSP: script-src unsafe-eval
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
  - Description : La politique de sécurité du contenu (CSP) permet l'exécution dynamique de code via eval, ce qui peut permettre l'exécution de code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Recommandation : Rechercher les usages de eval, new Function, setTimeout avec chaîne ou équivalent et refactoriser les composants front-end concernés.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-eval.
- CSP: script-src unsafe-inline
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
  - Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre l'exécution de code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Recommandation : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline.
- CSP: style-src unsafe-inline
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
  - Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut permettre l'exécution de code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Recommandation : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline.
- Cross-Domain Misconfiguration
  - Description : La configuration de Cross Origin Resource Sharing (CORS) est trop permissive, ce qui peut permettre l'accès non autorisé à des ressources.
  - Référence : https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy
  - Catégorie OWASP : A01:2021 - Broken Access Control
  - Recommandation : Identifier les endpoints réellement destinés à un accès cross-origin et remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.
  - Vérification : Tester les endpoints depuis une origine autorisée et une origine non autorisée.

C - Plan de remédiation
1. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP sans fallback et les ajouter avec des valeurs restrictives — Délai : 30 jours
2. CSP: script-src unsafe-eval : Rechercher les usages de eval, new Function, setTimeout avec chaîne ou équivalent et refactoriser les composants front-end concernés — Délai : 30 jours
3. CSP: script-src unsafe-inline : Identifier les scripts inline et les migrer vers des fichiers JS statiques versionnés — Délai : 30 jours
4. CSP: style-src unsafe-inline : Identifier les styles inline et les déplacer vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
5. Cross-Domain Misconfiguration : Identifier les endpoints réellement destinés à un accès cross-origin et remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée — Délai : 30 jours

D - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire la plus critique est de remédier à la vulnérabilité CSP: Failure to Define Directive with No Fallback, avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d'attaque et protéger les ressources contre les menaces potentielles.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise les vulnérabilités retenues dans le rapport principal après déduplication.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 5 | 2 | 37 |

    
    **Niveau de risque global : MODÉRÉ**

    **Éléments techniques listés en annexe :** 44 | **Vulnérabilités retenues dans le rapport :** 7 | **Prioritaires (section B) :** 5**

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication.*
    

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doubleclick.net; frame-ancestors 'self'; frame-src https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.sched.com https://*.google.com https://*.twitter.com https://www.youtube.com https://w.soundcloud.com https://buttons.github.io; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.youtube.com https://*.meetup.com https://*.sched.com https://*.google-analytics.com https://unpkg.com https://buttons.github.io https://www.google.com https://*.gstatic.com https://*.twitter.com https://*.twimg.com https://www.googletagmanager.com; style-src 'self' 'unsafe-inline' https://*.gstatic.com https://cdnjs.cloudflare.com https://www.google.com https://fonts.googleapis.com https://platform.twitter.com https://*.twimg.com data:; font-src 'self' https://*.fontawesome.com fonts.gstatic.com; manifest-src 'self' https://pay.google.com; img-src 'self' https://*.globalappsec.org https://render.com https://*.render.com https://okteto.com https://*.okteto.com data: www.w3.org https://*.bestpractices.dev https://licensebuttons.net https://img.shields.io https://*.twitter.com https://github.githubassets.com https://*.twimg.com https://platform.twitter.com https://*.githubusercontent.com https://*.vercel.app https://*.cloudfront.net https://*.coreinfrastructure.org https://*.securityknowledgeframework.org https://badges.gitter.im https://travis-ci.org https://api.travis-ci.org https://s3.amazonaws.com https://snyk.io https://coveralls.io https://requires.io https://github.com https://*.googleapis.com https://*.google.com https://*.gstatic.com https://static.scarf.sh | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-eval | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doubleclick.net; frame-ancestors 'self'; frame-src https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.sched.com https://*.google.com https://*.twitter.com https://www.youtube.com https://w.soundcloud.com https://buttons.github.io; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.youtube.com https://*.meetup.com https://*.sched.com https://*.google-analytics.com https://unpkg.com https://buttons.github.io https://www.google.com https://*.gstatic.com https://*.twitter.com https://*.twimg.com https://www.googletagmanager.com; style-src 'self' 'unsafe-inline' https://*.gstatic.com https://cdnjs.cloudflare.com https://www.google.com https://fonts.googleapis.com https://platform.twitter.com https://*.twimg.com data:; font-src 'self' https://*.fontawesome.com fonts.gstatic.com; manifest-src 'self' https://pay.google.com; img-src 'self' https://*.globalappsec.org https://render.com https://*.render.com https://okteto.com https://*.okteto.com data: www.w3.org https://*.bestpractices.dev https://licensebuttons.net https://img.shields.io https://*.twitter.com https://github.githubassets.com https://*.twimg.com https://platform.twitter.com https://*.githubusercontent.com https://*.vercel.app https://*.cloudfront.net https://*.coreinfrastructure.org https://*.securityknowledgeframework.org https://badges.gitter.im https://travis-ci.org https://api.travis-ci.org https://s3.amazonaws.com https://snyk.io https://coveralls.io https://requires.io https://github.com https://*.googleapis.com https://*.google.com https://*.gstatic.com https://static.scarf.sh | 10055-10 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doubleclick.net; frame-ancestors 'self'; frame-src https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.sched.com https://*.google.com https://*.twitter.com https://www.youtube.com https://w.soundcloud.com https://buttons.github.io; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.youtube.com https://*.meetup.com https://*.sched.com https://*.google-analytics.com https://unpkg.com https://buttons.github.io https://www.google.com https://*.gstatic.com https://*.twitter.com https://*.twimg.com https://www.googletagmanager.com; style-src 'self' 'unsafe-inline' https://*.gstatic.com https://cdnjs.cloudflare.com https://www.google.com https://fonts.googleapis.com https://platform.twitter.com https://*.twimg.com data:; font-src 'self' https://*.fontawesome.com fonts.gstatic.com; manifest-src 'self' https://pay.google.com; img-src 'self' https://*.globalappsec.org https://render.com https://*.render.com https://okteto.com https://*.okteto.com data: www.w3.org https://*.bestpractices.dev https://licensebuttons.net https://img.shields.io https://*.twitter.com https://github.githubassets.com https://*.twimg.com https://platform.twitter.com https://*.githubusercontent.com https://*.vercel.app https://*.cloudfront.net https://*.coreinfrastructure.org https://*.securityknowledgeframework.org https://badges.gitter.im https://travis-ci.org https://api.travis-ci.org https://s3.amazonaws.com https://snyk.io https://coveralls.io https://requires.io https://github.com https://*.googleapis.com https://*.google.com https://*.gstatic.com https://static.scarf.sh | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doubleclick.net; frame-ancestors 'self'; frame-src https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.sched.com https://*.google.com https://*.twitter.com https://www.youtube.com https://w.soundcloud.com https://buttons.github.io; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.youtube.com https://*.meetup.com https://*.sched.com https://*.google-analytics.com https://unpkg.com https://buttons.github.io https://www.google.com https://*.gstatic.com https://*.twitter.com https://*.twimg.com https://www.googletagmanager.com; style-src 'self' 'unsafe-inline' https://*.gstatic.com https://cdnjs.cloudflare.com https://www.google.com https://fonts.googleapis.com https://platform.twitter.com https://*.twimg.com data:; font-src 'self' https://*.fontawesome.com fonts.gstatic.com; manifest-src 'self' https://pay.google.com; img-src 'self' https://*.globalappsec.org https://render.com https://*.render.com https://okteto.com https://*.okteto.com data: www.w3.org https://*.bestpractices.dev https://licensebuttons.net https://img.shields.io https://*.twitter.com https://github.githubassets.com https://*.twimg.com https://platform.twitter.com https://*.githubusercontent.com https://*.vercel.app https://*.cloudfront.net https://*.coreinfrastructure.org https://*.securityknowledgeframework.org https://badges.gitter.im https://travis-ci.org https://api.travis-ci.org https://s3.amazonaws.com https://snyk.io https://coveralls.io https://requires.io https://github.com https://*.googleapis.com https://*.google.com https://*.gstatic.com https://static.scarf.sh | 10055-6 | — |
| P3 | vulnerability | medium | Medium | Medium | Cross-Domain Misconfiguration | https://owasp.org/ | Access-Control-Allow-Origin: * | 10098 | — |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://owasp.org/ | <script async src='https://www.google-analytics.com/analytics.js'></script> | 10017 | — |
| P5 | information | info | Informational | Low | Information Disclosure - Suspicious Comments | https://owasp.org/ | from | 10027 | — |
| P5 | information | info | Informational | Medium | Modern Web Application | https://owasp.org/ | <a href="#" class="menu-toggler" aria-hidden="true"> <i class="fa fa-bars"></i> </a> | 10109 | — |
| P5 | information | info | Informational | Low | Re-examine Cache-control Directives | https://owasp.org/ | max-age=600 | 10015 | — |
| P5 | information | info | Informational | Medium | Retrieved from Cache | https://owasp.org/ | HIT | 10050-1 | — |
| P5 | information | info | — | — | Technologie détectée : Amazon S3 | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Amazon Web Services | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Cloudflare | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Fastly | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : GitHub Pages | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : HSTS | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Varnish | https://owasp.org/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | caa-fingerprint | owasp.org | — |  | — |
| P5 | information | info | — | — | csp-script-src-wildcard | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | dkim-record-detect | google._domainkey.owasp.org | "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5isI707a9CxKrh9pFfCqdXsY15Ig8oaPkg4NhsNJskXdJ0zpM5Hes3WH2WxyjzAQfJMh03R8NeY4k5uBN8Vp1vZ6rwB6f34NiGEK6uyDKMEP/ak7CdjmCWK8gnmznDrfK0OJCu+sngzLqQJ1gaXSBbj+XUmazvtoDph6g/Qql+Gj5osAZDLj8ZjQot8/7W1GX" "QHL7J8gSKDyAUMJaagGUglootlWq0IHMjwFHccJp2GyVbgMMOllmVoDTov1kX50cXuoy2nsgDneZISSV7KSOt9bef5AdbfhNeqKHc7B/Z9VleLAP8Ikyn7wun+NjA5eLR1m5GI7a/L484HAaTKxcQIDAQAB"" |  | — |
| P5 | information | info | — | — | dmarc-detect | _dmarc.owasp.org | ""v=DMARC1; p=quarantine; rua=mailto:88b4c392605549efbbfedf60d5b5ba94@dmarc-reports.cloudflare.net,mailto:owasp-dmarc-reports@owasp.com"" |  | — |
| P5 | information | info | — | — | dns-waf-detect:cloudflare | owasp.org | — |  | — |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-digest | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-path | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | fastly-debug-headers:fastly-debug-ttl | https://owasp.org/ | — |  | — |
| P5 | vulnerability | low | — | — | google-calendar-exposure:calendar-url | https://owasp.org/ | https://calendar.google.com/calendar/embed?src=hl6cjgs6ep1h7oniqgueu2bhbo%40group.calendar.google.com&amp;ctz=America%2FChicago |  | — |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://owasp.org/ | — |  | — |
| P5 | information | info | — | — | missing-sri | https://owasp.org/ | https://www.google-analytics.com/analytics.js, https://owasp.org/www--site-theme/assets/js/jquery-3.7.1.min.js, https://owasp.org/www--site-theme/assets/js/util.js, https://owasp.org/www--site-theme/assets/js/yaml.min.js, https://owasp.org/www--site-theme/assets/js/kjua.min.js, https://owasp.org/www--site-theme/assets/js/js.cookie.min.js, https://owasp.org/www--site-theme/assets/css/styles.css |  | — |
| P5 | information | info | — | — | mx-fingerprint | owasp.org | 1 aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 10 alt4.aspmx.l.google.com. |  | — |
| P5 | information | info | — | — | mx-service-detector:Google Apps | owasp.org | — |  | — |
| P5 | information | info | — | — | nameserver-fingerprint | owasp.org | fay.ns.cloudflare.com., west.ns.cloudflare.com. |  | — |
| P5 | information | info | — | — | spf-record-detect | owasp.org | "v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"" |  | — |
| P5 | information | info | — | — | ssl-dns-names | owasp.org:443 | *.owasp.org, owasp.org |  | — |
| P5 | information | info | — | — | ssl-issuer | owasp.org:443 | Google Trust Services |  | — |
| P5 | information | info | — | — | tls-version | owasp.org:443 | tls12 |  | — |
| P5 | information | info | — | — | tls-version | owasp.org:443 | tls13 |  | — |
| P5 | information | info | — | — | txt-fingerprint | owasp.org | ""google-site-verification=I9qx_X9EKlR_rfceG25-iXHBXJvLrmeNbkEdy182iI"",""v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"",""google-site-verification=_slXlbOCopK1Ss9VQEoxdsNxpScVKvXVB_JtPpyL3eQ"",""google-site-verification=hJ9eCIFoexfh1sb-WVBkVB5PEND3JiaojOVyaNpyWK8"",""google-site-verification=kmxuuCvLW4gII8YaV-3ilTOLUvjZa3uaipm0tmpVGpU"",""google-site-verification=ubHJGF1N2ylOhYxQnIzEIIFaqUodqsIdTLXF-rCX9ps"",""MS=ms73859685"",""RrGYbfHtHhF55ld5k5Rw87iuBu7wAWOX4GR9zffrTh4="",""atlassian-domain-verification=BhaFKFKoRcW20xvi6UJ3U0CKocKOCgLH6LSuiBYPQ5A53cSCUN6gcbzcKSOmlVGs"",""google-site-verification=1zT9Of9pBuTj1rgeGCxMbya3iQQMxFE9-DzUBhftUVQ"" |  | — |
| P5 | information | info | — | — | weak-csp-detect:default-src-directive | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doubleclick.net |  | — |
| P5 | information | info | — | — | weak-csp-detect:script-src-directive | https://owasp.org/ | script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.youtube.com https://*.meetup.com https://*.sched.com https://*.google-analytics.com https://unpkg.com https://buttons.github.io https://www.google.com https://*.gstatic.com https://*.twitter.com https://*.twimg.com https://www.googletagmanager.com |  | — |
| P5 | information | info | — | — | wildcard-tls | owasp.org:443 | CN: owasp.org, SAN: [owasp.org *.owasp.org] |  | — |
