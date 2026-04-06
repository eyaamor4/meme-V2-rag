A - Résumé Exécutif
7 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires. La présence de plusieurs vulnérabilités liées à la politique de sécurité de contenu (CSP) amplifie la surface d'attaque XSS, ce qui rend le risque combiné plus élevé.

B - Vulnérabilités Prioritaires
**CSP: Failure to Define Directive with No Fallback**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) ne définit pas une directive essentielle sans fallback, ce qui équivaut à autoriser n'importe quelle source.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.
  - Contrôler dans les outils navigateur que les violations CSP sont bien remontées.

**CSP: script-src unsafe-eval**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) autorise l'exécution dynamique de code via la directive script-src avec l'option unsafe-eval.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Rechercher les usages de eval, new Function, setTimeout avec chaîne ou équivalent dans le code et les dépendances, et refactoriser les composants front-end concernés pour éviter l’exécution dynamique de code.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier que script-src ne contient plus unsafe-eval.
  - Tester les fonctionnalités front-end dynamiques susceptibles d'utiliser eval.

**CSP: script-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) autorise l'exécution de scripts inline via la directive script-src avec l'option unsafe-inline.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés lorsque possible.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier que script-src ne contient plus unsafe-inline.
  - Contrôler dans le HTML que les scripts inline restants portent un nonce ou hash valide.

**CSP: style-src unsafe-inline**
* **Paramètre/Ressource affecté(e) :** `Content-Security-Policy`
* Description : La politique de sécurité de contenu (CSP) autorise l'injection de styles inline via la directive style-src avec l'option unsafe-inline.
* Référence : 
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : 
  - Exécuter curl -I https://[site] | grep -i content-security-policy
  - Vérifier que style-src ne contient plus unsafe-inline.
  - Contrôler le rendu visuel des pages après externalisation des styles.

**Cross-Domain Misconfiguration**
* Description : La configuration de partage de ressources cross-domain (CORS) est trop permissive, permettant potentiellement des attaques de type Cross-Site Request Forgery (CSRF) ou d'injection de données.
* Référence : https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Identifier les endpoints réellement destinés à un accès cross-origin et remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.
* Vérification : 
  - Tester les endpoints depuis une origine autorisée et une origine non autorisée.
  - Vérifier qu’une origine arbitraire ne reçoit plus de réponse CORS valide.
  - Contrôler les endpoints contenant des données métiers ou identifiants.

C - Plan de remédiation
1. **CSP: Failure to Define Directive with No Fallback** : Ajouter les directives manquantes avec des valeurs restrictives.
2. **CSP: script-src unsafe-eval** : Refactoriser les composants front-end pour éviter l’exécution dynamique de code.
3. **CSP: script-src unsafe-inline** : Migrer les scripts inline vers des fichiers JS statiques versionnés.
4. **CSP: style-src unsafe-inline** : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
5. **Cross-Domain Misconfiguration** : Remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.

D - Conclusion
Le niveau de risque global est MODÉRÉ. L'action prioritaire la plus critique est de remédier à la vulnérabilité **CSP: Failure to Define Directive with No Fallback** pour réduire la surface d'attaque XSS. Il est recommandé de traiter ces vulnérabilités dans les 30 jours.


## Tableau de synthèse des vulnérabilités

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 5 | 2 | 36 |

**Éléments techniques listés en annexe :** 43 | **Vulnérabilités retenues dans le rapport :** 7 | **Prioritaires (section B) :** 5


## Annexe A - Vulnérabilités potentielles détectées mais non retenues dans le total principal (version non confirmée)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-13 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-eval | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-10 | — |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-5 | — |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-6 | — |
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
| P5 | information | info | — | — | dkim-record-detect | google._domainkey.owasp.org | "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5isI707a9CxKrh9pFfCqdXsY15Ig8oaPkg4NhsNJskXdJ0zpM5Hes3WH2WxyjzAQfJMh03R8NeY4k5uBN8Vp1vZ6rwB6f34NiGEK6uyDKMEP/ak7CdjmCWK8gnmznDrfK0OJCu+sngzLqQJ1gaXSBbj+XUmazvtoDph6g/Qql+Gj5osAZDLj8ZjQot8/7W1GX" "Q… |  | — |
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
| P5 | information | info | — | — | missing-sri | https://owasp.org/ | https://www.google-analytics.com/analytics.js, https://owasp.org/www--site-theme/assets/js/jquery-3.7.1.min.js, https://owasp.org/www--site-theme/assets/js/util.js, https://owasp.org/www--site-theme/assets/js/yaml.min.js, https://owasp.org/www--site-theme/asse… |  | — |
| P5 | information | info | — | — | mx-fingerprint | owasp.org | 1 aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 10 alt4.aspmx.l.google.com. |  | — |
| P5 | information | info | — | — | mx-service-detector:Google Apps | owasp.org | — |  | — |
| P5 | information | info | — | — | nameserver-fingerprint | owasp.org | fay.ns.cloudflare.com., west.ns.cloudflare.com. |  | — |
| P5 | information | info | — | — | spf-record-detect | owasp.org | "v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"" |  | — |
| P5 | information | info | — | — | ssl-dns-names | owasp.org:443 | *.owasp.org, owasp.org |  | — |
| P5 | information | info | — | — | ssl-issuer | owasp.org:443 | Google Trust Services |  | — |
| P5 | information | info | — | — | tls-version | owasp.org:443 | tls12, tls13 |  | — |
| P5 | information | info | — | — | txt-fingerprint | owasp.org | ""google-site-verification=I9qx_X9EKlR_rfceG25-iXHBXJvLrmeNbkEdy182iI"",""v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"",""google-site-verification=_slXlbOCopK1Ss9VQEoxdsNxpScVKvXVB_JtPpyL3eQ"",""google-site-verification=h… |  | — |
| P5 | information | info | — | — | weak-csp-detect:default-src-directive | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… |  | — |
| P5 | information | info | — | — | weak-csp-detect:script-src-directive | https://owasp.org/ | script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.w… |  | — |
| P5 | information | info | — | — | wildcard-tls | owasp.org:443 | CN: owasp.org, SAN: [owasp.org *.owasp.org] |  | — |
