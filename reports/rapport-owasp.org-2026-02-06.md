**A - Résumé Exécutif**

Un total de 11 vulnérabilités a été identifié sur le système cible. Parmi celles-ci, 5 sont considérées comme prioritaires. Le nombre total de vulnérabilités est supérieur à zéro.

**B - Vulnérabilités Prioritaires**

1. **CSP: Failure to Define Directive with No Fallback**
	* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive qui n'a pas de fallback. Cela signifie que les directives manquantes ou exclues sont considérées comme autorisant tout.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
	* Vérification : Exécuter curl -I sur plusieurs pages HTML et vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

2. **CSP: script-src unsafe-eval**
	* Description : La politique de sécurité du contenu (CSP) inclut l'utilisation de eval, new Function ou setTimeout avec chaîne.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Rechercher dans le code et les dépendances les usages de eval, new Function, setTimeout avec chaîne ou équivalent.
	* Vérification : Vérifier que la directive script-src ne contient plus unsafe-eval.

3. **CSP: script-src unsafe-inline**
	* Description : La politique de sécurité du contenu (CSP) inclut l'utilisation d'instructions JavaScript inline.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Identifier tous les scripts inline présents dans les templates HTML.
	* Vérification : Contrôler que script-src ne contient plus unsafe-inline.

4. **CSP: style-src unsafe-inline**
	* Description : La politique de sécurité du contenu (CSP) inclut l'utilisation d'instructions CSS inline.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Identifier les styles inline dans les templates et composants front-end.
	* Vérification : Contrôler le rendu visuel des pages après externalisation des styles.

5. **Cross-Domain Misconfiguration**
	* Description : Une configuration de Cross-Origin Resource Sharing (CORS) trop permissive sur le serveur web peut permettre aux navigateurs d'accéder à des données sans autorisation.
	* Référence : https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.
	* Vérification : Tester les endpoints depuis une origine autorisée et une origine non autorisée.

**C - Plan de remédiation**

1. CSP: Failure to Define Directive with No Fallback
	* Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
2. CSP: script-src unsafe-eval
	* Rechercher dans le code et les dépendances les usages de eval, new Function, setTimeout avec chaîne ou équivalent.
3. CSP: script-src unsafe-inline
	* Identifier tous les scripts inline présents dans les templates HTML.
4. CSP: style-src unsafe-inline
	* Identifier les styles inline dans les templates et composants front-end.
5. Cross-Domain Misconfiguration
	* Remplacer Access-Control-Allow-Origin: * par une liste blanche contrôlée.

**D - Conclusion**

Un total de 11 vulnérabilités a été identifié sur le système cible, dont 5 sont considérées comme prioritaires. Il est recommandé d'appliquer les mesures de remédiation décrites ci-dessus pour corriger ces vulnérabilités.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-13 |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-eval | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-10 |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-5 |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… | 10055-6 |
| P3 | vulnerability | medium | Medium | Medium | Cross-Domain Misconfiguration | https://owasp.org/ | Access-Control-Allow-Origin: * | 10098 |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://owasp.org/ | <script async src='https://www.google-analytics.com/analytics.js'></script> | 10017 |
| P5 | information | info | Informational | Medium | Modern Web Application | https://owasp.org/ | <a href="#" class="menu-toggler" aria-hidden="true"> <i class="fa fa-bars"></i> </a> | 10109 |
| P5 | information | info | Informational | Medium | Retrieved from Cache | https://owasp.org/ | HIT | 10050-1 |
| P5 | information | info | Non fourni | Non fourni | caa-fingerprint | owasp.org |  |  |
| P5 | information | info | Non fourni | Non fourni | csp-script-src-wildcard | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | dkim-record-detect | google._domainkey.owasp.org | "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5isI707a9CxKrh9pFfCqdXsY15Ig8oaPkg4NhsNJskXdJ0zpM5Hes3WH2WxyjzAQfJMh03R8NeY4k5uBN8Vp1vZ6rwB6f34NiGEK6uyDKMEP/ak7CdjmCWK8gnmznDrfK0OJCu+sngzLqQJ1gaXSBbj+XUmazvtoDph6g/Qql+Gj5osAZDLj8ZjQot8/7W1GX" "Q… |  |
| P5 | information | info | Non fourni | Non fourni | dmarc-detect | _dmarc.owasp.org | ""v=DMARC1; p=quarantine; rua=mailto:88b4c392605549efbbfedf60d5b5ba94@dmarc-reports.cloudflare.net,mailto:owasp-dmarc-reports@owasp.com"" |  |
| P5 | information | info | Non fourni | Non fourni | dns-waf-detect:cloudflare | owasp.org |  |  |
| P5 | information | info | Non fourni | Non fourni | fastly-debug-headers:fastly-debug-digest | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | fastly-debug-headers:fastly-debug-path | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | fastly-debug-headers:fastly-debug-ttl | https://owasp.org/ |  |  |
| P5 | vulnerability | low | Non fourni | Non fourni | google-calendar-exposure:calendar-url | https://owasp.org/ | https://calendar.google.com/calendar/embed?src=hl6cjgs6ep1h7oniqgueu2bhbo%40group.calendar.google.com&amp;ctz=America%2FChicago |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:clear-site-data | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:cross-origin-embedder-policy | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:cross-origin-opener-policy | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:cross-origin-resource-policy | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | http-missing-security-headers:x-permitted-cross-domain-policies | https://owasp.org/ |  |  |
| P5 | information | info | Non fourni | Non fourni | missing-sri | https://owasp.org/ | https://www.google-analytics.com/analytics.js, https://owasp.org/www--site-theme/assets/js/jquery-3.7.1.min.js, https://owasp.org/www--site-theme/assets/js/util.js, https://owasp.org/www--site-theme/assets/js/yaml.min.js, https://owasp.org/www--site-theme/asse… |  |
| P5 | information | info | Non fourni | Non fourni | mx-fingerprint | owasp.org | 1 aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 10 alt4.aspmx.l.google.com. |  |
| P5 | information | info | Non fourni | Non fourni | mx-service-detector:Google Apps | owasp.org |  |  |
| P5 | information | info | Non fourni | Non fourni | nameserver-fingerprint | owasp.org | fay.ns.cloudflare.com., west.ns.cloudflare.com. |  |
| P5 | information | info | Non fourni | Non fourni | spf-record-detect | owasp.org | "v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"" |  |
| P5 | information | info | Non fourni | Non fourni | ssl-dns-names | owasp.org:443 | *.owasp.org, owasp.org |  |
| P5 | information | info | Non fourni | Non fourni | ssl-issuer | owasp.org:443 | Google Trust Services |  |
| P5 | information | info | Non fourni | Non fourni | tls-version | owasp.org:443 | tls12, tls13 |  |
| P5 | information | info | Non fourni | Non fourni | txt-fingerprint | owasp.org | ""google-site-verification=I9qx_X9EKlR_rfceG25-iXHBXJvLrmeNbkEdy182iI"",""v=spf1 include:_spf.google.com include:servers.mcsv.net include:amazonses.com -all"",""google-site-verification=_slXlbOCopK1Ss9VQEoxdsNxpScVKvXVB_JtPpyL3eQ"",""google-site-verification=h… |  |
| P5 | information | info | Non fourni | Non fourni | weak-csp-detect:default-src-directive | https://owasp.org/ | default-src 'self' https://*.fontawesome.com https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doublecli… |  |
| P5 | information | info | Non fourni | Non fourni | weak-csp-detect:script-src-directive | https://owasp.org/ | script-src 'self' 'unsafe-inline' 'unsafe-eval' https://viewer.diagrams.net https://fonts.googleapis.com https://*.fontawesome.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.w… |  |
| P5 | information | info | Non fourni | Non fourni | wildcard-tls | owasp.org:443 | CN: owasp.org, SAN: [owasp.org *.owasp.org] |  |
