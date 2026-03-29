A - Résumé Exécutif

38 vulnérabilités ont été identifiées au total, dont 3 sont prioritaires.

B - Vulnérabilités Prioritaires

**Content Security Policy (CSP) Header Not Set**
* Description : La politique de sécurité du contenu n'est pas définie. Cela signifie que les attaques XSS et d'injection de données ne peuvent pas être détectées ou mises en échec.
* Référence :
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir une politique CSP de base avec default-src 'self'. Déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors. Éviter unsafe-inline et unsafe-eval sauf contrainte technique clairement identifiée.
* Vérification : Exécuter curl -I sur plusieurs pages HTML. Contrôler la présence de l’en-tête Content-Security-Policy.

**Missing Anti-clickjacking Header**
* Description : La réponse ne protège pas contre les attaques 'ClickJacking'. Elle devrait inclure soit une politique CSP avec la directive 'frame-ancestors' ou X-Frame-Options.
* Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet. Si CSP est utilisée, définir explicitement frame-ancestors avec une valeur restrictive.
* Vérification : Exécuter curl -I sur plusieurs pages HTML. Contrôler la présence de X-Frame-Options ou de frame-ancestors.

**Sub Resource Integrity Attribute Missing**
* Description : L'attribut d'intégrité est manquant sur un script ou une balise link servie par un serveur externe. Cet attribut empêche un attaquant qui a accédé à ce serveur de injecter du contenu malveillant.
* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Identifier les scripts et feuilles CSS chargés depuis des domaines externes. Ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées. Héberger localement les ressources externes critiques si leur contenu varie fréquemment. Réduire le nombre de dépendances tierces non indispensables.
* Vérification : Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity='. Vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

C - Plan de remédiation

1. **Content Security Policy (CSP) Header Not Set** : Définir une politique CSP de base avec default-src 'self'. Déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.
2. **Missing Anti-clickjacking Header** : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet. Si CSP est utilisée, définir explicitement frame-ancestors avec une valeur restrictive.
3. **Sub Resource Integrity Attribute Missing** : Ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.

D - Conclusion

Le niveau de risque global est MODÉRÉ. Une action immédiate est requise pour définir la politique CSP et ajouter l'attribut d'intégrité aux balises script et link externes. Les corrections doivent être effectuées dans les 7 jours.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 3 | 8 | 27 |

    **Total :** 38 | **Prioritaires :** 3
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | Content Security Policy (CSP) Header Not Set | https://www.medianet.tn/fr | — | 10038-1 |  |
| P3 | vulnerability | medium | Medium | Medium | Missing Anti-clickjacking Header | https://www.medianet.tn/fr | x-frame-options | 10020-1 |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://www.medianet.tn/fr | <script data-ad-client="ca-pub-2558923983607209" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script> | 90003 |  |
| P4 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie | 10010 |  |
| P4 | vulnerability | low | Low | Medium | Cookie Without Secure Flag | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie | 10011 |  |
| P4 | vulnerability | low | Low | Medium | Cookie without SameSite Attribute | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie | 10054-1 |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.medianet.tn/fr | <script data-ad-client="ca-pub-2558923983607209" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script> | 10017 |  |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://www.medianet.tn/fr | — | 10035-1 |  |
| P4 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | https://www.medianet.tn/fr | x-content-type-options | 10021 |  |
| P5 | information | info | Informational | Medium | Modern Web Application | https://www.medianet.tn/fr | <a title="" class="standard_link"></a> | 10109 |  |
| P5 | information | info | — | — | caa-fingerprint | www.medianet.tn | — |  |  |
| P5 | information | info | — | — | cookies-without-httponly | www.medianet.tn | md_csrf_md_cookie |  |  |
| P5 | information | info | — | — | cookies-without-secure | www.medianet.tn | md_csrf_md_cookie, ci_session |  |  |
| P5 | information | info | — | — | deprecated-tls:tls_1.0 | www.medianet.tn:443 | tls10 |  |  |
| P5 | information | info | — | — | deprecated-tls:tls_1.1 | www.medianet.tn:443 | tls11 |  |  |
| P5 | information | info | — | — | dns-saas-service-detection | www.medianet.tn | medianet.tn |  |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:content-security-policy | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:permissions-policy | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:referrer-policy | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:strict-transport-security | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:x-content-type-options | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:x-frame-options | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://www.medianet.tn/fr/ | — |  |  |
| P5 | information | info | — | — | missing-cookie-samesite-strict | https://www.medianet.tn/fr/ | md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03-Feb-2026 14:48:58 GMT; Max-Age=17200; path=/ md_user_lang=fr; expires=Thu, 05-Feb-2026 09:48:58 GMT; Max-Age=172000; path=/, md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03… |  |  |
| P5 | information | info | — | — | missing-sri | https://www.medianet.tn/fr/ | https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-554096385a39fe0b, https://www.medianet.tn/assets/js/home/homes.js, https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js, https://www.medianet.tn/assets/js/fr/vendors/jquery.min.js, https://www.… |  |  |
| P5 | information | info | — | — | mx-fingerprint | www.medianet.tn | 10 ALT4.ASPMX.L.GOOGLE.com., 10 ALT2.ASPMX.L.GOOGLE.com., 1 ASPMX.L.GOOGLE.com., 5 ALT2.ASPMX.L.GOOGLE.com., 5 ALT1.ASPMX.L.GOOGLE.com. |  |  |
| P5 | information | info | — | — | nameserver-fingerprint | www.medianet.tn | ns5.gnet.tn., ns1.gnet.tn., ns2.gnet.tn., ns4.gnet.tn. |  |  |
| P5 | information | info | — | — | spf-record-detect | www.medianet.tn | "v=spf1 include:_spf.google.com ~all"" |  |  |
| P5 | information | info | — | — | ssl-dns-names | www.medianet.tn:443 | medianet.com.tn, medianet.tn, www.medianet.com.tn, www.medianet.tn |  |  |
| P5 | information | info | — | — | ssl-issuer | www.medianet.tn:443 | Let's Encrypt |  |  |
| P5 | information | info | — | — | tls-version | www.medianet.tn:443 | tls10, tls11, tls12 |  |  |
| P5 | information | info | — | — | txt-fingerprint | www.medianet.tn | ""MS=A40ECE4992D1E5D118F2E8873DC069F971231AA4"",""v=spf1 include:_spf.google.com ~all"",""google-site-verification=EmcBMq21CMbShWrPq72VQDdxovlEaq7_Lh8ZXB3GfaA"" |  |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.0 | www.medianet.tn:443 | [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.1 | www.medianet.tn:443 | [tls11 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |  |
