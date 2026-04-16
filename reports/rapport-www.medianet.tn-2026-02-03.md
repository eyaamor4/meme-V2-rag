A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 12 vulnérabilités ont été retenues dans ce rapport, dont 3 sont prioritaires.
Le rapport s'appuie sur 46 findings techniques dédupliqués au total, incluant les vulnérabilités retenues et, le cas échéant, des éléments informationnels.
Niveau de risque global : MODÉRÉ. Niveau source déclaré : medium. Cible : https://www.medianet.tn/ (inconnu Non fourni). Scan du : 2026-02-03 10:02:34 UTC.

B - Vulnérabilités Prioritaires
- Content Security Policy (CSP) Header Not Set
  - Description : Le header Content Security Policy (CSP) n'est pas défini, ce qui expose le site à des attaques de type Cross Site Scripting (XSS) et d'injection de données.
  - Référence : 
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
    - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
    - https://www.w3.org/TR/CSP/
    - https://w3c.github.io/webappsec-csp/
    - https://web.dev/articles/csp
    - https://caniuse.com/#feat=contentsecuritypolicy
    - https://content-security-policy.com/
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Recommandation : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, Contrôler la présence de l'en-tête Content-Security-Policy, Tester l'application pour détecter d'éventuelles régressions fonctionnelles liées à la CSP.
- Missing Anti-clickjacking Header
* **Paramètre/Ressource affecté(e) :** `x-frame-options`
  - Description : La réponse ne protège pas contre les attaques de type ClickJacking, car elle ne contient pas de header X-Frame-Options ou de directive frame-ancestors dans la politique de sécurité du contenu.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet, ou définir explicitement frame-ancestors avec une valeur restrictive si la politique de sécurité du contenu est utilisée.
  - Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options, Contrôler la présence de X-Frame-Options ou de frame-ancestors dans la CSP, Tester l'intégration de la page dans une iframe depuis un domaine tiers.
- Sub Resource Integrity Attribute Missing
  - Description : L'attribut d'intégrité des ressources est manquant sur une balise script ou link servie par un serveur externe, ce qui permet à un attaquant ayant accès à ce serveur d'injecter du contenu malveillant.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
  - Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes, ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées, héberger localement les ressources externes critiques si leur contenu varie fréquemment.
  - Vérification : Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity=', Vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin, Recalculer le hash en cas de mise à jour de la dépendance.

C - Plan de remédiation
1. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires — Délai : 30 jours
2. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 30 jours
3. Sub Resource Integrity Attribute Missing : Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter l'attribut integrity — Délai : 30 jours

D - Conclusion
Le niveau de risque global est MODÉRÉ.
Le niveau brut source déclaré est medium.
L'action prioritaire la plus critique est de définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires, avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour assurer la sécurité du site web.


## Tableau de synthèse des vulnérabilités

> **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités retenues dans le rapport principal après déduplication.
> Les éléments informationnels sont comptabilisés séparément.

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 3 | 9 | 21 |

**Niveau de risque global : MODÉRÉ**

**Findings techniques dédupliqués (total) :** 46  
**Faiblesses et vulnérabilités retenues dans le rapport :** 12
**Éléments informationnels :** 21  
**Prioritaires (section B) :** 3  

> ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*


## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://www.medianet.tn/fr | <script data-ad-client="ca-pub-2558923983607209" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>, <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>, <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>, <script type="text/javascript" src="https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-554096385a39fe0b"></script> | 10017 | — |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://www.medianet.tn/fr | — | 10035-1 | — |
| P4 | vulnerability | low | Low | Low | Timestamp Disclosure - Unix | https://www.medianet.tn/fr | 1766420159, 1769691334, 1769695547 | 10096 | — |
| P5 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie, Set-Cookie: md_user_lang | 10010 | — |
| P5 | vulnerability | low | Low | Medium | Cookie Without Secure Flag | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie, Set-Cookie: ci_session, Set-Cookie: md_user_lang | 10011 | — |
| P5 | vulnerability | low | Low | Medium | Cookie without SameSite Attribute | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie, Set-Cookie: ci_session, Set-Cookie: md_user_lang | 10054-1 | — |
| P5 | information | info | Informational | Medium | Modern Web Application | https://www.medianet.tn/fr | <a title="" class="standard_link"></a> | 10109 | — |
| P5 | information | info | — | — | Technologie détectée : Apache HTTP Server | https://www.medianet.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : CodeIgniter | https://www.medianet.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | https://www.medianet.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | information | info | — | — | Technologie détectée : PHP | https://www.medianet.tn/ | Version non fournie |  | Technologie détectée via Webanalyze |
| P5 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | https://www.medianet.tn/fr | — | 10021 | — |
| P5 | information | info | — | — | caa-fingerprint | www.medianet.tn | — |  | — |
| P5 | information | info | — | — | cookies-without-httponly | www.medianet.tn | md_csrf_md_cookie |  | — |
| P5 | information | info | — | — | cookies-without-secure | www.medianet.tn | md_csrf_md_cookie, ci_session |  | — |
| P5 | information | info | — | — | deprecated-tls:tls_1.0 | www.medianet.tn:443 | tls10 |  | — |
| P5 | information | info | — | — | deprecated-tls:tls_1.1 | www.medianet.tn:443 | tls11 |  | — |
| P5 | information | info | — | — | dns-saas-service-detection | www.medianet.tn | medianet.tn |  | — |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:content-security-policy | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:permissions-policy | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:referrer-policy | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:x-content-type-options | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://www.medianet.tn/fr/ | — |  | — |
| P5 | information | info | — | — | missing-cookie-samesite-strict | https://www.medianet.tn/fr/ | md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03-Feb-2026 14:48:58 GMT; Max-Age=17200; path=/ md_user_lang=fr; expires=Thu, 05-Feb-2026 09:48:58 GMT; Max-Age=172000; path=/ |  | — |
| P5 | information | info | — | — | missing-sri | https://www.medianet.tn/fr/ | https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-554096385a39fe0b, https://www.medianet.tn/assets/js/home/homes.js, https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js, https://www.medianet.tn/assets/js/fr/vendors/jquery.min.js, https://www.medianet.tn/assets/js/fr/vendors/built.min.js, https://www.medianet.tn/assets/fr/css/built.min.css, https://fonts.googleapis.com/css?family=Roboto:100,100i,300,300i,400,400i,500,500i,700,700i,900,900i&display=swap |  | — |
| P5 | information | info | — | — | mx-fingerprint | www.medianet.tn | 10 ALT4.ASPMX.L.GOOGLE.com., 10 ALT2.ASPMX.L.GOOGLE.com., 1 ASPMX.L.GOOGLE.com., 5 ALT2.ASPMX.L.GOOGLE.com., 5 ALT1.ASPMX.L.GOOGLE.com. |  | — |
| P5 | information | info | — | — | nameserver-fingerprint | www.medianet.tn | ns5.gnet.tn., ns1.gnet.tn., ns2.gnet.tn., ns4.gnet.tn. |  | — |
| P5 | information | info | — | — | spf-record-detect | www.medianet.tn | "v=spf1 include:_spf.google.com ~all"" |  | — |
| P5 | information | info | — | — | ssl-dns-names | www.medianet.tn:443 | medianet.com.tn, medianet.tn, www.medianet.com.tn, www.medianet.tn |  | — |
| P5 | information | info | — | — | ssl-issuer | www.medianet.tn:443 | Let's Encrypt |  | — |
| P5 | information | info | — | — | tls-version | www.medianet.tn:443 | tls10 |  | — |
| P5 | information | info | — | — | txt-fingerprint | www.medianet.tn | ""MS=A40ECE4992D1E5D118F2E8873DC069F971231AA4"",""v=spf1 include:_spf.google.com ~all"",""google-site-verification=EmcBMq21CMbShWrPq72VQDdxovlEaq7_Lh8ZXB3GfaA"" |  | — |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.0 | www.medianet.tn:443 | [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  | — |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.1 | www.medianet.tn:443 | [tls11 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  | — |
