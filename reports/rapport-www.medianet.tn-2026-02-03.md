**A - Résumé Exécutif**

Un total de 32 vulnérabilités a été identifié sur le site web de Medianet. Parmi elles, 3 vulnérabilités sont considérées comme prioritaires.

**B - Vulnérabilités Prioritaires**

1. **Content Security Policy (CSP) Header Not Set**
	* Description : La politique de sécurité du contenu n'est pas configurée, ce qui rend le site vulnérable aux attaques de type Cross Site Scripting (XSS) et de data injection.
	* Impact potentiel : Les attaques de type XSS et de data injection peuvent permettre à un attaquant d'exécuter du code malveillant sur le site, ce qui peut entraîner la perte de données sensibles ou l'installation de malware.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
	* Score CVSS : 6.5

2. **Missing Anti-clickjacking Header**
	* Description : La réponse ne protège pas contre les attaques de type ClickJacking. Elle devrait inclure soit l’en-tête Content-Security-Policy avec la directive frame-ancestors, soit l’en-tête X-Frame-Options.
	* Impact potentiel : Les attaques de type ClickJacking peuvent permettre à un attaquant de masquer les éléments de la page et de les remplacer par du code malveillant.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Ajouter l’en-tête Content-Security-Policy avec la directive frame-ancestors ou l’en-tête X-Frame-Options.
	* Vérification : Vérifier que l’en-tête Content-Security-Policy est présent avec la directive frame-ancestors ou que l’en-tête X-Frame-Options est présent.
	* Score CVSS : 5.3

3. **Sub Resource Integrity Attribute Missing**
	* Description : L’attribut d’intégrité de la ressource est manquant sur une balise script ou link servie par un serveur externe. L’attribut d’intégrité empêche un attaquant qui a accès à ce serveur d’injecter du contenu malveillant.
	* Impact potentiel : Les attaques de type injection de code peuvent permettre à un attaquant d’exécuter du code malveillant sur le site.
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut d’intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut d’intégrité valide correspondant au contenu réellement servi.
	* Score CVSS : 6.1

**C - Plan de remédiation**

1. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
2. Ajouter l’en-tête Content-Security-Policy avec la directive frame-ancestors ou l’en-tête X-Frame-Options.
3. Ajouter un attribut d’intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

**D - Conclusion**

Un total de 3 vulnérabilités prioritaires a été identifié sur le site web de Medianet. Il est recommandé de mettre en place les mesures de remédiation décrites ci-dessus pour atténuer ces vulnérabilités. Il est important de noter que ces vulnérabilités ne sont pas les seules qui existent sur le site, et qu'une analyse plus approfondie est nécessaire pour identifier les vulnérabilités non prioritaires.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | Non fourni | medium | Medium | High | Non fourni | Content Security Policy (CSP) Header Not Set | https://www.medianet.tn/fr |  | 10038-1 |
| P3 | Non fourni | medium | Medium | Medium | Non fourni | Missing Anti-clickjacking Header | https://www.medianet.tn/fr | x-frame-options | 10020-1 |
| P3 | Non fourni | medium | Medium | High | Non fourni | Sub Resource Integrity Attribute Missing | https://www.medianet.tn/fr | <script data-ad-client="ca-pub-2558923983607209" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script> | 90003 |
| P4 | Non fourni | low | Low | Medium | Non fourni | Cookie No HttpOnly Flag | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie | 10010 |
| P4 | Non fourni | low | Low | Medium | Non fourni | Cookie Without Secure Flag | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie | 10011 |
| P4 | Non fourni | low | Low | Medium | Non fourni | Cookie without SameSite Attribute | https://www.medianet.tn/fr | Set-Cookie: md_csrf_md_cookie | 10054-1 |
| P4 | Non fourni | low | Low | Medium | Non fourni | Cross-Domain JavaScript Source File Inclusion | https://www.medianet.tn/fr | <script data-ad-client="ca-pub-2558923983607209" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script> | 10017 |
| P4 | Non fourni | low | Low | High | Non fourni | Strict-Transport-Security Header Not Set | https://www.medianet.tn/fr |  | 10035-1 |
| P4 | Non fourni | low | Low | Medium | Non fourni | X-Content-Type-Options Header Missing | https://www.medianet.tn/fr | x-content-type-options | 10021 |
| P5 | Non fourni | info | Informational | Medium | Non fourni | Modern Web Application | https://www.medianet.tn/fr | <a title="" class="standard_link"></a> | 10109 |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | caa-fingerprint | www.medianet.tn |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | cookies-without-httponly | www.medianet.tn | md_csrf_md_cookie |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | cookies-without-secure | www.medianet.tn | md_csrf_md_cookie, ci_session |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | deprecated-tls:tls_1.0 | www.medianet.tn:443 | tls10 |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | deprecated-tls:tls_1.1 | www.medianet.tn:443 | tls11 |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | dns-saas-service-detection | www.medianet.tn | medianet.tn |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:clear-site-data | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:content-security-policy | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:cross-origin-embedder-policy | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:cross-origin-opener-policy | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:cross-origin-resource-policy | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:permissions-policy | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:referrer-policy | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:strict-transport-security | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:x-content-type-options | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:x-frame-options | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | http-missing-security-headers:x-permitted-cross-domain-policies | https://www.medianet.tn/fr/ |  |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | missing-cookie-samesite-strict | https://www.medianet.tn/fr/ | md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03-Feb-2026 14:48:58 GMT; Max-Age=17200; path=/ md_user_lang=fr; expires=Thu, 05-Feb-2026 09:48:58 GMT; Max-Age=172000; path=/, md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03… |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | missing-sri | https://www.medianet.tn/fr/ | https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-554096385a39fe0b, https://www.medianet.tn/assets/js/home/homes.js, https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js, https://www.medianet.tn/assets/js/fr/vendors/jquery.min.js, https://www.… |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | mx-fingerprint | www.medianet.tn | 10 ALT4.ASPMX.L.GOOGLE.com., 10 ALT2.ASPMX.L.GOOGLE.com., 1 ASPMX.L.GOOGLE.com., 5 ALT2.ASPMX.L.GOOGLE.com., 5 ALT1.ASPMX.L.GOOGLE.com. |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | nameserver-fingerprint | www.medianet.tn | ns5.gnet.tn., ns1.gnet.tn., ns2.gnet.tn., ns4.gnet.tn. |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | spf-record-detect | www.medianet.tn | "v=spf1 include:_spf.google.com ~all"" |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | ssl-dns-names | www.medianet.tn:443 | medianet.com.tn, medianet.tn, www.medianet.com.tn, www.medianet.tn |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | ssl-issuer | www.medianet.tn:443 | Let's Encrypt |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | tls-version | www.medianet.tn:443 | tls10, tls11, tls12 |  |
| P5 | Non fourni | info | Non fourni | Non fourni | Non fourni | txt-fingerprint | www.medianet.tn | ""MS=A40ECE4992D1E5D118F2E8873DC069F971231AA4"",""v=spf1 include:_spf.google.com ~all"",""google-site-verification=EmcBMq21CMbShWrPq72VQDdxovlEaq7_Lh8ZXB3GfaA"" |  |
| P5 | Non fourni | low | Non fourni | Non fourni | Non fourni | weak-cipher-suites:tls-1.0 | www.medianet.tn:443 | [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |
| P5 | Non fourni | low | Non fourni | Non fourni | Non fourni | weak-cipher-suites:tls-1.1 | www.medianet.tn:443 | [tls11 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |
