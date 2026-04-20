A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 12 vulnérabilités ont été retenues dans ce rapport, dont 3 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.medianet.tn/ (inconnu Non fourni). Scan du : 2026-02-03 10:02:34 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client, notamment l'absence de Content Security Policy (CSP), l'attribut Sub Resource Integrity manquant et l'en-tête anti-clickjacking absent.

B - Vulnérabilités Prioritaires
Content Security Policy (CSP) Header Not Set
- Description : La politique de sécurité de contenu (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certains types d'attaques, notamment les attaques de scriptage intersite (XSS) et les attaques d'injection de données.
- Référence : 
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, contrôler la présence de l'en-tête Content-Security-Policy et tester l'application pour détecter d'éventuelles régressions fonctionnelles liées à la CSP.

Sub Resource Integrity Attribute Missing
- Description : L'attribut d'intégrité des ressources est manquant sur une balise script ou link servie par un serveur externe.
- Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter l'attribut integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
- Vérification : Inspecter le code source HTML : curl -s https://[site] | grep -i 'integrity=', vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

Missing Anti-clickjacking Header
  - Paramètre/Ressource affecté(e) : x-frame-options
- Description : La réponse ne protège pas contre les attaques de clickjacking.
- Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options, contrôler la présence de X-Frame-Options ou de frame-ancestors dans la CSP.

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider n'a été identifiée.

D - Plan de remédiation
1. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' — Délai : 30 jours
2. Sub Resource Integrity Attribute Missing : Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter l'attribut integrity et crossorigin=\"anonymous\" — Délai : 30 jours
3. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de définir une politique CSP de base avec default-src 'self' pour atténuer les risques liés à la sécurité côté client, avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d'attaque côté navigateur et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 3 | 9 | 21 |

    **Niveau de risque global : MODÉRÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 12  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 21  
    **Prioritaires confirmées (section B) :** 3 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | — | 10035-1 |
| P4 | vulnerability | low | Low | Low | Timestamp Disclosure - Unix | 1766420159, 1769691334, 1769695547 | 10096 |
| P5 | vulnerability | low | Low | Medium | Cookie No HttpOnly Flag | Set-Cookie: md_csrf_md_cookie, Set-Cookie: md_user_lang | 10010 |
| P5 | vulnerability | low | Low | Medium | Cookie Without Secure Flag | Set-Cookie: md_csrf_md_cookie, Set-Cookie: ci_session, Set-Cookie: md_user_lang | 10011 |
| P5 | vulnerability | low | Low | Medium | Cookie without SameSite Attribute | Set-Cookie: md_csrf_md_cookie, Set-Cookie: ci_session, Set-Cookie: md_user_lang | 10054-1 |
| P5 | information | info | Informational | Medium | Modern Web Application | <a title="" class="standard_link"></a> | 10109 |
| P5 | information | info | — | — | Technologie détectée : Apache HTTP Server | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : CodeIgniter | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Google Tag Manager | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : PHP | Version non fournie |  |
| P5 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | — | 10021 |
| P5 | information | info | — | — | caa-fingerprint | — |  |
| P5 | information | info | — | — | cookies-without-httponly | md_csrf_md_cookie |  |
| P5 | information | info | — | — | cookies-without-secure | md_csrf_md_cookie, ci_session |  |
| P5 | information | info | — | — | deprecated-tls:tls_1.0 | tls10 |  |
| P5 | information | info | — | — | deprecated-tls:tls_1.1 | tls11 |  |
| P5 | information | info | — | — | dns-saas-service-detection | medianet.tn |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | — |  |
| P5 | information | info | — | — | http-missing-security-headers:content-security-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:permissions-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:referrer-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:x-content-type-options | — |  |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | — |  |
| P5 | information | info | — | — | missing-cookie-samesite-strict | md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03-Feb-2026 14:48:58 GMT; Max-Age=17200; path=/ md_user_lang=fr; expires=Thu, 05-Feb-2026 09:48:58 GMT; Max-Age=172… |  |
| P5 | information | info | — | — | missing-sri | https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-554096385a39fe0b, https://www.medianet.tn/assets/js/home/homes.js, https://pagead2.googlesyndication.com/pagead/js/adsbygoo… |  |
| P5 | information | info | — | — | mx-fingerprint | 10 ALT4.ASPMX.L.GOOGLE.com., 10 ALT2.ASPMX.L.GOOGLE.com., 1 ASPMX.L.GOOGLE.com., 5 ALT2.ASPMX.L.GOOGLE.com., 5 ALT1.ASPMX.L.GOOGLE.com. |  |
| P5 | information | info | — | — | nameserver-fingerprint | ns5.gnet.tn., ns1.gnet.tn., ns2.gnet.tn., ns4.gnet.tn. |  |
| P5 | information | info | — | — | spf-record-detect | "v=spf1 include:_spf.google.com ~all"" |  |
| P5 | information | info | — | — | ssl-dns-names | medianet.com.tn, medianet.tn, www.medianet.com.tn, www.medianet.tn |  |
| P5 | information | info | — | — | ssl-issuer | Let's Encrypt |  |
| P5 | information | info | — | — | tls-version | tls10 |  |
| P5 | information | info | — | — | txt-fingerprint | ""MS=A40ECE4992D1E5D118F2E8873DC069F971231AA4"",""v=spf1 include:_spf.google.com ~all"",""google-site-verification=EmcBMq21CMbShWrPq72VQDdxovlEaq7_Lh8ZXB3GfaA"" |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.0 | [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.1 | [tls11 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |
