A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 12 vulnérabilités ont été retenues dans ce rapport, dont 3 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.medianet.tn/ (inconnu Non fourni). Scan du : 2026-02-03 10:02:34 UTC.
La surface d’attaque côté navigateur est élargie.

B - Vulnérabilités Prioritaires
[Content Security Policy (CSP) Header Not Set]
- Description : Content Security Policy (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certains types d'attaques, notamment les attaques de scriptage inter-site (XSS) et les attaques d'injection de données. Ces attaques sont utilisées pour tout, depuis le vol de données jusqu'à la modification du site ou la distribution de logiciels malveillants. CSP fournit un ensemble d'en-têtes HTTP standard qui permettent aux propriétaires de sites Web de déclarer les sources de contenu approuvées que les navigateurs devraient être autorisés à charger sur cette page — les types couverts sont JavaScript, CSS, les cadres HTML, les polices, les images et les objets incorporables tels que les applets Java, ActiveX, les fichiers audio et vidéo.
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
- Recommandation : Définir une politique CSP de base avec default-src 'self'. Déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors. Éviter unsafe-inline et unsafe-eval sauf contrainte technique clairement identifiée.
- Vérification : 
curl -I https://www.medianet.tn/ | grep -i content-security-policy
Si l’en-tête Content-Security-Policy est absent → vulnérabilité confirmée.

[Sub Resource Integrity Attribute Missing]
- Description : L'attribut d'intégrité est manquant sur une balise script ou link servie par un serveur externe. L'attribut d'intégrité empêche un attaquant qui a accès à ce serveur d'injecter un contenu malveillant.
- Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes. Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées. Héberger localement les ressources externes critiques si leur contenu varie fréquemment. Réduire le nombre de dépendances tierces non indispensables.
- Vérification : 
curl -s https://www.medianet.tn/ | grep -i integrity
Si une ressource externe script ou link ne contient pas l’attribut integrity → vulnérabilité confirmée.

[Missing Anti-clickjacking Header]
  - Paramètre/Ressource affecté(e) : x-frame-options
- Description : La réponse ne protège pas contre les attaques de type 'ClickJacking'. Elle devrait inclure soit Content-Security-Policy avec la directive 'frame-ancestors', soit X-Frame-Options.
- Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet. Si CSP est utilisée, définir explicitement frame-ancestors avec une valeur restrictive.
- Vérification : 
curl -I https://www.medianet.tn/ | grep -i x-frame-options
Si l’en-tête X-Frame-Options est absent → vulnérabilité confirmée.

C - Vulnérabilités Potentielles à Valider
Cette section est absente car il n'y a pas de vulnérabilités potentielles à valider.

D - Plan de remédiation
1. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires — Délai : 30 jours
2. Sub Resource Integrity Attribute Missing : Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter l’attribut integrity — Délai : 30 jours
3. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de définir une politique CSP de base avec default-src 'self' et de déclarer explicitement les directives nécessaires pour le finding "Content Security Policy (CSP) Header Not Set", avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d’attaque côté navigateur et améliorer la sécurité globale du site Web.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

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

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | Strict-Transport-Security Header Not Set | low | — | 10035-1 |
| P4 | Timestamp Disclosure - Unix | low | 1766420159, 1769691334, 1769695547 | 10096 |
| P5 | Cookie No HttpOnly Flag | low | Set-Cookie: md_csrf_md_cookie, Set-Cookie: md_user_lang | 10010 |
| P5 | Cookie Without Secure Flag | low | Set-Cookie: md_csrf_md_cookie, Set-Cookie: ci_session, Set-Cookie: md_user_lang | 10011 |
| P5 | Cookie without SameSite Attribute | low | Set-Cookie: md_csrf_md_cookie, Set-Cookie: ci_session, Set-Cookie: md_user_lang | 10054-1 |
| P5 | Modern Web Application | info | <a title="" class="standard_link"></a> | 10109 |
| P5 | Technologie détectée : Apache HTTP Server | info | Version non fournie |  |
| P5 | Technologie détectée : CodeIgniter | info | Version non fournie |  |
| P5 | Technologie détectée : Google Tag Manager | info | Version non fournie |  |
| P5 | Technologie détectée : PHP | info | Version non fournie |  |
| P5 | X-Content-Type-Options Header Missing | low | — | 10021 |
| P5 | caa-fingerprint | info | — |  |
| P5 | cookies-without-httponly | info | md_csrf_md_cookie |  |
| P5 | cookies-without-secure | info | md_csrf_md_cookie, ci_session |  |
| P5 | deprecated-tls:tls_1.0 | info | tls10 |  |
| P5 | deprecated-tls:tls_1.1 | info | tls11 |  |
| P5 | dns-saas-service-detection | info | medianet.tn |  |
| P5 | http-missing-security-headers:clear-site-data | info | — |  |
| P5 | http-missing-security-headers:content-security-policy | info | — |  |
| P5 | http-missing-security-headers:cross-origin-embedder-policy | info | — |  |
| P5 | http-missing-security-headers:cross-origin-opener-policy | info | — |  |
| P5 | http-missing-security-headers:cross-origin-resource-policy | info | — |  |
| P5 | http-missing-security-headers:permissions-policy | info | — |  |
| P5 | http-missing-security-headers:referrer-policy | info | — |  |
| P5 | http-missing-security-headers:x-content-type-options | info | — |  |
| P5 | http-missing-security-headers:x-permitted-cross-domain-policies | info | — |  |
| P5 | missing-cookie-samesite-strict | info | md_csrf_md_cookie=a375e1fee469804fdaa8feb74f877d9e; expires=Tue, 03-Feb-2026 14:48:58 GMT; Max-Age=17200; path=/ md_user_lang=fr; expires=Thu, 05-Feb-2026 09:48:58 GMT; Max-Age=172… |  |
| P5 | missing-sri | info | https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-554096385a39fe0b, https://www.medianet.tn/assets/js/home/homes.js, https://pagead2.googlesyndication.com/pagead/js/adsbygoo… |  |
| P5 | mx-fingerprint | info | 10 ALT4.ASPMX.L.GOOGLE.com., 10 ALT2.ASPMX.L.GOOGLE.com., 1 ASPMX.L.GOOGLE.com., 5 ALT2.ASPMX.L.GOOGLE.com., 5 ALT1.ASPMX.L.GOOGLE.com. |  |
| P5 | nameserver-fingerprint | info | ns5.gnet.tn., ns1.gnet.tn., ns2.gnet.tn., ns4.gnet.tn. |  |
| P5 | spf-record-detect | info | "v=spf1 include:_spf.google.com ~all"" |  |
| P5 | ssl-dns-names | info | medianet.com.tn, medianet.tn, www.medianet.com.tn, www.medianet.tn |  |
| P5 | ssl-issuer | info | Let's Encrypt |  |
| P5 | tls-version | info | tls10 |  |
| P5 | txt-fingerprint | info | ""MS=A40ECE4992D1E5D118F2E8873DC069F971231AA4"",""v=spf1 include:_spf.google.com ~all"",""google-site-verification=EmcBMq21CMbShWrPq72VQDdxovlEaq7_Lh8ZXB3GfaA"" |  |
| P5 | weak-cipher-suites:tls-1.0 | low | [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |
| P5 | weak-cipher-suites:tls-1.1 | low | [tls11 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] |  |
