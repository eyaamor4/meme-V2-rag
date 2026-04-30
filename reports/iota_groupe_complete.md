A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 27 vulnérabilités ont été retenues dans ce rapport, dont 10 sont prioritaires.
Niveau de risque global : ÉLEVÉ. Cible : https://iota-group.com/ (inconnu Non fourni). Scan du : 2026-04-09 19:07:22 UTC.
Le grade SSL/TLS obtenu est B.
La surface d'attaque TLS est étendue et le risque de downgrade ou d'affaiblissement cryptographique est accru.
La surface d’attaque côté navigateur est élargie.

B - Vulnérabilités Prioritaires
[Protocole déprécié activé : TLS 1.0]
- Description : 
  Le protocole TLS 1.0 est activé, ce qui constitue un protocole déprécié (RFC 8996).
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : HIGH
- Recommandation : Désactiver TLS 1.0 et TLS 1.1 sur le serveur web ou équipement de terminaison TLS.
- Vérification :
  openssl s_client -connect iota-group.com:443 -tls1_0
  Si la connexion TLS 1.0 est établie → vulnérabilité confirmée.

[Vulnérabilité TLS : LUCKY13]
- Description : 
  La vulnérabilité LUCKY13 affecte certaines suites cryptographiques TLS basées sur des chiffrements CBC et peut permettre une attaque par canal auxiliaire selon l’implémentation côté serveur.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2013-0169
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Réduire ou supprimer les suites CBC lorsque possible.
- Vérification :
  testssl.sh iota-group.com
  Si des suites CBC sont proposées → vulnérabilité confirmée.

[Protocole déprécié activé : TLS 1.1]
- Description : 
  Le protocole TLS 1.1 est activé, ce qui constitue un protocole déprécié (RFC 8996).
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Désactiver TLS 1.0 et TLS 1.1 sur le serveur web ou équipement de terminaison TLS.
- Vérification :
  openssl s_client -connect iota-group.com:443 -tls1_1
  Si la connexion TLS 1.1 est établie → vulnérabilité confirmée.

[CSP: Failure to Define Directive with No Fallback]
- Description : 
  Il manque des directives CSP sans fallback parmi : form-action, frame-ancestors, base-uri, object-src.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Ajouter les directives manquantes avec des valeurs restrictives.
- Vérification :
  curl -I https://iota-group.com/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP récupéré.
  Vérifier explicitement la présence des directives form-action, frame-ancestors, base-uri et object-src.

[CSP: script-src unsafe-inline]
- Description : 
  La directive script-src contient 'unsafe-inline'.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible.
- Vérification :
  curl -I https://iota-group.com/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Identifier la directive script-src dans la politique.

[CSP: style-src unsafe-inline]
- Description : 
  La directive style-src contient 'unsafe-inline'.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
- Vérification :
  curl -I https://iota-group.com/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Identifier la directive style-src dans la politique.

[Content Security Policy (CSP) Header Not Set]
- Description : 
  L’en-tête Content-Security-Policy est absent.
- Référence : https://iota-group.com
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self'.
- Vérification :
  curl -I https://iota-group.com/ | grep -i content-security-policy
  Contrôler la présence de l’en-tête Content-Security-Policy.

[Sub Resource Integrity Attribute Missing]
- Description : 
  Il manque l’attribut integrity sur les balises script et link.
- Référence : https://iota-group.com/*/comments/
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
- Vérification :
  curl -s https://iota-group.com/ | grep -i integrity
  Identifier les balises script et link qui chargent des ressources externes.
  Vérifier si ces balises contiennent un attribut integrity et crossorigin.

[CSP: Wildcard Directive]
- Description : 
  Une directive CSP contient '*'.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Remplacer '*' par une liste précise d’hôtes de confiance.
- Vérification :
  curl -I https://iota-group.com/ | grep -i content-security-policy
  Lire la valeur complète de l’en-tête CSP.
  Rechercher explicitement le caractère '*' dans les directives concernées.

[Missing Anti-clickjacking Header]
- Description : 
  L’en-tête X-Frame-Options est absent.
- Référence : https://iota-group.com
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification :
  curl -I https://iota-group.com/ | grep -i x-frame-options
  Contrôler la présence de X-Frame-Options.

C - Vulnérabilités Potentielles à Valider
Cette section est absente car il n'y a pas de vulnérabilités potentielles à valider.

D - Plan de remédiation
1. [Protocole déprécié activé : TLS 1.0] : Désactiver TLS 1.0 et TLS 1.1 sur le serveur web ou équipement de terminaison TLS — Délai : sous 24h
2. [Vulnérabilité TLS : LUCKY13] : Réduire ou supprimer les suites CBC lorsque possible — Délai : 7 jours
3. [Protocole déprécié activé : TLS 1.1] : Désactiver TLS 1.0 et TLS 1.1 sur le serveur web ou équipement de terminaison TLS — Délai : sous 24h
4. [CSP: Failure to Define Directive with No Fallback] : Ajouter les directives manquantes avec des valeurs restrictives — Délai : 7 jours
5. [CSP: script-src unsafe-inline] : Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible — Délai : 7 jours
6. [CSP: style-src unsafe-inline] : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées — Délai : 7 jours
7. [Content Security Policy (CSP) Header Not Set] : Définir une politique CSP de base avec default-src 'self' — Délai : 7 jours
8. [Sub Resource Integrity Attribute Missing] : Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées — Délai : 7 jours
9. [CSP: Wildcard Directive] : Remplacer '*' par une liste précise d’hôtes de confiance — Délai : 7 jours
10. [Missing Anti-clickjacking Header] : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 7 jours

E - Conclusion
Le niveau de risque global est ÉLEVÉ.
L'action prioritaire principale est de désactiver TLS 1.0 et TLS 1.1 sur le serveur web ou équipement de terminaison TLS, avec un délai de sous 24h.
Il est essentiel de traiter ces vulnérabilités pour réduire les risques de sécurité et protéger les données sensibles.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 1 | 12 | 14 | 11 |

    **Niveau de risque global : ÉLEVÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 27  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 11  
    **Prioritaires confirmées (section B) :** 10 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | Absence of Anti-CSRF Tokens | medium | — |  |
| P4 | Application Error Disclosure | low | — |  |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | — |  |
| P4 | Port sensible exposé : 2082/infowave | medium | infowave |  |
| P4 | Port sensible exposé : 2086/gnunet | medium | gnunet |  |
| P4 | Timestamp Disclosure - Unix | low | — |  |
| P5 | Cookie without SameSite Attribute | low | — |  |
| P5 | Grade SSL/TLS dégradé (SSL Labs) | info | — |  |
| P5 | Information Disclosure - Suspicious Comments | info | — |  |
| P5 | Modern Web Application | info | — |  |
| P5 | Port sensible exposé : 2083/radsec | low | radsec |  |
| P5 | Port sensible exposé : 2087/eli | low | eli |  |
| P5 | Port sensible exposé : 2095/nbx-ser | low | nbx-ser |  |
| P5 | Port sensible exposé : 8080/http-proxy | low | http-proxy (cloudflare) |  |
| P5 | Port sensible exposé : 8880/cddbp-alt | low | cddbp-alt |  |
| P5 | Re-examine Cache-control Directives | info | — |  |
| P5 | Retrieved from Cache | info | — |  |
| P5 | Strict-Transport-Security Header Not Set | low | — |  |
| P5 | User Controllable HTML Element Attribute (Potential XSS) | info | — |  |
| P5 | Vulnérabilité TLS : BREACH | low | — |  |
| P5 | X-Content-Type-Options Header Missing | low | — |  |
| P5 | aaaa-fingerprint | info | 2606:4700:3037::ac43:b241, 2606:4700:3033::6815:11c8, https://www.cloudflare.com/learning/dns/dns-records/dns-aaaa-record/, https://en.wikipedia.org/wiki/IPv6_address |  |
| P5 | caa-fingerprint | info | comodoca.com, digicert.com; cansignhttpexchanges=yes, letsencrypt.org, pki.goog; cansignhttpexchanges=yes, ssl.com, https://support.dnsimple.com/articles/caa-record/#whats-a-caa-re… |  |
| P5 | deprecated-tls | info | iota-group.com:443, tls11, https://ssl-config.mozilla.org/#config=intermediate |  |
| P5 | dkim-record-detect | info | selector1._domainkey.iota-group.com, v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK3uppUY11X5CKnfqkjo/nBHI/94WXtTYxJcMDY+0XxMxxyXIiqCuDNrde0ko4TpyH6as4LQEQ8HgDVv+tB1g76… |  |
| P5 | dmarc-detect | info | _dmarc.iota-group.com, "v=DMARC1; p=none; rua=mailto:admingeneral@iota-group.com,mailto:dmarc@smtp.mailtrap.live; ruf=mailto:dmarc@smtp.mailtrap.live; adkim=s; aspf=s; rf=afrf; pct… |  |
| P5 | dns-waf-detect | info | — |  |
| P5 | http-missing-security-headers | info | https://iota-group.com/ |  |
| P5 | missing-sri | info | https://iota-group.com/, https://iota-group.com/wp-content/plugins/date-time-picker-for-contact-form-7/assets/js/jquery.datetimepicker.full.min.js?ver=ea8a0c180bb803b33118ac150f9e9… |  |
| P5 | mx-fingerprint | info | 10 iotagroup.in.tmes.trendmicro.eu., https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/, https://mxtoolbox.com/ |  |
| P5 | nameserver-fingerprint | info | ollie.ns.cloudflare.com., evan.ns.cloudflare.com. |  |
| P5 | spf-record-detect | info | v=spf1 include:mailgun.org include:spf.protection.outlook.com include:spf.tmes.trendmicro.eu include:_spf.smtp.mailtrap.live include:relay.mail.infomaniak.ch ip4:3.250.248.228 ip4:… |  |
| P5 | ssl-dns-names | info | iota-group.com:443, iota-group.com, *.iota-group.com |  |
| P5 | ssl-issuer | info | iota-group.com:443, Google Trust Services |  |
| P5 | tls-version | info | iota-group.com:443, tls10 |  |
| P5 | txt-fingerprint | info | "google-site-verification=Gm35tp05os7CHhrmYPaBsRMRDVEfewc4ZcGqvQXQc7A", "tmes=007d600ba858a7d97759cb63d2937faf", "v=spf1 include:mailgun.org include:spf.protection.outlook.com incl… |  |
| P5 | weak-cipher-suites | low | iota-group.com:443, [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA], https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |  |
| P5 | wildcard-tls | info | iota-group.com:443, CN: iota-group.com, SAN: [iota-group.com *.iota-group.com], https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#carefully-c… |  |
| P5 | wordpress-elementor-fpd | low | https://iota-group.com/wp-content/plugins/elementor/app/modules/import-export/runners/export/wp-content.php, https://wordpress.org/plugins/elementor/ |  |
