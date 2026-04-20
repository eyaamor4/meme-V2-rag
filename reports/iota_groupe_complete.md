A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 27 vulnérabilités ont été retenues dans ce rapport, dont 10 sont prioritaires.
Niveau de risque global : ÉLEVÉ. Cible : https://iota-group.com/ (inconnu Non fourni). Scan du : 2026-04-09 19:07:22 UTC.
Le grade SSL/TLS obtenu est B.
La surface d'attaque TLS est étendue et le risque de downgrade ou d'affaiblissement cryptographique est accru en raison de la présence de protocoles dépréciés et de vulnérabilités TLS.
La surface d’attaque côté navigateur est élargie en raison de plusieurs findings liés à la sécurité côté client.

B - Vulnérabilités Prioritaires
1. Protocole déprécié activé : TLS 1.0
- Description : TLS 1.0 activé — protocole déprécié (RFC 8996)
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : HIGH
- Recommandation : Désactiver le protocole TLS 1.0 dans la configuration serveur.
- Vérification : Utiliser openssl s_client -connect [host]:443 -tls1_0 pour tester la connexion.

2. Vulnérabilité TLS : LUCKY13
- Description : Vulnérabilité affectant certains chiffrements CBC, pouvant permettre une attaque par canal auxiliaire sur les communications TLS selon l’implémentation côté serveur.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2013-0169
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Réduire ou supprimer les suites CBC lorsque possible.
- Vérification : Utiliser openssl s_client -connect [host]:443 -cipher [suite] pour tester la connexion.

3. Protocole déprécié activé : TLS 1.1
- Description : TLS 1.1 activé — protocole déprécié (RFC 8996)
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Désactiver le protocole TLS 1.1 dans la configuration serveur.
- Vérification : Utiliser openssl s_client -connect [host]:443 -tls1_1 pour tester la connexion.

4. CSP: Failure to Define Directive with No Fallback
- Description : CSP: Failure to Define Directive with No Fallback — 1 instance(s) détectée(s).
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les directives CSP sans fallback qui sont ABSENTES de la politique actuelle.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy pour vérifier la présence de la directive.

5. CSP: script-src unsafe-inline
- Description : CSP: script-src unsafe-inline — 1 instance(s) détectée(s).
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier tous les scripts inline présents dans les templates HTML.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy pour vérifier la présence de la directive.

6. CSP: style-src unsafe-inline
- Description : CSP: style-src unsafe-inline — 1 instance(s) détectée(s).
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les styles inline dans les templates et composants front-end.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy pour vérifier la présence de la directive.

7. Content Security Policy (CSP) Header Not Set
- Description : Content Security Policy (CSP) Header Not Set — 43 instance(s) détectée(s).
- Référence : https://iota-group.com
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self'.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy pour vérifier la présence de l'en-tête.

8. Sub Resource Integrity Attribute Missing
- Description : Sub Resource Integrity Attribute Missing — 17 instance(s) détectée(s).
- Référence : https://iota-group.com/*/comments/
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes.
- Vérification : Inspecter le code source HTML pour vérifier la présence de l'attribut integrity.

9. CSP: Wildcard Directive
- Description : CSP: Wildcard Directive — 1 instance(s) détectée(s).
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Remplacer * par une liste précise d’hôtes de confiance.
- Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy pour vérifier la présence de la directive.

10. Missing Anti-clickjacking Header
- Description : Missing Anti-clickjacking Header — 31 instance(s) détectée(s).
- Référence : https://iota-group.com
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : Exécuter curl -I https://[site] | grep -i x-frame-options pour vérifier la présence de l'en-tête.

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider.

D - Plan de remédiation
1. Protocole déprécié activé : TLS 1.0 : Désactiver le protocole TLS 1.0 dans la configuration serveur — Délai : sous 24h
2. Vulnérabilité TLS : LUCKY13 : Réduire ou supprimer les suites CBC lorsque possible — Délai : 7 jours
3. Protocole déprécié activé : TLS 1.1 : Désactiver le protocole TLS 1.1 dans la configuration serveur — Délai : 7 jours
4. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP sans fallback qui sont ABSENTES de la politique actuelle — Délai : 7 jours
5. CSP: script-src unsafe-inline : Identifier tous les scripts inline présents dans les templates HTML — Délai : 7 jours
6. CSP: style-src unsafe-inline : Identifier les styles inline dans les templates et composants front-end — Délai : 7 jours
7. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' — Délai : 7 jours
8. Sub Resource Integrity Attribute Missing : Identifier les scripts et feuilles CSS chargés depuis des domaines externes — Délai : 30 jours
9. CSP: Wildcard Directive : Remplacer * par une liste précise d’hôtes de confiance — Délai : 30 jours
10. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 30 jours

E - Conclusion
Le niveau de risque global est ÉLEVÉ.
L'action prioritaire principale est de désactiver le protocole TLS 1.0 dans la configuration serveur, avec un délai de sous 24h.
Il est essentiel de traiter les vulnérabilités prioritaires pour réduire le risque de sécurité.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

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

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | medium | Medium | Low | Absence of Anti-CSRF Tokens | — |  |
| P4 | vulnerability | low | Low | Medium | Application Error Disclosure | — |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | — |  |
| P4 | vulnerability | medium | — | — | Port sensible exposé : 2082/infowave | infowave |  |
| P4 | vulnerability | medium | — | — | Port sensible exposé : 2086/gnunet | gnunet |  |
| P4 | vulnerability | low | Low | Low | Timestamp Disclosure - Unix | — |  |
| P5 | vulnerability | low | Low | Medium | Cookie without SameSite Attribute | — |  |
| P5 | information | info | — | — | Grade SSL/TLS dégradé (SSL Labs) | — |  |
| P5 | information | info | Informational | Low | Information Disclosure - Suspicious Comments | — |  |
| P5 | information | info | Informational | Medium | Modern Web Application | — |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2083/radsec | radsec |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2087/eli | eli |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2095/nbx-ser | nbx-ser |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 8080/http-proxy | http-proxy (cloudflare) |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 8880/cddbp-alt | cddbp-alt |  |
| P5 | information | info | Informational | Low | Re-examine Cache-control Directives | — |  |
| P5 | information | info | Informational | Medium | Retrieved from Cache | — |  |
| P5 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | — |  |
| P5 | information | info | Informational | Low | User Controllable HTML Element Attribute (Potential python pdf_export.py reports	on_rapport.md) | — |  |
| P5 | vulnerability | low | — | — | Vulnérabilité TLS : BREACH | — |  |
| P5 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | — |  |
| P5 | information | info | — | — | aaaa-fingerprint | 2606:4700:3037::ac43:b241, 2606:4700:3033::6815:11c8, https://www.cloudflare.com/learning/dns/dns-records/dns-aaaa-record/, https://en.wikipedia.org/wiki/IPv6_address |  |
| P5 | information | info | — | — | caa-fingerprint | comodoca.com, digicert.com; cansignhttpexchanges=yes, letsencrypt.org, pki.goog; cansignhttpexchanges=yes, ssl.com, https://support.dnsimple.com/articles/caa-record/#whats-a-caa-re… |  |
| P5 | information | info | — | — | deprecated-tls | iota-group.com:443, tls11, https://ssl-config.mozilla.org/#config=intermediate |  |
| P5 | information | info | — | — | dkim-record-detect | selector1._domainkey.iota-group.com, v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK3uppUY11X5CKnfqkjo/nBHI/94WXtTYxJcMDY+0XxMxxyXIiqCuDNrde0ko4TpyH6as4LQEQ8HgDVv+tB1g76… |  |
| P5 | information | info | — | — | dmarc-detect | _dmarc.iota-group.com, "v=DMARC1; p=none; rua=mailto:admingeneral@iota-group.com,mailto:dmarc@smtp.mailtrap.live; ruf=mailto:dmarc@smtp.mailtrap.live; adkim=s; aspf=s; rf=afrf; pct… |  |
| P5 | information | info | — | — | dns-waf-detect | — |  |
| P5 | information | info | — | — | http-missing-security-headers | https://iota-group.com/ |  |
| P5 | information | info | — | — | missing-sri | https://iota-group.com/, https://iota-group.com/wp-content/plugins/date-time-picker-for-contact-form-7/assets/js/jquery.datetimepicker.full.min.js?ver=ea8a0c180bb803b33118ac150f9e9… |  |
| P5 | information | info | — | — | mx-fingerprint | 10 iotagroup.in.tmes.trendmicro.eu., https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/, https://mxtoolbox.com/ |  |
| P5 | information | info | — | — | nameserver-fingerprint | ollie.ns.cloudflare.com., evan.ns.cloudflare.com. |  |
| P5 | information | info | — | — | spf-record-detect | v=spf1 include:mailgun.org include:spf.protection.outlook.com include:spf.tmes.trendmicro.eu include:_spf.smtp.mailtrap.live include:relay.mail.infomaniak.ch ip4:3.250.248.228 ip4:… |  |
| P5 | information | info | — | — | ssl-dns-names | iota-group.com:443, iota-group.com, *.iota-group.com |  |
| P5 | information | info | — | — | ssl-issuer | iota-group.com:443, Google Trust Services |  |
| P5 | information | info | — | — | tls-version | iota-group.com:443, tls10 |  |
| P5 | information | info | — | — | txt-fingerprint | "google-site-verification=Gm35tp05os7CHhrmYPaBsRMRDVEfewc4ZcGqvQXQc7A", "tmes=007d600ba858a7d97759cb63d2937faf", "v=spf1 include:mailgun.org include:spf.protection.outlook.com incl… |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites | iota-group.com:443, [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA], https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |  |
| P5 | information | info | — | — | wildcard-tls | iota-group.com:443, CN: iota-group.com, SAN: [iota-group.com *.iota-group.com], https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#carefully-c… |  |
| P5 | vulnerability | low | — | — | wordpress-elementor-fpd | https://iota-group.com/wp-content/plugins/elementor/app/modules/import-export/runners/export/wp-content.php, https://wordpress.org/plugins/elementor/ |  |
