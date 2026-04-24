A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 27 vulnérabilités ont été retenues dans ce rapport, dont 10 sont prioritaires.
Niveau de risque global : ÉLEVÉ. Cible : https://iota-group.com/ (inconnu Non fourni). Scan du : 2026-04-09 19:07:22 UTC.
Le grade SSL/TLS obtenu est B.
La surface d'attaque TLS est étendue et le risque de downgrade ou d'affaiblissement cryptographique est accru, notamment en raison de l'activation de protocoles dépréciés tels que TLS 1.0 et TLS 1.1.
La surface d’attaque côté navigateur est élargie en raison de plusieurs findings liés à la sécurité côté client, tels que l'absence de certaines directives CSP et la présence de scripts et styles inline non sécurisés.

B - Vulnérabilités Prioritaires
1. Protocole déprécié activé : TLS 1.0
- Description : Le protocole TLS 1.0 est activé, ce qui constitue un risque de sécurité car il est considéré comme déprécié et vulnérable à certaines attaques.
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : HIGH
- Recommandation : Désactiver TLS 1.0 et conserver uniquement TLS 1.2 et TLS 1.3.
- Vérification : Utiliser la commande `openssl s_client -connect iota-group.com:443 -tls1_0` pour tester si le protocole TLS 1.0 est accepté. Si la connexion est établie, la vulnérabilité est confirmée.

2. Vulnérabilité TLS : LUCKY13
- Description : La vulnérabilité LUCKY13 affecte certaines suites cryptographiques TLS basées sur des chiffrements CBC et peut permettre une attaque par canal auxiliaire selon l’implémentation côté serveur.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2013-0169
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Réduire ou supprimer les suites CBC lorsque possible et appliquer les correctifs sur le composant TLS ou reverse proxy.
- Vérification : Utiliser la commande `testssl.sh iota-group.com` pour tester les suites cryptographiques utilisées par le serveur. Si des suites CBC sont détectées, la vulnérabilité est confirmée.

3. Protocole déprécié activé : TLS 1.1
- Description : Le protocole TLS 1.1 est activé, ce qui constitue un risque de sécurité car il est considéré comme déprécié et vulnérable à certaines attaques.
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Désactiver TLS 1.1 et conserver uniquement TLS 1.2 et TLS 1.3.
- Vérification : Utiliser la commande `openssl s_client -connect iota-group.com:443 -tls1_1` pour tester si le protocole TLS 1.1 est accepté. Si la connexion est établie, la vulnérabilité est confirmée.

4. CSP: Failure to Define Directive with No Fallback
- Description : Il manque une directive CSP avec un fallback pour certaines ressources, ce qui peut permettre l'injection de code malveillant.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Ajouter les directives manquantes avec des valeurs restrictives pour les ressources concernées.
- Vérification : Utiliser la commande `curl -I https://iota-group.com` pour récupérer l'en-tête CSP. Si les directives nécessaires sont absentes, la vulnérabilité est confirmée.

5. CSP: script-src unsafe-inline
- Description : La directive CSP pour les scripts autorise l'exécution de scripts inline, ce qui peut permettre l'injection de code malveillant.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Migrer les scripts inline vers des fichiers JS statiques versionnés et utiliser des nonces dynamiques pour les scripts inline légitimes restants.
- Vérification : Utiliser la commande `curl -I https://iota-group.com` pour récupérer l'en-tête CSP. Si la directive script-src contient 'unsafe-inline', la vulnérabilité est confirmée.

6. CSP: style-src unsafe-inline
- Description : La directive CSP pour les styles autorise l'injection de styles inline, ce qui peut permettre l'injection de code malveillant.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées et conserver uniquement des hashes CSP pour les fragments inline impossibles à externaliser.
- Vérification : Utiliser la commande `curl -I https://iota-group.com` pour récupérer l'en-tête CSP. Si la directive style-src contient 'unsafe-inline', la vulnérabilité est confirmée.

7. Content Security Policy (CSP) Header Not Set
- Description : L'en-tête CSP n'est pas défini, ce qui peut permettre l'injection de code malveillant.
- Référence : https://iota-group.com
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec des directives restrictives pour les ressources concernées.
- Vérification : Utiliser la commande `curl -I https://iota-group.com` pour récupérer l'en-tête CSP. Si l'en-tête est absent, la vulnérabilité est confirmée.

8. Sub Resource Integrity Attribute Missing
- Description : L'attribut SRI est manquant pour certaines ressources, ce qui peut permettre l'injection de code malveillant.
- Référence : https://iota-group.com/*/comments/
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Ajouter l'attribut integrity pour les ressources concernées et utiliser des nonces dynamiques pour les ressources qui ne peuvent pas être versionnées.
- Vérification : Utiliser la commande `curl -s https://iota-group.com` pour récupérer les balises script et link. Si les attributs integrity sont absents, la vulnérabilité est confirmée.

9. CSP: Wildcard Directive
- Description : La directive CSP contient un joker qui autorise des sources trop larges, ce qui peut permettre l'injection de code malveillant.
- Référence : https://iota-group.com/wp-admin/admin-post.php?action=mailpoet_subscription_form
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Remplacer le joker par une liste précise d'hôtes de confiance et séparer les besoins par type de ressource.
- Vérification : Utiliser la commande `curl -I https://iota-group.com` pour récupérer l'en-tête CSP. Si la directive contient un joker, la vulnérabilité est confirmée.

10. Missing Anti-clickjacking Header
- Description : L'en-tête anti-clickjacking est manquant, ce qui peut permettre des attaques de type clickjacking.
- Référence : https://iota-group.com
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir l'en-tête X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : Utiliser la commande `curl -I https://iota-group.com` pour récupérer l'en-tête X-Frame-Options. Si l'en-tête est absent, la vulnérabilité est confirmée.

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider n'a été détectée.

D - Plan de remédiation
1. Protocole déprécié activé : TLS 1.0 : Désactiver TLS 1.0 — Délai : sous 24h
2. Vulnérabilité TLS : LUCKY13 : Réduire ou supprimer les suites CBC — Délai : 7 jours
3. Protocole déprécié activé : TLS 1.1 : Désactiver TLS 1.1 — Délai : 7 jours
4. CSP: Failure to Define Directive with No Fallback : Ajouter les directives manquantes — Délai : 30 jours
5. CSP: script-src unsafe-inline : Migrer les scripts inline vers des fichiers JS statiques — Délai : 30 jours
6. CSP: style-src unsafe-inline : Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
7. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base — Délai : 30 jours
8. Sub Resource Integrity Attribute Missing : Ajouter l'attribut integrity pour les ressources concernées — Délai : 30 jours
9. CSP: Wildcard Directive : Remplacer le joker par une liste précise d'hôtes de confiance — Délai : 30 jours
10. Missing Anti-clickjacking Header : Définir l'en-tête X-Frame-Options à DENY ou SAMEORIGIN — Délai : 30 jours

E - Conclusion
Le niveau de risque global est ÉLEVÉ. L'action prioritaire principale est de désactiver le protocole TLS 1.0, qui présente un risque de sécurité élevé, dans les 24 prochaines heures. Il est essentiel de traiter ces vulnérabilités pour assurer la sécurité de l'application et protéger les données des utilisateurs.


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
