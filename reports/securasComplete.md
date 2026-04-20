A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 18 vulnérabilités ont été retenues dans ce rapport, dont 7 sont prioritaires.
Niveau de risque global : ÉLEVÉ. Cible : https://securas.fr/ (inconnu Non fourni). Scan du : 2026-03-13 11:51:22 UTC.
La surface d'attaque TLS est étendue et le risque de downgrade ou d'affaiblissement cryptographique est accru en raison de la présence de plusieurs findings réseau SSL/TLS.
La surface d’attaque côté navigateur est élargie en raison de la présence de plusieurs findings liés à la sécurité côté client.

B - Vulnérabilités Prioritaires
1. Protocole déprécié activé : TLS 1.0
- Description : TLS 1.0 activé — protocole déprécié (RFC 8996)
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : HIGH
- Recommandation : Supprimer les suites CBC anciennes ou faibles lorsque la compatibilité n’est pas requise.
- Vérification : openssl s_client -connect [host]:443 -tls1.0

2. Vulnérabilité TLS : SWEET32
- Description : Vulnérabilité liée à l’utilisation de chiffrements à bloc 64 bits, pouvant affaiblir la confidentialité des échanges chiffrés lors de sessions longues.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-2183
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Désactiver 3DES et toute suite à bloc 64 bits.
- Vérification : openssl s_client -connect [host]:443 -tls1.2

3. Vulnérabilité TLS : LUCKY13
- Description : Vulnérabilité affectant certains chiffrements CBC, pouvant permettre une attaque par canal auxiliaire sur les communications TLS selon l’implémentation côté serveur.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2013-0169
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Réduire ou supprimer les suites CBC lorsque possible.
- Vérification : openssl s_client -connect [host]:443 -tls1.2

4. Protocole déprécié activé : TLS 1.1
- Description : TLS 1.1 activé — protocole déprécié (RFC 8996)
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Supprimer les suites CBC anciennes ou faibles lorsque la compatibilité n’est pas requise.
- Vérification : openssl s_client -connect [host]:443 -tls1.1

5. Content Security Policy (CSP) Header Not Set
- Description : Content Security Policy (CSP) Header Not Set — 5 instance(s) détectée(s).
- Référence : https://securas.fr
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self'.
- Vérification : curl -I https://[site] | grep -i content-security-policy

6. Sub Resource Integrity Attribute Missing
- Description : Sub Resource Integrity Attribute Missing — 5 instance(s) détectée(s).
- Référence : https://securas.fr
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes.
- Vérification : curl -s https://[site] | grep -i 'integrity='

7. Missing Anti-clickjacking Header
- Description : Missing Anti-clickjacking Header — 5 instance(s) détectée(s).
- Référence : https://securas.fr
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : curl -I https://[site] | grep -i x-frame-options

C - Vulnérabilités Potentielles à Valider
Cette section est vide car il n'y a pas de vulnérabilités potentielles à valider.

D - Plan de remédiation
1. Protocole déprécié activé : TLS 1.0 : Désactiver le protocole TLS 1.0 — Délai : sous 24h
2. Vulnérabilité TLS : SWEET32 : Désactiver 3DES et toute suite à bloc 64 bits — Délai : 7 jours
3. Vulnérabilité TLS : LUCKY13 : Réduire ou supprimer les suites CBC lorsque possible — Délai : 7 jours
4. Protocole déprécié activé : TLS 1.1 : Supprimer les suites CBC anciennes ou faibles lorsque la compatibilité n’est pas requise — Délai : 7 jours
5. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' — Délai : 7 jours
6. Sub Resource Integrity Attribute Missing : Identifier les scripts et feuilles CSS chargés depuis des domaines externes — Délai : 7 jours
7. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 7 jours

E - Conclusion
Le niveau de risque global est ÉLEVÉ.
L'action prioritaire principale est de désactiver le protocole TLS 1.0, qui doit être effectuée sous 24h.
Il est essentiel de traiter les vulnérabilités prioritaires pour réduire le risque global.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 1 | 8 | 9 | 12 |

    **Niveau de risque global : ÉLEVÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 18  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 12  
    **Prioritaires confirmées (section B) :** 7 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | — |  |
| P4 | vulnerability | medium | — | — | Port sensible exposé : 2082/infowave | infowave |  |
| P4 | vulnerability | medium | — | — | Port sensible exposé : 2086/gnunet | gnunet |  |
| P4 | vulnerability | low | Low | Medium | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | — |  |
| P5 | information | info | — | — | Grade SSL/TLS dégradé (SSL Labs) | — |  |
| P5 | information | info | Informational | Low | Information Disclosure - Suspicious Comments | — |  |
| P5 | information | info | Informational | Medium | Modern Web Application | — |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2083/radsec | radsec |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2087/eli | eli |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2095/nbx-ser | nbx-ser |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 8080/http-proxy | http-proxy (cloudflare) |  |
| P5 | vulnerability | low | — | — | Port sensible exposé : 8880/cddbp-alt | cddbp-alt |  |
| P5 | information | info | Informational | Low | Re-examine Cache-control Directives | — |  |
| P5 | vulnerability | low | — | — | Vulnérabilité TLS : BREACH | — |  |
| P5 | information | info | — | — | aaaa-fingerprint | 2a06:98c1:3121::, 2a06:98c1:3120::, https://www.cloudflare.com/learning/dns/dns-records/dns-aaaa-record/, https://en.wikipedia.org/wiki/IPv6_address |  |
| P5 | information | info | — | — | caa-fingerprint | https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record |  |
| P5 | information | info | — | — | deprecated-tls | securas.fr:443, tls11, https://ssl-config.mozilla.org/#config=intermediate |  |
| P5 | information | info | — | — | dkim-record-detect | google._domainkey.securas.fr, v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAptM3rpC2LA5+yS//Uy2PQJ2M6vKod1GuzzAXUJ1QvmidenWnYVaAucYqgndmPO6Xud/NC8JMCOAgLdCJW6NL5YFb… |  |
| P5 | information | info | — | — | dmarc-detect | _dmarc.securas.fr, "v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc@mailinblue.com; ruf=mailto:dmarc@mailinblue.com; ri=86400; aspf=s; adkim=s; fo=1", https://dmarc.org/, http… |  |
| P5 | information | info | — | — | dns-waf-detect | — |  |
| P5 | information | info | — | — | http-missing-security-headers | https://securas.fr/ |  |
| P5 | information | info | — | — | missing-sri | https://securas.fr/, https://manus-analytics.com/umami, https://files.manuscdn.com/manus-space-dispatcher/spaceEditor-DPV-_I11.js, https://plausible.io/js/script.file-downloads.has… |  |
| P5 | information | info | — | — | mx-fingerprint | 1 aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., https://www.cloudflare.com/learning/dns/dns… |  |
| P5 | information | info | — | — | mx-service-detector | — |  |
| P5 | information | info | — | — | nameserver-fingerprint | beau.ns.cloudflare.com., lisa.ns.cloudflare.com. |  |
| P5 | information | info | — | — | spf-record-detect | v=spf1 include:mx.ovh.com include:spf.sendinblue.com include:eu.transmail.net include:eu.zcsend.net mx include:_spf.google.com ~all", https://www.mimecast.com/content/how-to-create… |  |
| P5 | information | info | — | — | srv-service-detect | _autodiscover._tcp.securas.fr, SRV 0 0 443 pro1.mail.ovh.net., https://www.rfc-editor.org/rfc/rfc2srv, https://en.wikipedia.org/wiki/SRV_record |  |
| P5 | information | info | — | — | ssl-dns-names | securas.fr:443, securas.fr |  |
| P5 | information | info | — | — | ssl-issuer | securas.fr:443, Google Trust Services |  |
| P5 | information | info | — | — | tls-version | securas.fr:443, tls10 |  |
| P5 | information | info | — | — | txt-fingerprint | "brevo-code:7155099cecfa7c123d01beff5122ac76", "google-site-verification=1AmqyWIx4Jbqi9twtMYtCfcSEX_usnvoeihc2QgcuOA", "google-site-verification=c0GXk6gMTyyf_sb18hOdTkmllh_adlQU_Kl… |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites | securas.fr:443, [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA], https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |  |
