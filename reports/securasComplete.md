A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 18 vulnérabilités ont été retenues dans ce rapport, dont 7 sont prioritaires.
Niveau de risque global : ÉLEVÉ. Cible : https://securas.fr/ (inconnu Non fourni). Scan du : 2026-03-13 11:51:22 UTC.
Le grade SSL/TLS obtenu est B.
La surface d'attaque TLS est étendue et le risque de downgrade ou d'affaiblissement cryptographique est accru, notamment en raison de l'activation de protocoles dépréciés tels que TLS 1.0 et TLS 1.1, ainsi que la présence de vulnérabilités TLS comme SWEET32 et LUCKY13.
La surface d’attaque côté navigateur est également élargie en raison de l'absence de certaines en-têtes de sécurité, telles que Content Security Policy (CSP) et les attributs Sub Resource Integrity (SRI), ainsi que l'absence de headers anti-clickjacking.

B - Vulnérabilités Prioritaires
1. Protocole déprécié activé : TLS 1.0
- Description : Le protocole TLS 1.0 est activé, ce qui constitue un protocole déprécié (RFC 8996) et peut présenter des risques de sécurité.
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : HIGH
- Recommandation : Désactiver TLS 1.0 et conserver uniquement TLS 1.2 et TLS 1.3.
- Vérification : Exécuter openssl s_client -connect securas.fr:443 -tls1_0 pour tester si TLS 1.0 est accepté. Si la connexion est établie, la vulnérabilité est confirmée.

2. Vulnérabilité TLS : SWEET32
- Description : La vulnérabilité SWEET32 est liée à l’utilisation de chiffrements à bloc 64 bits, ce qui peut affaiblir la confidentialité des échanges chiffrés lors de sessions longues.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-2183
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Désactiver 3DES et conserver uniquement des suites modernes pour TLS 1.2 et TLS 1.3.
- Vérification : Exécuter testssl.sh securas.fr pour tester les suites de chiffrement proposées. Si des suites à bloc 64 bits sont proposées, la vulnérabilité est confirmée.

3. Vulnérabilité TLS : LUCKY13
- Description : La vulnérabilité LUCKY13 affecte certaines suites cryptographiques TLS basées sur des chiffrements CBC et peut permettre une attaque par canal auxiliaire selon l’implémentation côté serveur.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2013-0169
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Réduire ou supprimer les suites CBC lorsque possible et appliquer les correctifs sur le composant TLS ou reverse proxy.
- Vérification : Exécuter testssl.sh securas.fr pour tester les suites de chiffrement proposées. Si des suites CBC sont proposées, la vulnérabilité est confirmée.

4. Protocole déprécié activé : TLS 1.1
- Description : Le protocole TLS 1.1 est activé, ce qui constitue un protocole déprécié (RFC 8996) et peut présenter des risques de sécurité.
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Sévérité : MEDIUM
- Recommandation : Désactiver TLS 1.1 et conserver uniquement TLS 1.2 et TLS 1.3.
- Vérification : Exécuter openssl s_client -connect securas.fr:443 -tls1_1 pour tester si TLS 1.1 est accepté. Si la connexion est établie, la vulnérabilité est confirmée.

5. Content Security Policy (CSP) Header Not Set
- Description : L'en-tête Content Security Policy (CSP) n'est pas défini, ce qui peut permettre des attaques de type XSS.
- Référence : https://securas.fr
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self'.
- Vérification : Exécuter curl -I https://securas.fr | grep -i content-security-policy pour tester si l'en-tête CSP est présent. Si l'en-tête est absent, la vulnérabilité est confirmée.

6. Sub Resource Integrity Attribute Missing
- Description : L'attribut Sub Resource Integrity (SRI) est manquant, ce qui peut permettre des attaques de type XSS.
- Référence : https://securas.fr
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Ajouter l'attribut integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
- Vérification : Exécuter curl -s https://securas.fr | grep -i integrity pour tester si l'attribut SRI est présent. Si l'attribut est absent, la vulnérabilité est confirmée.

7. Missing Anti-clickjacking Header
- Description : L'en-tête anti-clickjacking est manquant, ce qui peut permettre des attaques de type clickjacking.
- Référence : https://securas.fr
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : Exécuter curl -I https://securas.fr | grep -i x-frame-options pour tester si l'en-tête X-Frame-Options est présent. Si l'en-tête est absent, la vulnérabilité est confirmée.

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider n'a été détectée.

D - Plan de remédiation
1. Protocole déprécié activé : TLS 1.0 : Désactiver TLS 1.0 — Délai : 7 jours
2. Vulnérabilité TLS : SWEET32 : Désactiver 3DES — Délai : 7 jours
3. Vulnérabilité TLS : LUCKY13 : Réduire ou supprimer les suites CBC — Délai : 7 jours
4. Protocole déprécié activé : TLS 1.1 : Désactiver TLS 1.1 — Délai : 7 jours
5. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base — Délai : 7 jours
6. Sub Resource Integrity Attribute Missing : Ajouter l'attribut integrity — Délai : 7 jours
7. Missing Anti-clickjacking Header : Définir X-Frame-Options — Délai : 7 jours

E - Conclusion
Le niveau de risque global est ÉLEVÉ.
L'action prioritaire principale est de désactiver TLS 1.0, qui présente un risque élevé de sécurité, avec un délai de 7 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire les risques de sécurité et protéger les données sensibles.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

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

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | — |  |
| P4 | Port sensible exposé : 2082/infowave | medium | infowave |  |
| P4 | Port sensible exposé : 2086/gnunet | medium | gnunet |  |
| P4 | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | low | — |  |
| P5 | Grade SSL/TLS dégradé (SSL Labs) | info | — |  |
| P5 | Information Disclosure - Suspicious Comments | info | — |  |
| P5 | Modern Web Application | info | — |  |
| P5 | Port sensible exposé : 2083/radsec | low | radsec |  |
| P5 | Port sensible exposé : 2087/eli | low | eli |  |
| P5 | Port sensible exposé : 2095/nbx-ser | low | nbx-ser |  |
| P5 | Port sensible exposé : 8080/http-proxy | low | http-proxy (cloudflare) |  |
| P5 | Port sensible exposé : 8880/cddbp-alt | low | cddbp-alt |  |
| P5 | Re-examine Cache-control Directives | info | — |  |
| P5 | Vulnérabilité TLS : BREACH | low | — |  |
| P5 | aaaa-fingerprint | info | 2a06:98c1:3121::, 2a06:98c1:3120::, https://www.cloudflare.com/learning/dns/dns-records/dns-aaaa-record/, https://en.wikipedia.org/wiki/IPv6_address |  |
| P5 | caa-fingerprint | info | https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record |  |
| P5 | deprecated-tls | info | securas.fr:443, tls11, https://ssl-config.mozilla.org/#config=intermediate |  |
| P5 | dkim-record-detect | info | google._domainkey.securas.fr, v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAptM3rpC2LA5+yS//Uy2PQJ2M6vKod1GuzzAXUJ1QvmidenWnYVaAucYqgndmPO6Xud/NC8JMCOAgLdCJW6NL5YFb… |  |
| P5 | dmarc-detect | info | _dmarc.securas.fr, "v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc@mailinblue.com; ruf=mailto:dmarc@mailinblue.com; ri=86400; aspf=s; adkim=s; fo=1", https://dmarc.org/, http… |  |
| P5 | dns-waf-detect | info | — |  |
| P5 | http-missing-security-headers | info | https://securas.fr/ |  |
| P5 | missing-sri | info | https://securas.fr/, https://manus-analytics.com/umami, https://files.manuscdn.com/manus-space-dispatcher/spaceEditor-DPV-_I11.js, https://plausible.io/js/script.file-downloads.has… |  |
| P5 | mx-fingerprint | info | 1 aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., https://www.cloudflare.com/learning/dns/dns… |  |
| P5 | mx-service-detector | info | — |  |
| P5 | nameserver-fingerprint | info | beau.ns.cloudflare.com., lisa.ns.cloudflare.com. |  |
| P5 | spf-record-detect | info | v=spf1 include:mx.ovh.com include:spf.sendinblue.com include:eu.transmail.net include:eu.zcsend.net mx include:_spf.google.com ~all", https://www.mimecast.com/content/how-to-create… |  |
| P5 | srv-service-detect | info | _autodiscover._tcp.securas.fr, SRV 0 0 443 pro1.mail.ovh.net., https://www.rfc-editor.org/rfc/rfc2srv, https://en.wikipedia.org/wiki/SRV_record |  |
| P5 | ssl-dns-names | info | securas.fr:443, securas.fr |  |
| P5 | ssl-issuer | info | securas.fr:443, Google Trust Services |  |
| P5 | tls-version | info | securas.fr:443, tls10 |  |
| P5 | txt-fingerprint | info | "brevo-code:7155099cecfa7c123d01beff5122ac76", "google-site-verification=1AmqyWIx4Jbqi9twtMYtCfcSEX_usnvoeihc2QgcuOA", "google-site-verification=c0GXk6gMTyyf_sb18hOdTkmllh_adlQU_Kl… |  |
| P5 | weak-cipher-suites | low | securas.fr:443, [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA], https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |  |
