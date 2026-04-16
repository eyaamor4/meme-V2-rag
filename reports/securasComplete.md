A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 18 vulnérabilités ont été retenues dans ce rapport, dont 7 sont prioritaires.
Le rapport s'appuie sur 39 findings techniques dédupliqués au total, incluant les vulnérabilités retenues et, le cas échéant, des éléments informationnels.
Niveau de risque global : ÉLEVÉ. Niveau source déclaré : medium. Cible : https://securas.fr/ (inconnu Non fourni). Scan du : 2026-03-13 11:51:22 UTC.
Le grade SSL/TLS obtenu est B.

La surface d'attaque TLS est étendue et le risque de downgrade ou d'affaiblissement cryptographique est accru.
La surface d'attaque XSS est élargie et le risque combiné est plus élevé.

B - Vulnérabilités Prioritaires
1. Protocole déprécié activé : TLS 1.0
- Description : Le protocole TLS 1.0 est activé, ce qui constitue un protocole déprécié.
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Recommandation : Désactiver les protocoles dépréciés et conserver uniquement les suites recommandées pour TLS 1.2 et TLS 1.3.
- Vérification : openssl s_client -connect [host]:443 -tls1_0

2. Vulnérabilité TLS : LUCKY13
- Description : La vulnérabilité LUCKY13 est potentielllement présente, ce qui pourrait permettre une attaque de type CBC.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2013-0169
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Recommandation : Désactiver les suites CBC anciennes ou faibles et conserver uniquement les suites recommandées pour TLS 1.2 et TLS 1.3.
- Vérification : openssl s_client -connect [host]:443 -tls1_2

3. Vulnérabilité TLS : SWEET32
- Description : La vulnérabilité SWEET32 est présente, ce qui pourrait permettre une attaque de type 64 bit block ciphers.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2016-2183
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Recommandation : Désactiver les suites CBC anciennes ou faibles et conserver uniquement les suites recommandées pour TLS 1.2 et TLS 1.3.
- Vérification : openssl s_client -connect [host]:443 -tls1_2

4. Protocole déprécié activé : TLS 1.1
- Description : Le protocole TLS 1.1 est activé, ce qui constitue un protocole déprécié.
- Référence : https://www.rfc-editor.org/rfc/rfc8996
- Catégorie OWASP : A02:2021 - Cryptographic Failures
- Recommandation : Désactiver les protocoles dépréciés et conserver uniquement les suites recommandées pour TLS 1.2 et TLS 1.3.
- Vérification : openssl s_client -connect [host]:443 -tls1_1

5. Content Security Policy (CSP) Header Not Set
- Description : L'en-tête Content Security Policy (CSP) n'est pas défini.
- Référence : Non fourni
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Définir une politique CSP de base avec default-src 'self'.
- Vérification : curl -I https://[site] | grep -i content-security-policy

6. Missing Anti-clickjacking Header
- Description : L'en-tête anti-clickjacking est manquant.
- Référence : Non fourni
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : curl -I https://[site] | grep -i x-frame-options

7. Sub Resource Integrity Attribute Missing
- Description : L'attribut Sub Resource Integrity est manquant.
- Référence : Non fourni
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Recommandation : Ajouter l'attribut integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
- Vérification : curl -s https://[site] | grep -i 'integrity='

C - Plan de remédiation
1. Protocole déprécié activé : TLS 1.0 : Désactiver le protocole TLS 1.0 — Délai : sous 24h
2. Vulnérabilité TLS : LUCKY13 : Désactiver les suites CBC anciennes ou faibles — Délai : sous 24h
3. Vulnérabilité TLS : SWEET32 : Désactiver les suites CBC anciennes ou faibles — Délai : sous 24h
4. Protocole déprécié activé : TLS 1.1 : Désactiver le protocole TLS 1.1 — Délai : 7 jours
5. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base — Délai : 7 jours
6. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN — Délai : 7 jours
7. Sub Resource Integrity Attribute Missing : Ajouter l'attribut integrity et crossorigin=\"anonymous\" — Délai : 30 jours

D - Conclusion
Le niveau de risque global est ÉLEVÉ.
Le niveau brut source déclaré est medium.
L'action prioritaire la plus critique est de désactiver le protocole TLS 1.0, qui doit être effectuée sous 24h.
Il est essentiel de traiter ces vulnérabilités pour assurer la sécurité de l'application.


## Tableau de synthèse des vulnérabilités

> **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités retenues dans le rapport principal après déduplication.
> Les éléments informationnels sont comptabilisés séparément.

| 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 1 | 8 | 9 | 12 |

**Niveau de risque global : ÉLEVÉ**

**Findings techniques dédupliqués (total) :** 39  
**Faiblesses et vulnérabilités retenues dans le rapport :** 18
**Éléments informationnels :** 12  
**Prioritaires (section B) :** 7  

> ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*


## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://securas.fr | — |  | — |
| P4 | vulnerability | medium | — | — | Port sensible exposé : 2082/infowave | https://securas.fr/ | infowave |  | Détecté via scan réseau (ports) |
| P4 | vulnerability | medium | — | — | Port sensible exposé : 2086/gnunet | https://securas.fr/ | gnunet |  | Détecté via scan réseau (ports) |
| P4 | vulnerability | low | Low | Medium | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | https://securas.fr/api/ | — |  | — |
| P5 | information | info | — | — | Grade SSL/TLS dégradé (SSL Labs) | https://securas.fr/ | — |  | Détecté via testssl.sh |
| P5 | information | info | Informational | Low | Information Disclosure - Suspicious Comments | https://securas.fr | — |  | — |
| P5 | information | info | Informational | Medium | Modern Web Application | https://securas.fr | — |  | — |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2083/radsec | https://securas.fr/ | radsec |  | Détecté via scan réseau (ports) |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2087/eli | https://securas.fr/ | eli |  | Détecté via scan réseau (ports) |
| P5 | vulnerability | low | — | — | Port sensible exposé : 2095/nbx-ser | https://securas.fr/ | nbx-ser |  | Détecté via scan réseau (ports) |
| P5 | vulnerability | low | — | — | Port sensible exposé : 8080/http-proxy | https://securas.fr/ | http-proxy (cloudflare) |  | Détecté via scan réseau (full) |
| P5 | vulnerability | low | — | — | Port sensible exposé : 8880/cddbp-alt | https://securas.fr/ | cddbp-alt |  | Détecté via scan réseau (ports) |
| P5 | information | info | Informational | Low | Re-examine Cache-control Directives | https://securas.fr/api/ | — |  | — |
| P5 | vulnerability | low | — | — | Vulnérabilité TLS : BREACH | https://securas.fr/ | — |  | Détecté via testssl.sh |
| P5 | information | info | — | — | aaaa-fingerprint | securas.fr | 2a06:98c1:3121::, 2a06:98c1:3120::, https://www.cloudflare.com/learning/dns/dns-records/dns-aaaa-record/, https://en.wikipedia.org/wiki/IPv6_address |  | — |
| P5 | information | info | — | — | caa-fingerprint | securas.fr | https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record |  | — |
| P5 | information | info | — | — | deprecated-tls | securas.fr:443 | securas.fr:443, tls11, https://ssl-config.mozilla.org/#config=intermediate |  | — |
| P5 | information | info | — | — | dkim-record-detect | google._domainkey.securas.fr | google._domainkey.securas.fr, v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAptM3rpC2LA5+yS//Uy2PQJ2M6vKod1GuzzAXUJ1QvmidenWnYVaAucYqgndmPO6Xud/NC8JMCOAgLdCJW6NL5YFb/+4GKijYsfb9tLSKToynI0+LO5VO4uII/za7WyOnPHK2NGo1b0POLEb8knhY+91fdqrq/q0woNHJMgOYzrY86VP32LWFdXoVzPm25UpXr" "x6peUA82EBzJw/ubqBZtphFWm7ptlZmLcP0nRxXPHUPA7engrHc+4R+zAmPajSNQuuqVQ0US1+u3yqZ2S2UHepKICrHV5Zy3B58NE2zKfRiEyvUTQQdNrtNWjV4g6jY5pBBpVy6ynjy/x3/UGh6wwIDAQAB", https://www.rfc-editor.org/rfc/rfc6376, https://dkim.org/ |  | — |
| P5 | information | info | — | — | dmarc-detect | _dmarc.securas.fr | _dmarc.securas.fr, "v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc@mailinblue.com; ruf=mailto:dmarc@mailinblue.com; ri=86400; aspf=s; adkim=s; fo=1", https://dmarc.org/, https://dmarc.org/wiki/FAQ#Why_is_DMARC_important.3F |  | — |
| P5 | information | info | — | — | dns-waf-detect | securas.fr | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers | https://securas.fr/ | https://securas.fr/ |  | — |
| P5 | information | info | — | — | missing-sri | https://securas.fr/ | https://securas.fr/, https://manus-analytics.com/umami, https://files.manuscdn.com/manus-space-dispatcher/spaceEditor-DPV-_I11.js, https://plausible.io/js/script.file-downloads.hash.outbound-links.pageview-props.revenue.tagged-events.js, https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html#subresource-integrity, https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity |  | — |
| P5 | information | info | — | — | mx-fingerprint | securas.fr | 1 aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 10 alt3.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/, https://mxtoolbox.com/ |  | — |
| P5 | information | info | — | — | mx-service-detector | securas.fr | — |  | — |
| P5 | information | info | — | — | nameserver-fingerprint | securas.fr | beau.ns.cloudflare.com., lisa.ns.cloudflare.com. |  | — |
| P5 | information | info | — | — | spf-record-detect | securas.fr | v=spf1 include:mx.ovh.com include:spf.sendinblue.com include:eu.transmail.net include:eu.zcsend.net mx include:_spf.google.com ~all", https://www.mimecast.com/content/how-to-create-an-spf-txt-record |  | — |
| P5 | information | info | — | — | srv-service-detect | _autodiscover._tcp.securas.fr | _autodiscover._tcp.securas.fr, SRV 0 0 443 pro1.mail.ovh.net., https://www.rfc-editor.org/rfc/rfc2srv, https://en.wikipedia.org/wiki/SRV_record |  | — |
| P5 | information | info | — | — | ssl-dns-names | securas.fr:443 | securas.fr:443, securas.fr |  | — |
| P5 | information | info | — | — | ssl-issuer | securas.fr:443 | securas.fr:443, Google Trust Services |  | — |
| P5 | information | info | — | — | tls-version | securas.fr:443 | securas.fr:443, tls10 |  | — |
| P5 | information | info | — | — | txt-fingerprint | securas.fr | "brevo-code:7155099cecfa7c123d01beff5122ac76", "google-site-verification=1AmqyWIx4Jbqi9twtMYtCfcSEX_usnvoeihc2QgcuOA", "google-site-verification=c0GXk6gMTyyf_sb18hOdTkmllh_adlQU_KlBkqtvRjk", "google-site-verification=yjSlJKszW0p3razG0GIKV2OQRNWV22sDLtqhUVgHCvc", "Sendinblue-code:6aa544db6c672539ad19ef14ae007106", "atlassian-domain-verification=ybyIlsJBaJUP0hccv3CYg7fee6kd0ZZauAy13ZpKCqUG3wyeH/LuAdLJZLf3Y4Ca", "atlassian-sending-domain-verification=9a0fdee2-4eb0-4f7e-8b23-41b114833003", "v=spf1 include:mx.ovh.com include:spf.sendinblue.com include:eu.transmail.net include:eu.zcsend.net mx include:_spf.google.com ~all", "1\|www.securas.fr", "detectify-verification=f86fa3d32bcaadefcb811ba06769b94c", "v=DMARC1; p=reject; rua=mailto:contact@securas.fr, contact@securas.fr; pct=100; adkim=s; aspf=s.", https://www.netspi.com/blog/technical/network-penetration-testing/analyzing-dns-txt-records-to-fingerprint-service-providers/ |  | — |
| P5 | vulnerability | low | — | — | weak-cipher-suites | securas.fr:443 | securas.fr:443, [tls10 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA], https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |  | — |
