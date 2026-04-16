A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 0 vulnérabilités ont été retenues dans ce rapport, dont 0 sont prioritaires.
Niveau de risque global : FAIBLE. Niveau source : Non fourni. Cible : https://mandrillapp.com/ (prestashop Non fourni). Scan du : {'$date': '2025-12-23T11:01:02.243Z'}.

B - Vulnérabilités Prioritaires
Aucune vulnérabilité prioritaire identifiée.

C - Plan de remédiation

D - Conclusion
Le niveau de risque global est FAIBLE.
Le niveau brut source est Non fourni.
Il n'y a pas d'action prioritaire à signaler, car aucune vulnérabilité n'a été identifiée.
Le niveau de risque global reste FAIBLE, et aucune action urgente n'est requise.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise les vulnérabilités retenues dans le rapport principal après déduplication.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 0 | 0 | 25 |

    
    **Niveau de risque global : FAIBLE**

    **Éléments techniques listés en annexe :** 25 | **Vulnérabilités retenues dans le rapport :** 0 | **Prioritaires (section B) :** 0**

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication.*
    

## Annexe B - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P5 | information | info | — | — | [!] Missing security header: X-Frame-Options | https://mandrillapp.com/ | — |  | — |
| P5 | information | info | — | — | [+] Forbidden but exists: https://mandrillapp.com/admin-dev/ | https://mandrillapp.com/ | — |  | — |
| P5 | information | info | — | — | [+] Forbidden but exists: https://mandrillapp.com/admin/ | https://mandrillapp.com/ | — |  | — |
| P5 | information | info | — | — | [+] Forbidden but exists: https://mandrillapp.com/admin123/ | https://mandrillapp.com/ | — |  | — |
| P5 | information | info | — | — | [+] Forbidden but exists: https://mandrillapp.com/phpinfo.php | https://mandrillapp.com/ | — |  | — |
| P5 | information | info | — | — | caa-fingerprint | mandrillapp.com | — |  | — |
| P5 | information | info | — | — | dmarc-detect | _dmarc.mandrillapp.com | ""v=DMARC1; p=reject; rua=mailto:19ezfriw@ag.dmarcian.com;"" |  | — |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:permissions-policy | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:referrer-policy | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:x-frame-options | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | https://mandrillapp.com/login/?referrer=%2F | — |  | — |
| P5 | information | info | — | — | missing-cookie-samesite-strict | https://mandrillapp.com/ | MDSESSID=marh4041aucrsphie1c5ulid83; expires=Tue, 23 Dec 2025 21:00:37 GMT; Max-Age=36000; path=/; domain=mandrillapp.com; secure; HttpOnly; SameSite=Lax |  | — |
| P5 | information | info | — | — | mx-fingerprint | mandrillapp.com | 10 9656353.in1.mandrillapp.com., 20 9656353.in2.mandrillapp.com. |  | — |
| P5 | information | info | — | — | nameserver-fingerprint | mandrillapp.com | ns-1127.awsdns-12.org., ns-1934.awsdns-49.co.uk., ns-289.awsdns-36.com., ns-720.awsdns-26.net. |  | — |
| P5 | information | info | — | — | spf-record-detect | mandrillapp.com | "v=spf1 include:spf.mandrillapp.com ~all"" |  | — |
| P5 | information | info | — | — | ssl-dns-names | mandrillapp.com:443 | mandrillapp.com, www.mandrillapp.com, *.in1.mandrillapp.com, *.in2.mandrillapp.com, *.mandrillapp.com, *.us-west-2.tx-prod.prod.mandrillapp.com |  | — |
| P5 | information | info | — | — | ssl-issuer | mandrillapp.com:443 | DigiCert Inc |  | — |
| P5 | information | info | — | — | tls-version | mandrillapp.com:443 | tls12 |  | — |
| P5 | information | info | — | — | tls-version | mandrillapp.com:443 | tls13 |  | — |
| P5 | information | info | — | — | txt-fingerprint | mandrillapp.com | ""google-site-verification=2dux36j2swb0zcDthVB4cvIakenujxPx2S1DGvOvhpo"",""v=spf1 include:spf.mandrillapp.com ~all"",""yahoo-verification-key=J0O8RUMRbvSyIUKQS6MEPRheM44S/KBgM/v+/5AK23o="" |  | — |
| P5 | information | info | — | — | wildcard-tls | mandrillapp.com:443 | SAN: [mandrillapp.com www.mandrillapp.com *.in1.mandrillapp.com *.in2.mandrillapp.com *.mandrillapp.com *.us-west-2.tx-prod.prod.mandrillapp.com], CN: mandrillapp.com |  | — |
