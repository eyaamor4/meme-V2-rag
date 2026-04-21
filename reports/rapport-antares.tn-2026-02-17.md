A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 10 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://antares.tn/ (drupal 11). Scan du : 2026-02-17 09:56:39 UTC.
La surface d’attaque côté navigateur est élargie en raison de la présence de plusieurs vulnérabilités liées à la sécurité côté client, notamment des problèmes de Content Security Policy (CSP) et des attributs de ressource non sécurisés.

B - Vulnérabilités Prioritaires
- CSP: Failure to Define Directive with No Fallback
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) ne définit pas une directive essentielle, ce qui peut permettre l'exécution de code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

- CSP: script-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre des attaques de type XSS.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés lorsque possible.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que script-src ne contient plus unsafe-inline.

- CSP: style-src unsafe-inline
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut permettre des attaques de type XSS.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Identifier les styles inline dans les templates et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, vérifier que style-src ne contient plus unsafe-inline.

- Sub Resource Integrity Attribute Missing
  - Description : L'attribut d'intégrité des ressources est manquant sur les balises script ou link, ce qui peut permettre l'injection de code malveillant.
  - Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
  - Sévérité : MEDIUM
  - Recommandation : Ajouter l'attribut d'intégrité sur les ressources chargées depuis des domaines externes.
  - Vérification : Inspecter le code source HTML, vérifier que chaque balise script et link externe contient l'attribut integrity et crossorigin.

- CSP: Wildcard Directive
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
  - Description : La politique de sécurité du contenu (CSP) utilise une directive générique, ce qui peut permettre l'exécution de code malveillant.
  - Référence : 
    - https://www.w3.org/TR/CSP/
    - https://caniuse.com/#search=content+security+policy
    - https://content-security-policy.com/
    - https://github.com/HtmlUnit/htmlunit-csp
    - https://web.dev/articles/csp#resource-options
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Remplacer la directive générique par une liste précise d'hôtes de confiance.
  - Vérification : Exécuter curl -I https://[site] | grep -i content-security-policy, comparer la CSP déployée avec l'inventaire réel des ressources chargées.

C - Vulnérabilités Potentielles à Valider
- CVE-2008-6020
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant aux attaquants de exécuter des commandes SQL arbitraires. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
  - Catégorie OWASP : A03:2021 - Injection
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

- CVE-2011-4113
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant aux attaquants de exécuter des commandes SQL arbitraires. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
  - Catégorie OWASP : A03:2021 - Injection
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

- CVE-2024-13254
  - Statut : À valider manuellement
  - Description : Vulnérabilité d'insertion d'informations sensibles dans les données envoyées dans le module REST Views pour Drupal, permettant la navigation forcée. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
  - Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
  - Catégorie OWASP : A01:2021 - Broken Access Control
  - Sévérité : HIGH
  - Délai : À valider manuellement avant planification

D - Plan de remédiation
1. CSP: Failure to Define Directive with No Fallback : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle et les ajouter avec des valeurs restrictives — Délai : 30 jours
2. CSP: script-src unsafe-inline : Identifier les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés lorsque possible — Délai : 30 jours
3. CSP: style-src unsafe-inline : Identifier les styles inline dans les templates et les déplacer vers des feuilles CSS servies depuis des sources approuvées — Délai : 30 jours
4. Sub Resource Integrity Attribute Missing : Ajouter l'attribut d'intégrité sur les ressources chargées depuis des domaines externes — Délai : 30 jours
5. CSP: Wildcard Directive : Remplacer la directive générique par une liste précise d'hôtes de confiance — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de remédier à la vulnérabilité CSP: Failure to Define Directive with No Fallback, avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d'attaque et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 5 | 5 | 23 |

    **Niveau de risque global : MODÉRÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 10  
    **Vulnérabilités potentielles à valider :** 3  
    **Éléments informationnels :** 23  
    **Prioritaires confirmées (section B) :** 5 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | — | 10035-1 |
| P5 | vulnerability | low | Low | High | CSP: Notices | Politique CSP autorise 'unsafe-inline' pour les scripts et styles | 10055-3 |
| P5 | information | info | — | — | Technologie détectée : Cloudflare | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : Drupal | 11 |  |
| P5 | information | info | — | — | Technologie détectée : HTTP/3 | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : PHP | Version non fournie |  |
| P5 | information | info | — | — | aaaa-fingerprint | 2606:4700:3037::6815:2d1b, 2606:4700:3031::ac43:d014 |  |
| P5 | information | info | — | — | caa-fingerprint | — |  |
| P5 | vulnerability | info | — | — | deprecated-tls:tls_1.0 | tls10 |  |
| P5 | vulnerability | info | — | — | deprecated-tls:tls_1.1 | tls11 |  |
| P5 | information | info | — | — | dkim-record-detect | "v=DKIM1;t=s;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kDmU1YoAmYLEc3kjBGVjJIn7T6gZrbjcYWMg2SVXmAAlbuowpNXXKPEqD20F1ONleJgpioVa6e0cgEFHi27OliB+3pQjqHC2NAk2TveV1V0VmvWjGcZQVnV0buRd6… |  |
| P5 | information | info | — | — | dmarc-detect | ""v=DMARC1;p=reject;rua=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@rua.easydmarc.com;ruf=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@ruf.easydmar… |  |
| P5 | information | info | — | — | dns-waf-detect:cloudflare | — |  |
| P5 | information | info | — | — | drupal-detect | — |  |
| P5 | information | info | — | — | drupal-login | — |  |
| P5 | information | info | — | — | http-missing-security-headers:clear-site-data | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-embedder-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-opener-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:cross-origin-resource-policy | — |  |
| P5 | vulnerability | info | — | — | http-missing-security-headers:permissions-policy | — |  |
| P5 | information | info | — | — | http-missing-security-headers:x-permitted-cross-domain-policies | — |  |
| P5 | vulnerability | info | — | — | missing-sri | https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js, https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js |  |
| P5 | information | info | — | — | mx-fingerprint | 10 alt3.aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 1 aspmx.l.google.com. |  |
| P5 | information | info | — | — | mx-service-detector:Google Apps | — |  |
| P5 | information | info | — | — | nameserver-fingerprint | sri.ns.cloudflare.com., brianna.ns.cloudflare.com. |  |
| P5 | information | info | — | — | spf-record-detect | "v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"" |  |
| P5 | vulnerability | info | — | — | ssl-dns-names | antares.tn, *.antares.tn |  |
| P5 | vulnerability | info | — | — | ssl-issuer | Google Trust Services |  |
| P5 | vulnerability | info | — | — | tls-version | tls10 |  |
| P5 | information | info | — | — | txt-fingerprint | ""v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"",""MS=30DD2F2CD0F16D7EA3365B56D58C6E468916806D"",""ahrefs-site-verification_f15e967d15c60d7aaf91839236b91319da7e012e9f5… |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.0 | [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | vulnerability | low | — | — | weak-cipher-suites:tls-1.1 | [tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | vulnerability | info | — | — | weak-csp-detect:unsafe-script-src | Politique CSP autorise 'unsafe-inline' pour les scripts et styles |  |
| P5 | vulnerability | info | — | — | wildcard-tls | CN: antares.tn, SAN: [antares.tn *.antares.tn] |  |
| P5 | information | info | — | — | xss-deprecated-header | 1; mode=block |  |
