A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 10 vulnérabilités ont été retenues dans ce rapport, dont 5 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://antares.tn/ (drupal 11). Scan du : 2026-02-17 09:56:39 UTC.
La surface d’attaque côté navigateur est élargie.

B - Vulnérabilités Prioritaires
[CSP: Failure to Define Directive with No Fallback]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité du contenu (CSP) ne définit pas une des directives qui n'a pas de fallback. L'absence ou l'exclusion de ces directives est la même chose que permettre n'importe quoi.
- Référence : https://www.w3.org/TR/CSP/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle parmi : form-action, frame-ancestors, base-uri, object-src. Ajouter uniquement les directives manquantes avec des valeurs restrictives.
- Vérification : 
Exécuter : curl -I https://antares.tn/ | grep -i content-security-policy
Lire la valeur complète de l’en-tête CSP récupéré.
Vérifier explicitement la présence des directives form-action, frame-ancestors, base-uri et object-src.

[CSP: script-src unsafe-inline]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité du contenu (CSP) permet l'exécution de scripts inline, ce qui peut permettre à un attaquant d'injecter du code malveillant.
- Référence : https://www.w3.org/TR/CSP/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier tous les scripts inline présents dans les templates HTML. Migrer les scripts inline vers des fichiers JS statiques versionnés lorsque possible.
- Vérification : 
Exécuter : curl -I https://antares.tn/ | grep -i content-security-policy
Lire la valeur complète de l’en-tête CSP.
Identifier la directive script-src dans la politique.

[CSP: style-src unsafe-inline]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité du contenu (CSP) permet l'injection de styles inline, ce qui peut permettre à un attaquant d'injecter du code malveillant.
- Référence : https://www.w3.org/TR/CSP/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Identifier les styles inline dans les templates et composants front-end. Déplacer les styles inline vers des feuilles CSS servies depuis des sources approuvées.
- Vérification : 
Exécuter : curl -I https://antares.tn/ | grep -i content-security-policy
Lire la valeur complète de l’en-tête CSP.
Identifier la directive style-src dans la politique.

[Sub Resource Integrity Attribute Missing]
- Description : L'attribut d'intégrité est manquant sur les balises script et link qui chargent des ressources externes, ce qui peut permettre à un attaquant d'injecter du code malveillant.
- Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Identifier les scripts et feuilles CSS chargés depuis des domaines externes. Ajouter integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
- Vérification : 
Exécuter : curl -s https://antares.tn/ | grep -i integrity
Identifier les balises script et link qui chargent des ressources externes (CDN, domaine tiers, URL absolue ou //domain).
Vérifier si ces balises contiennent un attribut integrity et crossorigin.

[CSP: Wildcard Directive]
  - Paramètre/Ressource affecté(e) : Content-Security-Policy
- Description : La politique de sécurité du contenu (CSP) utilise des directives génériques (*), ce qui peut permettre à un attaquant d'injecter du code malveillant.
- Référence : https://www.w3.org/TR/CSP/
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Remplacer * par une liste précise d’hôtes de confiance. Éviter les schémas génériques comme https: quand les domaines réels sont connus.
- Vérification : 
Exécuter : curl -I https://antares.tn/ | grep -i content-security-policy
Lire la valeur complète de l’en-tête CSP.
Rechercher explicitement le caractère '*' dans les directives concernées.

C - Vulnérabilités Potentielles à Valider
[CVE-2008-6020]
- Statut : À valider manuellement
- Description : Vulnérabilité d'injection SQL dans le module Views pour Drupal, permettant à un attaquant distant d'exécuter des commandes SQL arbitraires via des vecteurs non spécifiés liés à un filtre exposé sur les champs de texte CCK. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2008-6020
- Catégorie OWASP : A03:2021 - Injection
- Sévérité : HIGH
- Délai : À valider manuellement avant planification

[CVE-2011-4113]
- Statut : À valider manuellement
- Description : Vulnérabilité d'injection SQL dans le module Views avant la version 6.x-2.13 pour Drupal, permettant à un attaquant distant d'exécuter des commandes SQL arbitraires via des vecteurs liés aux filtres/arguments sur certains types de vues avec des configurations spécifiques d'arguments. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2011-4113
- Catégorie OWASP : A03:2021 - Injection
- Sévérité : HIGH
- Délai : À valider manuellement avant planification

[CVE-2024-13254]
- Statut : À valider manuellement
- Description : Vulnérabilité d'insertion d'informations sensibles dans les données envoyées dans Drupal REST Views, permettant la navigation forcée. Contexte : module détecté : views. Version non vérifiable — présence du module confirmée mais version exacte inconnue. Cette vulnérabilité peut ou non s'appliquer.
- Référence : https://nvd.nist.gov/vuln/detail/CVE-2024-13254
- Catégorie OWASP : A01:2021 - Broken Access Control
- Sévérité : HIGH
- Délai : À valider manuellement avant planification

D - Plan de remédiation
1. [CSP: Failure to Define Directive with No Fallback] : Identifier les directives CSP sans fallback qui sont absentes de la politique actuelle parmi : form-action, frame-ancestors, base-uri, object-src — Délai : 30 jours
2. [CSP: script-src unsafe-inline] : Identifier tous les scripts inline présents dans les templates HTML — Délai : 30 jours
3. [CSP: style-src unsafe-inline] : Identifier les styles inline dans les templates et composants front-end — Délai : 30 jours
4. [Sub Resource Integrity Attribute Missing] : Identifier les scripts et feuilles CSS chargés depuis des domaines externes — Délai : 30 jours
5. [CSP: Wildcard Directive] : Remplacer * par une liste précise d’hôtes de confiance — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de remédier à la vulnérabilité [CSP: Failure to Define Directive with No Fallback] dans un délai de 30 jours.
Il est essentiel de traiter les vulnérabilités identifiées pour réduire la surface d'attaque et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

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

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | Chargement de scripts depuis des domaines tiers | 10017 |
| P4 | Strict-Transport-Security Header Not Set | low | — | 10035-1 |
| P5 | CSP: Notices | low | Politique CSP autorise 'unsafe-inline' pour les scripts et styles | 10055-3 |
| P5 | Technologie détectée : Cloudflare | info | Version non fournie |  |
| P5 | Technologie détectée : Drupal | info | 11 |  |
| P5 | Technologie détectée : HTTP/3 | info | Version non fournie |  |
| P5 | Technologie détectée : PHP | info | Version non fournie |  |
| P5 | aaaa-fingerprint | info | 2606:4700:3037::6815:2d1b, 2606:4700:3031::ac43:d014 |  |
| P5 | caa-fingerprint | info | — |  |
| P5 | deprecated-tls:tls_1.0 | info | tls10 |  |
| P5 | deprecated-tls:tls_1.1 | info | tls11 |  |
| P5 | dkim-record-detect | info | "v=DKIM1;t=s;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kDmU1YoAmYLEc3kjBGVjJIn7T6gZrbjcYWMg2SVXmAAlbuowpNXXKPEqD20F1ONleJgpioVa6e0cgEFHi27OliB+3pQjqHC2NAk2TveV1V0VmvWjGcZQVnV0buRd6… |  |
| P5 | dmarc-detect | info | ""v=DMARC1;p=reject;rua=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@rua.easydmarc.com;ruf=mailto:8c0942cd@forensics.dmarc-report.com,mailto:28c31c5874@ruf.easydmar… |  |
| P5 | dns-waf-detect:cloudflare | info | — |  |
| P5 | drupal-detect | info | — |  |
| P5 | drupal-login | info | — |  |
| P5 | http-missing-security-headers:clear-site-data | info | — |  |
| P5 | http-missing-security-headers:cross-origin-embedder-policy | info | — |  |
| P5 | http-missing-security-headers:cross-origin-opener-policy | info | — |  |
| P5 | http-missing-security-headers:cross-origin-resource-policy | info | — |  |
| P5 | http-missing-security-headers:permissions-policy | info | — |  |
| P5 | http-missing-security-headers:x-permitted-cross-domain-policies | info | — |  |
| P5 | missing-sri | info | https://cdnjs.cloudflare.com/ajax/libs/enquire.js/2.1.6/enquire.min.js, https://cdnjs.cloudflare.com/ajax/libs/fontfaceobserver/2.1.0/fontfaceobserver.js |  |
| P5 | mx-fingerprint | info | 10 alt3.aspmx.l.google.com., 10 alt4.aspmx.l.google.com., 5 alt1.aspmx.l.google.com., 5 alt2.aspmx.l.google.com., 1 aspmx.l.google.com. |  |
| P5 | mx-service-detector:Google Apps | info | — |  |
| P5 | nameserver-fingerprint | info | sri.ns.cloudflare.com., brianna.ns.cloudflare.com. |  |
| P5 | spf-record-detect | info | "v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"" |  |
| P5 | ssl-dns-names | info | antares.tn, *.antares.tn |  |
| P5 | ssl-issuer | info | Google Trust Services |  |
| P5 | tls-version | info | tls10 |  |
| P5 | txt-fingerprint | info | ""v=spf1 mx ip4:151.80.213.177 include:_spf.google.com ~all"",""MS=30DD2F2CD0F16D7EA3365B56D58C6E468916806D"",""ahrefs-site-verification_f15e967d15c60d7aaf91839236b91319da7e012e9f5… |  |
| P5 | weak-cipher-suites:tls-1.0 | low | [tls10 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | weak-cipher-suites:tls-1.1 | low | [tls11 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] |  |
| P5 | weak-csp-detect:unsafe-script-src | info | Politique CSP autorise 'unsafe-inline' pour les scripts et styles |  |
| P5 | wildcard-tls | info | CN: antares.tn, SAN: [antares.tn *.antares.tn] |  |
| P5 | xss-deprecated-header | info | 1; mode=block |  |
