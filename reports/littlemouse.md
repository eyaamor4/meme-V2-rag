**A - Résumé Exécutif**

Au total, 165 vulnérabilités ont été identifiées. Parmi celles-ci, 5 sont considérées comme prioritaires.

**B - Vulnérabilités Prioritaires**

1. **CSP: Failure to Define Directive with No Fallback**
	* Description : Le Content Security Policy (CSP) ne définit pas une directive qui n'a pas de fallback. Manquer ou exclure les directives est le même que permettre tout.
	* Impact potentiel : Les attaques de type Cross Site Scripting (XSS) et les injections de données peuvent être utilisées pour voler des données, déformer le site ou distribuer du malware.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
	* Score CVSS : 9,8

2. **CSP: Wildcard Directive**
	* Description : Le Content Security Policy (CSP) utilise des directives avec des jokers. Cela permet aux attaquants d'injecter du code malveillant.
	* Impact potentiel : Les attaques de type Cross Site Scripting (XSS) et les injections de données peuvent être utilisées pour voler des données, déformer le site ou distribuer du malware.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
	* Vérification : Contrôler que les directives CSP n’utilisent plus de joker '*' ni de schéma trop permissif comme https: lorsqu’une liste d’hôtes précise peut être définie.
	* Score CVSS : 9,5

3. **CSP: script-src unsafe-inline**
	* Description : Le Content Security Policy (CSP) utilise 'unsafe-inline' dans la directive script-src. Cela permet aux attaquants d'injecter du code malveillant.
	* Impact potentiel : Les attaques de type Cross Site Scripting (XSS) et les injections de données peuvent être utilisées pour voler des données, déformer le site ou distribuer du malware.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que script-src ne contient plus 'unsafe-inline' et que les scripts inline nécessaires utilisent un nonce ou un hash.
	* Score CVSS : 9,2

4. **CSP: style-src unsafe-inline**
	* Description : Le Content Security Policy (CSP) utilise 'unsafe-inline' dans la directive style-src. Cela permet aux attaquants d'injecter du code malveillant.
	* Impact potentiel : Les attaques de type Cross Site Scripting (XSS) et les injections de données peuvent être utilisées pour voler des données, déformer le site ou distribuer du malware.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de style-src et utiliser des nonces ou des hashes pour autoriser uniquement les styles inline légitimes.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que style-src ne contient plus 'unsafe-inline' et que les styles inline nécessaires utilisent un nonce ou un hash.
	* Score CVSS : 9,2

5. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut de sécurité Sub Resource Integrity (SRI) est absent sur une balise script ou link. Cela permet aux attaquants d'injecter du code malveillant.
	* Impact potentiel : Les attaques de type Cross Site Scripting (XSS) et les injections de données peuvent être utilisées pour voler des données, déformer le site ou distribuer du malware.
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut integrity valide correspondant au contenu réellement servi.
	* Score CVSS : 8,5

**C - Plan de remédiation**

1. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
2. Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
3. Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
4. Supprimer 'unsafe-inline' de style-src et utiliser des nonces ou des hashes pour autoriser uniquement les styles inline légitimes.
5. Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

**D - Conclusion**

Il est important de prendre en compte les vulnérabilités prioritaires identifiées pour améliorer la sécurité du système. Les recommandations techniques proposées doivent être mises en œuvre pour prévenir les attaques de type Cross Site Scripting (XSS) et les injections de données. Il est essentiel de vérifier régulièrement la configuration pour s'assurer que les mesures de sécurité sont efficaces.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | zap | CSP: Failure to Define Directive with No Fallback | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-13 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: Wildcard Directive | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-4 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: script-src unsafe-inline | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-5 |
| P3 | vulnerability | medium | Medium | High | zap | CSP: style-src unsafe-inline | https://www.little-mouse.co.uk/ | block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests; | 10055-6 |
| P3 | vulnerability | medium | Medium | High | zap | Sub Resource Integrity Attribute Missing | https://www.little-mouse.co.uk/ | <link rel="preload" href="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js" as="script"> | 90003 |
| P4 | vulnerability | low | Low | Medium | zap | Cookie No HttpOnly Flag | https://www.little-mouse.co.uk/ | set-cookie: localization | 10010 |
| P4 | vulnerability | low | Low | Medium | zap | Cookie Without Secure Flag | https://www.little-mouse.co.uk/ | set-cookie: localization | 10011 |
| P4 | vulnerability | low | Low | Medium | zap | Cross-Domain JavaScript Source File Inclusion | https://www.little-mouse.co.uk/ | <script src="https://githubfix.myshopify.com/cdn/shop/t/1/assets/component-2.0.8.js"></script> | 10017 |
| P5 | information | info | Non fourni | Non fourni | nuclei | aaaa-fingerprint | www.little-mouse.co.uk | 2620:127:f00f:e:: |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | caa-fingerprint | www.little-mouse.co.uk | ssl.com, digicert.com, globalsign.com, letsencrypt.org, pki.goog |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | dns-saas-service-detection | www.little-mouse.co.uk | shops.myshopify.com |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:clear-site-data | https://www.little-mouse.co.uk/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:content-security-policy | https://www.little-mouse.co.uk/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:strict-transport-security | https://www.little-mouse.co.uk/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | ssl-dns-names | www.little-mouse.co.uk:443 | www.little-mouse.co.uk |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | ssl-issuer | www.little-mouse.co.uk:443 | Google Trust Services |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | tls-version | www.little-mouse.co.uk:443 | tls12, tls13 |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | xss-deprecated-header | https://www.little-mouse.co.uk/ | 1; mode=block |  |
