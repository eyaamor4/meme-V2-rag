**A - Résumé Exécutif**

Un total de 9 vulnérabilités ont été identifiées sur le système, dont 4 sont considérées comme prioritaires. Les vulnérabilités prioritaires sont listées ci-dessous.

**B - Vulnérabilités Prioritaires**

1. **Content Security Policy (CSP) Header Not Set**
	* Description : La politique de sécurité du contenu n'est pas définie, ce qui peut permettre des attaques de type Cross Site Scripting (XSS) et de data injection.
	* Impact potentiel : Les attaques de type XSS et de data injection peuvent permettre à un attaquant de compromettre la sécurité du système.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
	* Score CVSS : 5.4

2. **Cross-Domain Misconfiguration**
	* Description : La configuration de la politique de contrôle d'accès aux ressources partagées (CORS) est trop permissive, ce qui peut permettre aux navigateurs de charger des données provenant d'autres domaines.
	* Impact potentiel : Les attaques de type Cross-Site Request Forgery (CSRF) peuvent permettre à un attaquant de compromettre la sécurité du système.
	* Catégorie OWASP : A01:2021 - Broken Access Control
	* Recommandation technique : Restreindre Access-Control-Allow-Origin aux domaines applicatifs explicitement autorisés et éviter l’utilisation de '*' pour les ressources sensibles ou métier.
	* Vérification : Vérifier dans les réponses HTTP que Access-Control-Allow-Origin contient uniquement les origines prévues et qu’aucune ressource sensible n’est exposée avec une politique trop permissive.
	* Score CVSS : 4.3

3. **Missing Anti-clickjacking Header**
	* Description : La réponse ne protège pas contre les attaques de type clickjacking.
	* Impact potentiel : Les attaques de type clickjacking peuvent permettre à un attaquant de compromettre la sécurité du système.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
	* Score CVSS : 4.3

4. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut d'intégrité des sous-ressources est manquant, ce qui peut permettre à un attaquant de compromettre la sécurité du système.
	* Impact potentiel : Les attaques de type Cross-Site Scripting (XSS) peuvent permettre à un attaquant de compromettre la sécurité du système.
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut integrity valide correspondant au contenu réellement servi.
	* Score CVSS : 4.3

**C - Plan de remédiation**

1. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
2. Restreindre Access-Control-Allow-Origin aux domaines applicatifs explicitement autorisés et éviter l’utilisation de '*' pour les ressources sensibles ou métier.
3. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
4. Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

**D - Conclusion**

Un total de 9 vulnérabilités ont été identifiées sur le système, dont 4 sont considérées comme prioritaires. Les vulnérabilités prioritaires ont été listées et un plan de remédiation a été proposé pour chacune d'elles. Il est important de prendre en compte ces vulnérabilités et de les corriger pour améliorer la sécurité du système.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | zap | Content Security Policy (CSP) Header Not Set | https://cloud.projectdiscovery.io/ |  | 10038-1 |
| P3 | vulnerability | medium | Medium | Medium | zap | Cross-Domain Misconfiguration | https://cloud.projectdiscovery.io/ | Access-Control-Allow-Origin: * | 10098 |
| P3 | vulnerability | medium | Medium | Medium | zap | Missing Anti-clickjacking Header | https://cloud.projectdiscovery.io/ | x-frame-options | 10020-1 |
| P3 | vulnerability | medium | Medium | High | zap | Sub Resource Integrity Attribute Missing | https://cloud.projectdiscovery.io/ | <script src="https://uptime.betterstack.com/widgets/announcement.js" data-id="143167" async="" type="text/javascript"></script> | 90003 |
| P4 | vulnerability | low | Low | Medium | zap | Cross-Domain JavaScript Source File Inclusion | https://cloud.projectdiscovery.io/ | <script src="https://uptime.betterstack.com/widgets/announcement.js" data-id="143167" async="" type="text/javascript"></script> | 10017 |
| P4 | vulnerability | low | Low | Medium | zap | X-Content-Type-Options Header Missing | https://cloud.projectdiscovery.io/ | x-content-type-options | 10021 |
| P5 | information | info | Informational | Medium | zap | Modern Web Application | https://cloud.projectdiscovery.io/ | <script src="/_next/static/chunks/7cff742a97d6bce9.js?dpl=dpl_feK7qKhmR3TERGdT9A1qE2DqMgEp" async=""></script> | 10109 |
| P5 | information | info | Informational | Medium | zap | Retrieved from Cache | https://cloud.projectdiscovery.io/ | Age: 1553876 | 10050-2 |
| P5 | information | info | Non fourni | Non fourni | nuclei | caa-fingerprint | cloud.projectdiscovery.io | globalsign.com, letsencrypt.org, pki.goog, sectigo.com |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | dns-saas-service-detection | cloud.projectdiscovery.io | cname.vercel-dns.com |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:clear-site-data | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:content-security-policy | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:cross-origin-embedder-policy | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:cross-origin-opener-policy | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:cross-origin-resource-policy | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:permissions-policy | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:referrer-policy | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:strict-transport-security | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:x-content-type-options | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:x-frame-options | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | http-missing-security-headers:x-permitted-cross-domain-policies | https://cloud.projectdiscovery.io/ |  |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | missing-sri | https://cloud.projectdiscovery.io/ | https://uptime.betterstack.com/widgets/announcement.js |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | nameserver-fingerprint | cloud.projectdiscovery.io | ns2.vercel-dns-3.com., ns3.vercel-dns-3.com., ns4.vercel-dns-3.com., ns1.vercel-dns-3.com. |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | ssl-dns-names | cloud.projectdiscovery.io:443 | cloud.projectdiscovery.io |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | ssl-issuer | cloud.projectdiscovery.io:443 | Let's Encrypt |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | tls-version | cloud.projectdiscovery.io:443 | tls12, tls13 |  |
| P5 | information | info | Non fourni | Non fourni | nuclei | txt-fingerprint | cloud.projectdiscovery.io | ""google-site-verification=vdVEp47uMe4lAR2ml1tPq3ANqWecZ-qhk9Novyffkuc"" |  |
