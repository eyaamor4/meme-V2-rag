**A - Résumé Exécutif**

Aucune vulnérabilité prioritaire identifiée.

**B - Vulnérabilités Prioritaires**

1. **Content Security Policy (CSP) Header Not Set**
	* Description : Le Content Security Policy (CSP) n'est pas configuré. Cela signifie que les attaques de type Cross Site Scripting (XSS) et de données injectées ne peuvent pas être détectées et mises en échec.
	* Impact potentiel : Les attaques de type XSS et de données injectées peuvent permettre à des attaquants de compromettre la sécurité du site web et d'exécuter du code malveillant.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
	* Score CVSS : 7.5

**C - Plan de remédiation**

1. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.

**D - Conclusion**

Il est important de prendre en compte la vulnérabilité du Content Security Policy (CSP) pour éviter les attaques de type XSS et de données injectées. La mise en place d'une politique de sécurité CSP appropriée peut aider à prévenir ces types d'attaques et à protéger la sécurité du site web.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | zap | Content Security Policy (CSP) Header Not Set | http://www.acti.fr/ |  | 10038-1 |
| P4 | vulnerability | low | Low | Medium | zap | Cookie No HttpOnly Flag | http://www.acti.fr/ | set-cookie: WEBSRVID | 10010 |
| P4 | vulnerability | low | Low | Medium | zap | Cookie without SameSite Attribute | http://www.acti.fr/ | set-cookie: WEBSRVID | 10054-1 |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Non fourni | http://www.acti.fr/ |  |  |
