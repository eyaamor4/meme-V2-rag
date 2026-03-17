**A - Résumé Exécutif**

Aucune vulnérabilité prioritaire n'a été identifiée.

**B - Vulnérabilités Prioritaires**

1. **Content Security Policy (CSP) Header Not Set**
	* Description : La politique de sécurité du contenu (CSP) n'est pas définie. Cela signifie que les attaques de type Cross Site Scripting (XSS) et de données injectées ne peuvent pas être détectées et mises en échec.
	* Impact potentiel : Les attaques de type XSS et de données injectées peuvent permettre à un attaquant de compromettre la sécurité du site web et d'exécuter du code malveillant.
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
	* Score CVSS : 7.5

2. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut d'intégrité des sous-ressources (SRI) est manquant sur une balise script ou link chargée par un serveur externe. Cela signifie que les attaques de type XSS et de données injectées peuvent être menées avec succès.
	* Impact potentiel : Les attaques de type XSS et de données injectées peuvent permettre à un attaquant de compromettre la sécurité du site web et d'exécuter du code malveillant.
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut integrity valide correspondant au contenu réellement servi.
	* Score CVSS : 6.4

**C - Plan de remédiation**

1. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
2. Ajouter un attribut integrity et crossorigin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

**D - Conclusion**

Il est recommandé de mettre en œuvre les recommandations techniques mentionnées ci-dessus pour améliorer la sécurité du site web. Il est important de vérifier régulièrement les configurations et les mises à jour pour s'assurer que les vulnérabilités sont corrigées.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | zap | Content Security Policy (CSP) Header Not Set | https://themewagon.com/ |  | 10038-1 |
| P3 | vulnerability | medium | Medium | High | zap | Sub Resource Integrity Attribute Missing | https://themewagon.com/ | <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800;900&family=Nunito:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet"> | 90003 |
| P4 | vulnerability | low | Low | Medium | zap | Cross-Domain JavaScript Source File Inclusion | https://themewagon.com/ | <script type='text/javascript' src='https://widget.freshworks.com/widgets/69000001641.js' async defer></script> | 10017 |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Non fourni | https://themewagon.com/ |  |  |
