**A - Résumé Exécutif**

Le système présente 23 vulnérabilités au total et 2 vulnérabilités prioritaires ont été identifiées. Il est essentiel de les corriger pour améliorer la sécurité du système.

**B - Vulnérabilités Prioritaires**

1. **Content Security Policy (CSP) Header Not Set**
	* Description : La politique de sécurité du contenu n'est pas définie, ce qui rend le site vulnérable aux attaques de type Cross Site Scripting (XSS).
	* Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique :
		+ Définir une politique CSP de base avec default-src 'self'.
		+ Déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.
		Vérification : Vérifier la présence de l’en-tête Content-Security-Policy en exécutant curl -I sur plusieurs pages HTML.

2. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut d'intégrité est manquant sur un script ou une balise link servie par un serveur externe, ce qui permet à un attaquant de injecter du contenu malveillant.
	* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique :
		+ Identifier les scripts et feuilles CSS chargés depuis des domaines externes.
		+ Ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
	Vérification : Vérifier la présence de integrity et crossorigin sur les balises script et link externes.

**C - Plan de remédiation**

1. Définir une politique CSP de base avec default-src 'self' pour le site web.
2. Ajouter explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors dans la politique CSP.
3. Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter integrity et crossorigin="anonymous" sur ces ressources.

**D - Conclusion**

Le système présente 23 vulnérabilités au total et 2 vulnérabilités prioritaires ont été identifiées. Il est essentiel de corriger ces vulnérabilités pour améliorer la sécurité du système. Le plan de remédiation consiste à définir une politique CSP de base, ajouter explicitement les directives nécessaires et identifier les scripts et feuilles CSS chargés depuis des domaines externes.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Source | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | zap | Content Security Policy (CSP) Header Not Set | https://themewagon.com/ |  | 10038-1 |
| P3 | vulnerability | medium | Medium | High | zap | Sub Resource Integrity Attribute Missing | https://themewagon.com/ | <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800;900&family=Nunito:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet"> | 90003 |
| P4 | vulnerability | low | Low | Medium | zap | Cross-Domain JavaScript Source File Inclusion | https://themewagon.com/ | <script type='text/javascript' src='https://widget.freshworks.com/widgets/69000001641.js' async defer></script> | 10017 |
| P5 | vulnerability | low | Non fourni | Non fourni | cve | Non fourni | https://themewagon.com/ |  |  |
