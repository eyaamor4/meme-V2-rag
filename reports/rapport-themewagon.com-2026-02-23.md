**A - Résumé Exécutif**

Le système cible présente 23 vulnérabilités au total. Parmi elles, 2 sont considérées comme prioritaires. Il est essentiel de les corriger pour améliorer la sécurité globale du système.

**B - Vulnérabilités Prioritaires**

1. **Content Security Policy (CSP) Header Not Set**
	* Description : La politique de sécurité des contenus n'est pas configurée, ce qui rend le site vulnérable aux attaques de type Cross Site Scripting (XSS).
	* Référence : https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires comme script-src, style-src, img-src, font-src et frame-ancestors.
	* Vérification : Exécuter curl -I sur plusieurs pages HTML pour vérifier la présence de l’en-tête Content-Security-Policy.

2. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut d'intégrité des sous-ressources est manquant, ce qui permet à un attaquant de injecter du contenu malveillant.
	* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
	* Vérification : Vérifier la présence de integrity et crossorigin sur les balises script et link externes.

**C - Plan de remédiation**

1. Définir une politique CSP de base avec default-src 'self' pour le site cible.
2. Identifier les scripts et feuilles CSS chargés depuis des domaines externes et ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.

**D - Conclusion**

Il est essentiel de corriger ces deux vulnérabilités prioritaires pour améliorer la sécurité globale du système. Il convient également de prendre en compte les 21 autres vulnérabilités détectées pour garantir une sécurité maximale.

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | Content Security Policy (CSP) Header Not Set | https://themewagon.com/ |  | 10038-1 |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://themewagon.com/ | <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800;900&family=Nunito:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet"> | 90003 |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://themewagon.com/ | <script type='text/javascript' src='https://widget.freshworks.com/widgets/69000001641.js' async defer></script> | 10017 |
| P5 | vulnerability | low | Non fourni | Non fourni | Non fourni | https://themewagon.com/ |  |  |
