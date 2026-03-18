**A - Résumé Exécutif**

Un total de 165 vulnérabilités a été identifié. Parmi celles-ci, 5 vulnérabilités sont considérées comme prioritaires.

**B - Vulnérabilités Prioritaires**

1. **CSP: Failure to Define Directive with No Fallback**
	* Description : Le Content Security Policy (CSP) ne définit pas une directive qui n'a pas de fallback. Manquer ou exclure les directives est le même que permettre tout.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que les directives form-action, frame-ancestors, base-uri et object-src sont présentes avec des valeurs restrictives adaptées.
2. **CSP: Wildcard Directive**
	* Description : Le Content Security Policy (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certaines types d'attaques. Ces attaques incluent (mais ne sont pas limitées à) les attaques de Cross Site Scripting (XSS) et les attaques d'injection de données. Ces attaques sont utilisées pour tout, depuis le vol de données jusqu'à la déformation du site ou la distribution de logiciels malveillants. Le CSP fournit un ensemble de dossiers HTTP standards qui permettent aux propriétaires de site Web de déclarer les sources d'approbation de contenu que les navigateurs doivent être autorisés à charger sur cette page — les types couverts sont JavaScript, CSS, HTML frames, polices, images et objets embarqués tels que les applets Java, ActiveX, fichiers audio et vidéo.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
	* Vérification : Contrôler que les directives CSP n’utilisent plus de joker '*' ni de schéma trop permissif comme https: lorsqu’une liste d’hôtes précise peut être définie.
3. **CSP: script-src unsafe-inline**
	* Description : Le Content Security Policy (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certaines types d'attaques. Ces attaques incluent (mais ne sont pas limitées à) les attaques de Cross Site Scripting (XSS) et les attaques d'injection de données. Ces attaques sont utilisées pour tout, depuis le vol de données jusqu'à la déformation du site ou la distribution de logiciels malveillants. Le CSP fournit un ensemble de dossiers HTTP standards qui permettent aux propriétaires de site Web de déclarer les sources d'approbation de contenu que les navigateurs doivent être autorisés à charger sur cette page — les types couverts sont JavaScript, CSS, HTML frames, polices, images et objets embarqués tels que les applets Java, ActiveX, fichiers audio et vidéo.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
	* Vérification : Vérifier dans l’en-tête Content-Security-Policy que script-src ne contient plus 'unsafe-inline' et que les scripts inline nécessaires utilisent un nonce ou un hash.
4. **CSP: style-src unsafe-inline**
	* Description : Le Content Security Policy (CSP) est une couche de sécurité supplémentaire qui aide à détecter et à atténuer certaines types d'attaques. Ces attaques incluent (mais ne sont pas limitées à) les attaques de Cross Site Scripting (XSS) et les attaques d'injection de données. Ces attaques sont utilisées pour tout, depuis le vol de données jusqu'à la déformation du site ou la distribution de logiciels malveillants. Le CSP fournit un ensemble de dossiers HTTP standards qui permettent aux propriétaires de site Web de déclarer les sources d'approbation de contenu que les navigateurs doivent être autorisés à charger sur cette page — les types couverts sont JavaScript, CSS, HTML frames, polices, images et objets embarqués tels que les applets Java, ActiveX, fichiers audio et vidéo.
	* Référence : https://www.w3.org/TR/CSP/, https://caniuse.com/#search=content+security+policy, https://content-security-policy.com/, https://github.com/HtmlUnit/htmlunit-csp, https://web.dev/articles/csp#resource-options
	* Catégorie OWASP : A05:2021 - Security Misconfiguration
	* Recommandation technique : Supprimer 'unsafe-inline' de style-src et migrer les styles inline vers des feuilles CSS autorisées ou des hashes lorsque nécessaire.
	* Vérification : Vérifier que style-src ne contient plus 'unsafe-inline' et que les styles requis proviennent de fichiers CSS approuvés ou de hashes explicites.
5. **Sub Resource Integrity Attribute Missing**
	* Description : L'attribut d'intégrité est manquant sur une balise script ou link servie par un serveur externe. L'attribut d'intégrité empêche un attaquant qui a accès à ce serveur d'injecter un contenu malveillant.
	* Référence : https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
	* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
	* Recommandation technique : Ajouter un attribut d'intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.
	* Vérification : Vérifier dans le code HTML que chaque ressource externe concernée contient un attribut d'intégrité valide correspondant au contenu réellement servi.

**C - Plan de remédiation**

1. Définir explicitement les directives CSP sans fallback, notamment form-action, frame-ancestors, base-uri et object-src, selon les besoins exacts de l’application.
2. Remplacer les jokers CSP par une liste explicite et minimale de domaines de confiance pour chaque directive concernée.
3. Supprimer 'unsafe-inline' de script-src et utiliser des nonces ou des hashes pour autoriser uniquement les scripts inline légitimes.
4. Supprimer 'unsafe-inline' de style-src et migrer les styles inline vers des feuilles CSS autorisées ou des hashes lorsque nécessaire.
5. Ajouter un attribut d'intégrité et de cross-origin aux balises script ou link qui chargent des ressources externes stables depuis un CDN.

**D - Conclusion**

Un total de 165 vulnérabilités a été identifié. Parmi celles-ci, 5 vulnérabilités sont considérées comme prioritaires. Il est recommandé de mettre en œuvre les mesures de remédiation proposées pour atténuer ces vulnérabilités. Il est essentiel de vérifier que les corrections sont effectives et que les vulnérabilités ne sont pas réapparues.

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
