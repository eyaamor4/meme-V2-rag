A - Résumé Exécutif

28 vulnérabilités ont été identifiées au total, dont 8 sont prioritaires.

B - Vulnérabilités Prioritaires

**1. CSP: Failure to Define Directive with No Fallback**
* Description : La politique de sécurité du contenu (CSP) ne définit pas une directive qui n'a pas de fallback. Manquer ou exclure les directives est le même que permettre tout.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
* Vérification : Exécuter curl -I sur plusieurs pages HTML et vérifier la présence des directives form-action, frame-ancestors, base-uri et object-src.

**2. CSP: Wildcard Directive**
* Description : La politique de sécurité du contenu (CSP) utilise une directive générique qui permet tout.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Remplacer * par une liste précise d’hôtes de confiance.
* Vérification : Comparer la CSP déployée avec l’inventaire réel des ressources chargées.

**3. CSP: script-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) permet les scripts inline non sécurisés.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés.
* Vérification : Vérifier que script-src ne contient plus unsafe-inline.

**4. CSP: style-src unsafe-inline**
* Description : La politique de sécurité du contenu (CSP) permet les styles inline non sécurisés.
* Référence :
  - https://www.w3.org/TR/CSP/
  - https://caniuse.com/#search=content+security+policy
  - https://content-security-policy.com/
  - https://github.com/HtmlUnit/htmlunit-csp
  - https://web.dev/articles/csp#resource-options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
* Vérification : Contrôler le rendu visuel des pages après externalisation des styles.

**5. CVE-2023-5561**
* Score CVSS : 5.3
* Description : WordPress ne restreint pas correctement les champs utilisateur accessibles via l'API REST, permettant aux attaquants non authentifiés de découvrir les adresses e-mail des utilisateurs qui ont publié des articles publics sur un site affecté.
* Référence :
  - https://lists.debian.org/debian-lts-announce/2023/11/msg00014.html
  - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
  - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
* Catégorie OWASP : A01:2021 - Broken Access Control
* Recommandation technique : Mettre à jour WordPress à une version corrigée.
* Vérification : Tester les vues avec plusieurs rôles.

**6. CVE-2024-2473**
* Score CVSS : 5.3
* Description : Le plugin WPS Hide Login pour WordPress est vulnérable à la divulgation de la page de connexion en toutes versions jusqu'à et y compris 1.9.15.2, en raison d'une faille qui se crée lorsque le paramètre 'action=postpass' est fourni.
* Référence :
  - https://plugins.trac.wordpress.org/changeset/3099109/wps-hide-login
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/fd21c7d3-a5f1-4c3a-b6ab-0a979f070a62?source=cve
* Catégorie OWASP : Non fourni
* Recommandation technique : Mettre à jour le plugin WPS Hide Login à une version corrigée.
* Vérification : Tester les vues avec plusieurs rôles.

**7. Missing Anti-clickjacking Header**
* Description : La réponse ne protège pas contre les attaques de 'ClickJacking'. Elle devrait inclure soit la directive 'frame-ancestors' dans la politique de sécurité du contenu (CSP) ou X-Frame-Options.
* Référence :
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
* Catégorie OWASP : A05:2021 - Security Misconfiguration
* Recommandation technique : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
* Vérification : Exécuter curl -I sur plusieurs pages HTML.

**8. Sub Resource Integrity Attribute Missing**
* Description : L'attribut d'intégrité est manquant sur une balise script ou link servie par un serveur externe. Cet attribut empêche les attaquants qui ont accès à ce serveur de injecter du contenu malveillant.
* Référence :
  - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
* Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
* Recommandation technique : Ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
* Vérification : Vérifier la présence de integrity et crossorigin sur les balises script et link externes.

C - Plan de remédiation

1. CSP: Failure to Define Directive with No Fallback
	* Ajouter explicitement form-action, frame-ancestors, base-uri et object-src dans l’en-tête CSP.
2. CSP: Wildcard Directive
	* Remplacer * par une liste précise d’hôtes de confiance.
3. CSP: script-src unsafe-inline
	* Identifier tous les scripts inline présents dans les templates HTML et les migrer vers des fichiers JS statiques versionnés.
4. CSP: style-src unsafe-inline
	* Identifier les styles inline dans les templates et composants front-end et les déplacer vers des feuilles CSS servies depuis des sources approuvées.
5. CVE-2023-5561
	* Mettre à jour WordPress à une version corrigée.
6. CVE-2024-2473
	* Mettre à jour le plugin WPS Hide Login à une version corrigée.
7. Missing Anti-clickjacking Header
	* Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
8. Sub Resource Integrity Attribute Missing
	* Ajouter integrity et crossorigin="anonymous" sur les ressources stables et versionnées.

D - Conclusion

28 vulnérabilités ont été identifiées au total, dont 8 sont prioritaires. Il est essentiel de traiter ces vulnérabilités pour améliorer la sécurité du site web.


    ## Tableau de synthèse des vulnérabilités

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 8 | 4 | 16 |

    **Total :** 28 | **Prioritaires :** 8
    

## Annexe - Liste complète des findings (générée par Python)

| Priorité | Type | Severity | Risk | Confidence | Titre | Cible | Preuve | alertRef | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P3 | vulnerability | medium | Medium | High | CSP: Failure to Define Directive with No Fallback | https://manysports.tn/ | upgrade-insecure-requests | 10055-13 |  |
| P3 | vulnerability | medium | Medium | High | CSP: Wildcard Directive | https://manysports.tn/ | upgrade-insecure-requests | 10055-4 |  |
| P3 | vulnerability | medium | Medium | High | CSP: script-src unsafe-inline | https://manysports.tn/ | upgrade-insecure-requests | 10055-5 |  |
| P3 | vulnerability | medium | Medium | High | CSP: style-src unsafe-inline | https://manysports.tn/ | upgrade-insecure-requests | 10055-6 |  |
| P3 | vulnerability | medium | — | — | CVE-2023-5561 | https://manysports.tn/?rest_route=/wp/v2/users&search=@ | route="?rest_route=/wp/v2/users&" |  |  |
| P3 | vulnerability | medium | — | — | CVE-2024-2473 | https://manysports.tn/wp-admin/?action=postpass | — |  |  |
| P3 | vulnerability | medium | Medium | Medium | Missing Anti-clickjacking Header | https://manysports.tn/ | x-frame-options | 10020-1 |  |
| P3 | vulnerability | medium | Medium | High | Sub Resource Integrity Attribute Missing | https://manysports.tn/ | <link rel="preload" as="style" href="https://fonts.googleapis.com/css?family=Mulish:200,300,400,500,600,700,800,900,200italic,300italic,400italic,500italic,600italic,700italic,800italic,900italic&#038;display=swap&#038;ver=1752201721" /> | 90003 |  |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | https://manysports.tn/ | <script type="text/javascript" src="https://stats.wp.com/s-202611.js" id="woocommerce-analytics-js" defer="defer" data-wp-strategy="defer"></script> | 10017 |  |
| P4 | vulnerability | low | Low | Medium | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | https://manysports.tn/ | x-powered-by: PHP/8.2.30 | 10037 |  |
| P4 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | https://manysports.tn/ | — | 10035-1 |  |
| P4 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | https://manysports.tn/ | x-content-type-options | 10021 |  |
| P5 | information | info | — | — | Plugin détecté : automattic-for-agencies-client | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : blaze-ads | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : contact-form-7 | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : elementor | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : filebird | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : font-awesome | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : google-site-kit | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : hostinger | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : jetpack | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : jetpack-search | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : litespeed-cache | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : mainichi-shopify-products-connect | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : simple-history | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : woocommerce | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : wordpress-seo | https://manysports.tn/ | — |  |  |
| P5 | information | info | — | — | Plugin détecté : wp-store-lite | https://manysports.tn/ | — |  |  |
