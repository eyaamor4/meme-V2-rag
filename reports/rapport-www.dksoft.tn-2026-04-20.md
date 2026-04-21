A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 9 vulnérabilités ont été retenues dans ce rapport, dont 4 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.dksoft.tn/ (wordpress 6.9.4). Scan du : 2026-04-20 19:56:53 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client, notamment l'absence de Content Security Policy (CSP) et de Sub Resource Integrity Attribute.

B - Vulnérabilités Prioritaires
- Content Security Policy (CSP) Header Not Set
  - Description : L'en-tête Content Security Policy (CSP) n'est pas défini, ce qui peut permettre à des attaquants d'exécuter du code malveillant sur le site.
  - Référence : Non fourni
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Définir une politique CSP de base avec default-src 'self' et déclarer explicitement les directives nécessaires.
  - Vérification : Exécuter curl -I https://www.dksoft.tn/ | grep -i content-security-policy
- Sub Resource Integrity Attribute Missing
  - Description : L'attribut Sub Resource Integrity est manquant, ce qui peut permettre à des attaquants de modifier les ressources externes chargées par le site.
  - Référence : Non fourni
  - Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
  - Sévérité : MEDIUM
  - Recommandation : Ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées.
  - Vérification : Inspecter le code source HTML : curl -s https://www.dksoft.tn/ | grep -i 'integrity='
- Missing Anti-clickjacking Header
  - Description : L'en-tête X-Frame-Options est manquant, ce qui peut permettre à des attaquants d'intégrer le site dans une iframe et de réaliser des attaques de clickjacking.
  - Référence : Non fourni
  - Catégorie OWASP : A05:2021 - Security Misconfiguration
  - Sévérité : MEDIUM
  - Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
  - Vérification : Exécuter curl -I https://www.dksoft.tn/ | grep -i x-frame-options
- Absence of Anti-CSRF Tokens
  - Description : Les tokens anti-CSRF sont absents, ce qui peut permettre à des attaquants de réaliser des attaques de cross-site request forgery.
  - Référence : Non fourni
  - Catégorie OWASP : A01:2021 - Broken Access Control
  - Sévérité : MEDIUM
  - Recommandation : Définir des tokens anti-CSRF pour les formulaires sensibles.
  - Vérification : Vérifier la présence de tokens anti-CSRF dans les formulaires

C - Vulnérabilités Potentielles à Valider
Aucune vulnérabilité potentielle à valider n'a été détectée.

D - Plan de remédiation
1. Content Security Policy (CSP) Header Not Set : Définir une politique CSP de base avec default-src 'self' — Délai : 30 jours
2. Sub Resource Integrity Attribute Missing : Ajouter l'attribut integrity et crossorigin="anonymous" sur les ressources stables et versionnées — Délai : 30 jours
3. Missing Anti-clickjacking Header : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet — Délai : 30 jours
4. Absence of Anti-CSRF Tokens : Définir des tokens anti-CSRF pour les formulaires sensibles — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L'action prioritaire principale est de définir une politique CSP de base avec default-src 'self' pour remédier à la vulnérabilité Content Security Policy (CSP) Header Not Set, avec un délai de 30 jours.
Il est essentiel de remédier à ces vulnérabilités pour réduire la surface d’attaque côté navigateur et protéger le site contre les attaques malveillantes.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Ce tableau comptabilise uniquement les vulnérabilités confirmées retenues dans le rapport principal après déduplication.
    > Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

    | 🔴 Critique | 🟠 Élevé | 🟡 Moyen | 🟢 Faible | ℹ️ Info |
    |:---:|:---:|:---:|:---:|:---:|
    | 0 | 0 | 4 | 5 | 21 |

    **Niveau de risque global : MODÉRÉ**

    **Vulnérabilités confirmées retenues dans le rapport :** 9  
    **Vulnérabilités potentielles à valider :** 0  
    **Éléments informationnels :** 21  
    **Prioritaires confirmées (section B) :** 4 

    > ℹ️ *Les chiffres ci-dessus sont calculés après déduplication globale.*
    

## Annexe  - Liste complète des findings dédupliqués (TOUS)

| Priorité | Type | Sévérité  | Risk | Confidence | Titre | Preuve | alertRef |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P4 | vulnerability | low | Low | Medium | Cross-Domain JavaScript Source File Inclusion | — | cross-domain javascript source file inclusion |
| P4 | vulnerability | low | Low | Medium | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | — | server leaks information via "x-powered-by" http response header field(s) |
| P4 | vulnerability | low | Low | Low | Timestamp Disclosure - Unix | — | timestamp disclosure - unix |
| P5 | information | info | — | — | Plugin détecté : animentor-lottie-bodymovin-elementor | — |  |
| P5 | information | info | — | — | Plugin détecté : bdthemes-element-pack-lite | — |  |
| P5 | information | info | — | — | Plugin détecté : elementor | — |  |
| P5 | information | info | — | — | Plugin détecté : elementskit-lite | — |  |
| P5 | information | info | — | — | Plugin détecté : essential-addons-elementor | — |  |
| P5 | information | info | — | — | Plugin détecté : essential-addons-for-elementor-lite | — |  |
| P5 | information | info | — | — | Plugin détecté : exclusive-addons-for-elementor | — |  |
| P5 | information | info | — | — | Plugin détecté : forminator | — |  |
| P5 | information | info | — | — | Plugin détecté : happy-elementor-addons | — |  |
| P5 | information | info | — | — | Plugin détecté : happyaddons | — |  |
| P5 | information | info | — | — | Plugin détecté : header-footer-elementor | — |  |
| P5 | information | info | — | — | Plugin détecté : jetformbuilder | — |  |
| P5 | information | info | — | — | Plugin détecté : litespeed-cache | — |  |
| P5 | information | info | — | — | Plugin détecté : popup-maker | — |  |
| P5 | information | info | — | — | Plugin détecté : sticky-header-effects-for-elementor | — |  |
| P5 | information | info | — | — | Plugin détecté : wpforms-lite | — |  |
| P5 | vulnerability | low | Low | High | Strict-Transport-Security Header Not Set | — | strict-transport-security header not set |
| P5 | information | info | — | — | Technologie détectée : Elementor | 3.14.1 |  |
| P5 | information | info | — | — | Technologie détectée : MySQL | Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : PHP | 8.0, Version non fournie |  |
| P5 | information | info | — | — | Technologie détectée : WordPress | 6.9.4 |  |
| P5 | information | info | — | — | Technologie détectée : reCAPTCHA | Version non fournie |  |
| P5 | vulnerability | low | Low | Medium | X-Content-Type-Options Header Missing | — | x-content-type-options header missing |
