A - Résumé Exécutif
Après analyse, déduplication et consolidation des résultats, 9 vulnérabilités ont été retenues dans ce rapport, dont 4 sont prioritaires.
Niveau de risque global : MODÉRÉ. Cible : https://www.dksoft.tn/ (wordpress 6.9.4). Scan du : 2026-04-20 19:56:53 UTC.
La surface d’attaque côté navigateur est élargie en raison de plusieurs vulnérabilités liées à la sécurité côté client.

B - Vulnérabilités Prioritaires
[Content Security Policy (CSP) Header Not Set]
- Description : Le header Content Security Policy (CSP) n’est pas défini, ce qui peut permettre l’exécution de code malveillant.
- Référence : Non fourni
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir une politique CSP de base avec default-src 'self'.
- Vérification : 
curl -I https://www.dksoft.tn/ | grep -i content-security-policy

[Sub Resource Integrity Attribute Missing]
- Description : L’attribut Sub Resource Integrity (SRI) est manquant, ce qui peut permettre l’injection de code malveillant.
- Référence : Non fourni
- Catégorie OWASP : A08:2021 - Software and Data Integrity Failures
- Sévérité : MEDIUM
- Recommandation : Ajouter l’attribut integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées.
- Vérification : 
curl -s https://www.dksoft.tn/ | grep -i integrity

[Missing Anti-clickjacking Header]
- Description : Le header X-Frame-Options est manquant, ce qui peut permettre des attaques de clickjacking.
- Référence : Non fourni
- Catégorie OWASP : A05:2021 - Security Misconfiguration
- Sévérité : MEDIUM
- Recommandation : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet.
- Vérification : 
curl -I https://www.dksoft.tn/ | grep -i x-frame-options

[Absence of Anti-CSRF Tokens]
- Description : Les tokens Anti-CSRF sont absents, ce qui peut permettre des attaques de cross-site request forgery.
- Référence : Non fourni
- Catégorie OWASP : A01:2021 - Broken Access Control
- Sévérité : MEDIUM
- Recommandation : Implémenter des tokens Anti-CSRF pour les formulaires sensibles.
- Vérification : 
curl -s https://www.dksoft.tn/ | grep -Ei "csrf|token|xsrf"

C - Vulnérabilités Potentielles à Valider
Cette section est absente car il n’y a pas de vulnérabilités potentielles à valider.

D - Plan de remédiation
1. [Content Security Policy (CSP) Header Not Set] : Définir une politique CSP de base avec default-src 'self'. — Délai : 30 jours
2. [Sub Resource Integrity Attribute Missing] : Ajouter l’attribut integrity et crossorigin=\"anonymous\" sur les ressources stables et versionnées. — Délai : 30 jours
3. [Missing Anti-clickjacking Header] : Définir X-Frame-Options à DENY ou SAMEORIGIN si la compatibilité le permet. — Délai : 30 jours
4. [Absence of Anti-CSRF Tokens] : Implémenter des tokens Anti-CSRF pour les formulaires sensibles. — Délai : 30 jours

E - Conclusion
Le niveau de risque global est MODÉRÉ.
L’action prioritaire principale est de définir une politique CSP de base avec default-src 'self' pour le finding [Content Security Policy (CSP) Header Not Set], avec un délai de 30 jours.
Il est essentiel de traiter ces vulnérabilités pour réduire la surface d’attaque côté navigateur et améliorer la sécurité globale du site.


    ## Tableau de synthèse des vulnérabilités

    > **Note méthodologique :** Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.

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

| Priorité | Titre | Sévérité  | Preuve | alertRef |
| --- | --- | --- | --- | --- |
| P4 | Cross-Domain JavaScript Source File Inclusion | low | — | cross-domain javascript source file inclusion |
| P4 | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | low | — | server leaks information via "x-powered-by" http response header field(s) |
| P4 | Timestamp Disclosure - Unix | low | — | timestamp disclosure - unix |
| P5 | Plugin détecté : animentor-lottie-bodymovin-elementor | info | — |  |
| P5 | Plugin détecté : bdthemes-element-pack-lite | info | — |  |
| P5 | Plugin détecté : elementor | info | — |  |
| P5 | Plugin détecté : elementskit-lite | info | — |  |
| P5 | Plugin détecté : essential-addons-elementor | info | — |  |
| P5 | Plugin détecté : essential-addons-for-elementor-lite | info | — |  |
| P5 | Plugin détecté : exclusive-addons-for-elementor | info | — |  |
| P5 | Plugin détecté : forminator | info | — |  |
| P5 | Plugin détecté : happy-elementor-addons | info | — |  |
| P5 | Plugin détecté : happyaddons | info | — |  |
| P5 | Plugin détecté : header-footer-elementor | info | — |  |
| P5 | Plugin détecté : jetformbuilder | info | — |  |
| P5 | Plugin détecté : litespeed-cache | info | — |  |
| P5 | Plugin détecté : popup-maker | info | — |  |
| P5 | Plugin détecté : sticky-header-effects-for-elementor | info | — |  |
| P5 | Plugin détecté : wpforms-lite | info | — |  |
| P5 | Strict-Transport-Security Header Not Set | low | — | strict-transport-security header not set |
| P5 | Technologie détectée : Elementor | info | 3.14.1 |  |
| P5 | Technologie détectée : MySQL | info | Version non fournie |  |
| P5 | Technologie détectée : PHP | info | 8.0, Version non fournie |  |
| P5 | Technologie détectée : WordPress | info | 6.9.4 |  |
| P5 | Technologie détectée : reCAPTCHA | info | Version non fournie |  |
| P5 | X-Content-Type-Options Header Missing | low | — | x-content-type-options header missing |
