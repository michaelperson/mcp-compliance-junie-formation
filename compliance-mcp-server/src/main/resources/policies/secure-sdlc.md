# Secure SDLC — équipe Java (Spring Boot) + Angular

## NIS2 (art. 21 — loi belge du 26/04/2024, CCB / CyberFundamentals)
- Toute dépendance ajoutée ou montée : `check_dependency` (politique interne) **puis** `get_cve_status` (CVE live OSV.dev, Maven et npm).
- Verdict `VULNERABLE` CRITICAL/HIGH = bloquant ; `UNKNOWN` = non validé (fail-closed).
- Verdict `EXPLOITED` (match CISA KEV) = bloquant absolu + `open_cra_triage` immédiat.

## CRA (Règlement (UE) 2024/2847 — art. 14, applicable depuis le 11/09/2026)
- Vulnérabilité activement exploitée dans un produit livré : alerte précoce **24 h**, notification **72 h**,
  rapport final **14 jours** après le correctif, via la plateforme unique ENISA → CSIRT coordinateur.
- L'agent ouvre le dossier de triage ; le PSIRT / juridique décide de notifier. Aucune notification automatique.
- SBOM CycloneDX généré à chaque build, archivé avec l'artefact.
- Aucun secret dans le code, les prompts, les tests ou `mcp.json` versionné.
- Logs de sécurité structurés, sans donnée personnelle en clair.

## RGPD (privacy by design — art. 25)
- Avant de toucher une entité : `get_data_classification`.
- Champ PERSONAL / SENSITIVE / SPECIAL_ART9 → chiffrement au repos + masquage logs.
- Jeux de test : données synthétiques uniquement (jamais d'extraits de prod).
- DTO minimaux : on n'expose pas un champ que le front n'affiche pas.

## AI Act (art. 4 littératie IA, art. 50 transparence)
- Tout changement assisté par IA est déclaré via `declare_ai_assisted_change`.
- Revue humaine obligatoire avant merge — pas de merge autonome par un agent.
- Pas de données personnelles réelles envoyées au modèle.

## Java
- Validation Bean Validation sur tous les DTO entrants; requêtes paramétrées uniquement.
- Spring Security : deny by default, méthodes sensibles en `@PreAuthorize`.
- Erreurs : `ProblemDetail`, jamais de stacktrace côté client.

## Angular
- Interdit : `bypassSecurityTrust*`, `innerHTML` non assaini, tokens en `localStorage`.
- CSP stricte, `HttpInterceptor` pour l'auth, cookies `HttpOnly; Secure; SameSite`.
- `npm audit --omit=dev` bloquant en CI.
