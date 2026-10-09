# team-project — projet d'équipe fictif

Petite application de gestion de clients utilisée pour les séquences 4 à 6 du tutoriel. Elle joue le rôle du « vrai » projet de votre équipe : c'est **dans ce projet** que Junie travaille, cadrée par `AGENTS.md` et le MCP server de conformité.

| Dossier | Contenu |
|---|---|
| `backend/` | Spring Boot 4.1, Java 21 : entité JPA `Customer`, DTO, API REST `/api/customers`, base H2 en mémoire |
| `frontend/` | Angular 22 : formulaire client et liste, service HTTP |

Toutes les données sont synthétiques. N'y mettez jamais de données personnelles réelles.

## Lancer

```bash
cd backend && ./mvnw spring-boot:run        # http://127.0.0.1:8080/api/customers
cd frontend && npm ci && npm start          # http://localhost:4200
```

Sous Windows : `.\mvnw.cmd spring-boot:run`.

## Ce qui manque volontairement

- Pas de champ `phone` : c'est l'exercice de la séquence 4.
- Pas d'entité `Employee` : c'est le contre-exemple de la séquence 4 (entité absente du registre).
- Pas de fichiers de cadrage : le tutoriel vous fait copier `AGENTS.md`, `.junie/`, `.githooks/` et `.gitleaks.toml` depuis `team-repo-template/`.
