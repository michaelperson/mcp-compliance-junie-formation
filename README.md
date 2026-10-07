# Kit démo — Junie + MCP server + agents pour une équipe Java/Angular sous NIS2 · RGPD · AI Act

> **Commencer par [VERIFIER.md](VERIFIER.md)** : contenu du zip, ordre de vérification, scripts `scripts/verify.sh` / `verify.ps1`. Kit formateur complet dans `formateur/`.

> **Le point de vue de l'architecte :** l'agent ne "connaît" pas votre conformité. Le MCP server en est la **source de vérité exécutable**, `AGENTS.md` en est le **contrat**, et les subagents sont des **rôles spécialisés avec moindre privilège**.

```
IntelliJ + Junie ──(AGENTS.md : règles d'équipe)
      │
      ├── subagent compliance-reviewer  (lecture seule)
      ├── subagent privacy-by-design    (écriture, périmètre données)
      │
      └──Streamable HTTP + X-API-Key──► compliance-mcp-server (Spring AI 2.0, 127.0.0.1:8085/mcp)
                                          ├─ tool  get_data_classification  (RGPD art. 25/30)
                                          ├─ tool  check_dependency         (politique interne : libs bannies)
                                          ├─ tool  get_cve_status ──HTTPS──► api.osv.dev  (CVE live Maven + npm, NIS2 art. 21)
                                          │        └─ croisé avec ◄── catalogue CISA KEV (rafraîchi /6 h, en mémoire)
                                          ├─ tool  open_cra_triage          (CRA art. 14 : échéances 24 h / 72 h / 14 j)
                                          ├─ tool  declare_ai_assisted_change (AI Act transparence / audit)
                                          └─ resource policy://secure-sdlc
```

## Versions vérifiées (7 octobre 2026)

| Élément | État actuel |
|---|---|
| Spring AI | **2.0.x** (GA juin 2026) → requiert **Spring Boot 4.0/4.1**, Jackson 3, MCP Java SDK 2.0 |
| Spec MCP | **2026-07-28** : protocole sans session, `server/discover`, HTTP+SSE déprécié (12 mois). Junie négocie encore **2025-03-26** ; le kit tourne en `protocol: STATELESS` |
| Annotations | `@McpTool`, `@McpToolParam`, `@McpResource` (package `org.springframework.ai.mcp.annotation`, vérifié dans le jar) |
| Junie | GA (juillet 2026). MCP : `.junie/mcp/mcp.json` (projet) ou `~/.junie/mcp/mcp.json` (utilisateur) ; guidelines : `AGENTS.md` ou `.junie/guidelines.md` ; subagents : `.junie/agents/*.md` |
| AI Act | Digital Omnibus **en vigueur depuis le 29/07/2026** : high-risk Annex III → **2 déc. 2027**, Annex I → **2 août 2028**, transparence art. 50(2) → **2 déc. 2026**. Littératie IA (art. 4) et interdictions : déjà applicables. |
| NIS2 (BE) | Loi du 26/04/2024, en vigueur depuis le 18/10/2024 ; autorité : CCB ; cadre de référence : CyberFundamentals |
| **CRA** | Art. 14 **applicable depuis le 11/09/2026**, y compris aux produits déjà sur le marché : vulnérabilité activement exploitée → alerte précoce 24 h, notification 72 h, rapport final 14 j après correctif. **Plateforme unique ENISA (SRP) en service depuis le 11/09/2026** ; liste des CSIRT coordinateurs publiée le 04/09/2026. Application complète le 11/12/2027. |
| CISA KEV | Flux JSON public `known_exploited_vulnerabilities.json` (champs `cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`…) |

> ⚠️ Les subagents sont documentés côté Junie CLI ; Junie annonce la parité IDE/CLI via son protocole commun — **vérifiez sur votre version du plugin** avant la démo (si non supporté : bascule sur la CLI `junie` dans le terminal IntelliJ).

---

## Déroulé de la démo (≈ 45 min)

### Étape 0 — Préparer (avant la séance)
```bash
# Clé locale robuste (≥ 32 caractères) — jamais commitée
export COMPLIANCE_MCP_API_KEY=$(openssl rand -hex 32)       # PowerShell : [guid]::NewGuid().ToString('N')*2
```

### Étape 1 — Faire générer le MCP server par Junie (live) · 10 min
Ouvrir un projet vide dans IntelliJ, puis prompt Junie (mode **Plan** d'abord) :

> Crée un MCP server Spring Boot 4.1 / Spring AI 2.0.1, Java 21, starter `spring-ai-starter-mcp-server-webmvc`, protocole STATELESS (Streamable HTTP sans session, GET /mcp en 405), lié à 127.0.0.1:8085.
> Expose 5 outils via `@McpTool` : `get_data_classification(entity)`, `check_dependency(groupId, artifactId)` (liste interne de libs bannies), `get_cve_status(ecosystem, packageName, version)`, `open_cra_triage(cveId, component, version, product)` et `declare_ai_assisted_change(ticketId, summary, model)`, plus une ressource `policy://secure-sdlc`.
> `get_cve_status` interroge `POST https://api.osv.dev/v1/query` avec un `RestClient` (timeouts 3 s / 10 s, pas de redirection), écosystèmes MAVEN et NPM, validation regex stricte des entrées, cache TTL 6 h, pagination bornée, **fail-closed** (verdict UNKNOWN si OSV est indisponible), et neutralise/tronque les textes renvoyés par OSV. Tests avec `MockRestServiceServer`, sans réseau.
> Le référentiel vient d'un fichier `compliance-policy.yml` lié par `@ConfigurationProperties` (records immuables).
> Sécurise `/mcp` avec Spring Security : filtre clé API (`X-API-Key`, comparaison à temps constant, fail-fast si clé < 32 car.), validation de l'en-tête Origin, stateless, deny by default.
> Journalise chaque appel d'outil (qui/quoi/quand, sans contenu métier, anti log-injection). Ajoute des tests JUnit pour la logique de dépendances.

👉 Version abrégée : le prompt complet est P1 dans le kit formateur et le cahier stagiaire. Montrer le plan, le corriger, puis comparer au code de référence `compliance-mcp-server/` (filet de sécurité si le live dérape).

### Étape 2 — Lancer et tester le server · 5 min
```bash
cd compliance-mcp-server && mvn spring-boot:run
npx @modelcontextprotocol/inspector     # URL http://127.0.0.1:8085/mcp, header X-API-Key
```
Montrer : `tools/list`, un appel sans clé → **401/403** (Zero Trust).

### Étape 3 — Brancher Junie sur le server · 5 min
Copier `.junie/mcp/mcp.json.example` → **`~/.junie/mcp/mcp.json`** (scope utilisateur, car il contient la clé) et y coller la clé.
Ou via *Settings | Tools | Junie | MCP Settings*. Vérifier que les 3 outils apparaissent.

> 💡 Point pédagogique : un `mcp.json` projet commité avec un secret = incident NIS2. Le projet versionne l'**exemple**, l'utilisateur garde la clé.

### Étape 4 — Le contrat d'équipe : `AGENTS.md` · 5 min
Copier `team-repo-template/AGENTS.md` à la racine du repo Java+Angular. Prompt :

> Ajoute un champ `phone` à l'entité `Customer` et affiche-le dans le formulaire Angular.

Attendu : Junie appelle **d'elle-même** `get_data_classification("Customer")`, chiffre le champ, le masque dans les logs, puis `declare_ai_assisted_change`. Montrer le journal `AI_AUDIT` dans la console du server.

Contre-exemple : *« Ajoute une entité `Employee` avec le salaire »* → entité absente du registre → **l'agent doit s'arrêter** et renvoyer vers le DPO.

### Étape 5 — Les subagents spécialisés · 10 min
Copier `.junie/agents/`. Puis copier les fichiers de `demo-traps/` dans le projet et :

> Fais une revue de conformité des fichiers modifiés.

Junie délègue à **compliance-reviewer** (lecture seule, ne peut pas « réparer en douce »). Il doit trouver : secret en dur, injection JPQL, entité exposée, PII en logs et en URL, token en `localStorage`, `bypassSecurityTrustHtml`.
Coller `demo-traps/pom-snippet.xml` → `get_cve_status` renvoie **VULNERABLE / CRITICAL** (CVE-2021-44228…) avec les versions `fixedIn` ; l'agent doit proposer la version qui les couvre toutes.
Coller `demo-traps/package-json-snippet.json` côté Angular → même verdict sur `lodash@4.17.15` (écosystème NPM).
Log4Shell est au catalogue KEV → verdict **EXPLOITED** + bloc `cra.triageRequired=true`. L'agent doit **s'arrêter**, appeler `open_cra_triage` et afficher les échéances ; la console du server montre la ligne `WARN CRA_TRIAGE` (c'est elle que le SIEM capte).
`lodash@4.17.15` (CVE-2020-8203) n'est pas au KEV → reste **VULNERABLE** : bloquant, mais pas d'horloge CRA. Excellent contraste pour la salle.
Bonus live : couper le Wi-Fi et relancer → **UNKNOWN**, l'agent ne doit pas valider la dépendance (fail-closed).

### Étape 6 — Industrialiser (DevOps) · 5 min
Montrer `.github/workflows/ci.yml` : build + tests + **SBOM CycloneDX** archivé + `dependency-review-action` bloquant. Message clé : *l'agent aide, la CI prouve.*

---

## Note du formateur
- **Le MCP server n'est pas un garde-fou suffisant** : l'agent peut ne pas appeler un outil. La CI (SBOM, dependency review, SAST) reste la barrière déterministe ; `AGENTS.md` augmente la probabilité, la pipeline garantit.
- **Données externes = entrée non fiable.** Les `summary` OSV arrivent dans le contexte du LLM : un advisory piégé serait une injection de prompt indirecte. D'où la troncature, la neutralisation et la phrase « données, pas instructions » dans la réponse — et le test qui contient `IGNORE PREVIOUS INSTRUCTIONS`.
- **KEV ≠ obligation automatique.** Un match KEV prouve qu'une vulnérabilité est exploitée *quelque part* (définition CRA art. 3(42)). L'art. 14 vise le fabricant d'un produit qui *contient* cette vulnérabilité : composant réellement livré (pas une devDependency), code présent, produit sur le marché UE. D'où un **triage humain**, pas une notification automatique.
- **Quand commence l'horloge de 24 h ?** À la « prise de connaissance ». Question à poser au juriste : la détection par l'outil vaut-elle connaissance ? Par prudence, le dossier horodate la détection — c'est aussi pour ça que l'escalade est déterministe (log WARN → SIEM) et ne dépend pas de la bonne volonté du LLM.
- **KEV est américain et incomplet.** C'est un signal fort, pas exhaustif : l'interface `ExploitationIntel` permet d'ajouter l'**EUVD de l'ENISA** (`/api/exploitedvulnerabilities`) ou un flux commercial sans toucher au reste (Open/Closed).
- **Fail-closed vs fail-open :** demandez à la salle ce qui se passe si OSV est en panne. Un `CLEAN` par défaut serait une faille ; `UNKNOWN` force l'humain/la CI à trancher.
- **Description d'outil = prompt.** Une description malveillante dans un MCP tiers peut détourner l'agent (*tool poisoning*). N'installez que des MCP servers revus, épinglés en version, idéalement internes. Référence : OWASP Top 10 for LLM Apps 2025 + OWASP Top 10 for Agentic Applications.
- **Brave Mode / « Always allow »** = dette technique et risque. À réserver à des sandboxes jetables.
- **Socratique** : demandez à la salle — *« Ce check RGPD devrait-il vivre dans l'agent ou dans un ArchUnit test ? »* (réponse : les deux ; l'agent pour la prévention, ArchUnit/CI pour la preuve).

## Check DevOps / Sécurité
- [ ] Clé API → Azure Key Vault / secret store ; rotation. En prod : **OAuth 2.1 (Entra ID)** avec `org.springaicommunity:mcp-server-security` (encore marqué WIP — à évaluer).
- [ ] Server déployé en interne uniquement (Private Endpoint / VNet), jamais exposé Internet.
- [ ] Egress : deux flux sortants autorisés, `api.osv.dev:443` et `www.cisa.gov:443` (proxy / Azure Firewall FQDN rule). OSV est opéré par Google : seul le nom+version des paquets sort (pas de donnée personnelle), mais votre stack est révélée → à noter dans l'analyse de risques ; alternative souveraine : miroir local des exports OSV (`osv-scanner --offline`).
- [ ] Cache : remplacer la map maison par Caffeine (éviction LRU, métriques) en production.
- [ ] `AI_AUDIT` → SIEM (Sentinel), rétention définie avec le RSSI.
- [ ] `compliance-policy.yml` : CODEOWNERS = DPO + RSSI.
- [ ] Modèle LLM utilisé par Junie : contrat DPA, région UE, pas d'entraînement sur vos données (BYOK si besoin).
- [ ] Registre des usages IA de l'équipe tenu à jour (AI Act art. 4 : littératie, preuves de formation).
- [ ] Processus de signalement CRA (24 h) relié à votre processus d'incident NIS2 : compte fabricant créé sur la SRP ENISA, astreinte PSIRT, règle SIEM sur `CRA_TRIAGE`, exercice à blanc.
- [ ] Persister les dossiers `open_cra_triage` (aujourd'hui : log d'audit uniquement) dans un outil de ticketing (Jira / Azure Boards) pour la preuve de délai.
- [ ] Monitoring : alerte si le catalogue KEV passe `STALE` (> 48 h sans rafraîchissement).

## Scripts fournis

À lancer depuis la racine du dépôt.

| Script | Rôle | Commande |
|---|---|---|
| `scripts/start-server.ps1` | Démarre le server avec une clé de 64 caractères générée à chaque lancement (jamais affichée en entier). Options : `-UpdateJunieConfig` écrit la clé dans `~/.junie/mcp/mcp.json`, `-AllowInspector -OpenInspector` ouvre MCP Inspector | `pwsh ./scripts/start-server.ps1 -AllowInspector -OpenInspector -UpdateJunieConfig` |
| `scripts/verify.ps1` | Vérification de bout en bout sous Windows : build, tests, SBOM, refus sans clé, appels MCP, OSV et KEV. Attendu : 0 KO | `pwsh ./scripts/verify.ps1` |
| `scripts/verify.sh` | Même vérification sous Linux, macOS ou Git Bash | `bash ./scripts/verify.sh` |

Prérequis : JDK 21+, PowerShell 7 (`pwsh`) pour les `.ps1`, `curl` et un accès sortant vers `api.osv.dev` et `www.cisa.gov`.

Sur la branche `start`, le code Java n'existe pas encore : `verify` échoue tant que Junie ne l'a pas généré. C'est normal, et c'est justement le test de fin de la séquence 2.

## Où retrouver les déclarations `declare_ai_assisted_change`

L'outil n'écrit ni en base ni dans un fichier dédié : chaque appel produit **une ligne de journal** sur le logger `AI_AUDIT` du server et renvoie la même entrée à l'agent.

**Ce qui est enregistré** (`AiAuditLog.record`) :

| Champ | Contenu |
|---|---|
| `id` | UUID unique de la déclaration, à citer dans la PR ou le ticket |
| `at` | Horodatage (renvoyé à l'agent ; dans la console, c'est l'horodatage de la ligne de log) |
| `principal` | Identité authentifiée : toujours `junie-agent` avec la clé API partagée |
| `tool` | `declare_ai_assisted_change` |
| `detail` | `ticket=<ticketId> model=<modèle> summary=<résumé>`, tronqué à 200 caractères, retours ligne neutralisés (anti log injection, CWE-117) |

Exemple :

```text
INFO … AI_AUDIT : id=3f1c…e9 principal=junie-agent tool=declare_ai_assisted_change detail=ticket=DIS-1234 model=gpt-5 summary=Ajout du champ phone chiffré et masqué
```

**Où la lire, du plus simple au plus robuste :**

1. **La console du server** : le terminal où tourne `start-server.ps1` ou `mvn spring-boot:run`. C'est la preuve de référence pendant la formation. Elle disparaît à la fermeture du terminal.
2. **Le chat Junie** : le détail de l'appel d'outil affiche l'entrée renvoyée (`id`, `at`, `principal`, `tool`, `detail`). Utile pour copier l'`id` dans la description de la PR, mais ce n'est **pas** une preuve : c'est l'agent qui l'affiche.
3. **Un fichier de log**, pour garder une trace après redémarrage : Spring Boot écrit dans un fichier si la variable `LOGGING_FILE_NAME` est définie avant le démarrage.

   ```powershell
   $env:LOGGING_FILE_NAME = "logs/compliance-mcp.log"
   pwsh ./scripts/start-server.ps1 -UpdateJunieConfig
   # lister les déclarations
   Select-String -Path compliance-mcp-server/logs/compliance-mcp.log -Pattern "tool=declare_ai_assisted_change"
   ```

   ```bash
   LOGGING_FILE_NAME=logs/compliance-mcp.log ./mvnw spring-boot:run   # depuis compliance-mcp-server/
   grep "tool=declare_ai_assisted_change" logs/compliance-mcp.log
   ```

   Le dossier `logs/` ne doit jamais être commité : il est exclu par le `.gitignore` du dépôt.
4. **En production** : appender JSON vers le SIEM (Microsoft Sentinel, Elastic), rétention définie avec le RSSI. Exemple de requête Sentinel (KQL) :

   ```kusto
   ContainerLogs
   | where LogEntry has "AI_AUDIT" and LogEntry has "tool=declare_ai_assisted_change"
   | parse LogEntry with * "id=" Id " principal=" Principal " tool=" Tool " detail=ticket=" Ticket " model=" Model " summary=" Summary
   | project TimeGenerated, Id, Principal, Ticket, Model, Summary
   ```

**Limites à connaître**

- Le `principal` vaut toujours `junie-agent` : la clé API identifie l'outil, pas la personne. Le lien avec le développeur passe par le `ticketId` et l'auteur du commit ; OAuth 2.1 avec Entra ID donnerait l'identité réelle.
- La déclaration dépend de l'agent : si Junie oublie l'appel, rien n'est écrit. `AGENTS.md` le rend probable, une vérification en CI (par exemple : tout commit lié à un ticket marqué « IA » doit avoir une ligne `AI_AUDIT` correspondante) le rendrait prouvable.
- Aucune donnée personnelle dans `summary` : la description de l'outil le demande, et le journal est lu par l'équipe sécurité.

## Glossaire

| Terme | Signification | Dans ce kit |
|---|---|---|
| **AI Act** | Règlement européen 2024/1689 sur l'intelligence artificielle (calendrier modifié par le Digital Omnibus, JO du 24/07/2026) | Art. 4 (maîtrise de l'IA) et art. 50 (transparence) |
| **CCB** | Centre pour la Cybersécurité Belgique : autorité nationale NIS2, CSIRT national (CERT.be) et CSIRT coordinateur belge pour le CRA | Destinataire des signalements CRA pour la Belgique |
| **CRA** | Cyber Resilience Act, règlement (UE) 2024/2847 sur les produits comportant des éléments numériques. Art. 14 : signalement des vulnérabilités activement exploitées sous 24 h / 72 h / 14 jours, applicable depuis le 11/09/2026 ; application complète le 11/12/2027 | `open_cra_triage`, alerte `CRA_TRIAGE` |
| **CSIRT** | Computer Security Incident Response Team : équipe nationale de réponse aux incidents | CCB / CERT.be |
| **CVE** | Common Vulnerabilities and Exposures : identifiant public unique d'une vulnérabilité (ex. CVE-2021-44228, Log4Shell) | Renvoyé par `get_cve_status` |
| **CWE** | Common Weakness Enumeration : catalogue des types de faiblesses (ex. CWE-89 injection SQL, CWE-798 secret en dur) | Règles citées par le reviewer |
| **DPA** | Data Processing Agreement : contrat de sous-traitance RGPD (art. 28) avec un fournisseur qui traite des données pour vous. À ne pas confondre avec *Data Protection Authority*, l'autorité de contrôle (en Belgique : l'APD) | À exiger du fournisseur du modèle utilisé par Junie |
| **DPO** | Data Protection Officer (délégué à la protection des données) : garant de la conformité RGPD et propriétaire du registre des traitements | Entité inconnue du registre → renvoi vers le DPO |
| **ENISA / SRP** | Agence de l'UE pour la cybersécurité ; Single Reporting Platform, plateforme unique de signalement CRA ouverte le 11/09/2026 | Canal de notification CRA |
| **Fail-closed** | En cas de doute ou de panne, on refuse plutôt que d'accepter | `UNKNOWN` si OSV ne répond pas, jamais `CLEAN` |
| **KEV** | Known Exploited Vulnerabilities : catalogue de la CISA (agence américaine de cybersécurité) listant les CVE dont l'exploitation active est avérée | Chargé en mémoire, rafraîchi toutes les 6 h, `STALE` après 48 h |
| **Match KEV** | Une CVE trouvée pour une dépendance figure dans le catalogue KEV : elle est exploitée quelque part dans le monde. Cela ne déclenche pas à lui seul une notification CRA : il faut un triage (produit livré, code présent, marché UE) | Verdict `EXPLOITED` → `open_cra_triage` |
| **LRU** | Least Recently Used : politique de cache qui évince l'entrée utilisée le moins récemment quand le cache est plein | Le kit n'en fait pas : il vide tout le cache OSV quand il atteint `cacheMaxEntries`. En production : Caffeine (éviction W-TinyLFU, proche du LRU) |
| **MCP** | Model Context Protocol : protocole standard qui expose des outils, ressources et prompts à un agent IA (spec 2026-07-28) | `compliance-mcp-server` |
| **NIS2** | Directive (UE) 2022/2555 sur la cybersécurité, transposée en Belgique par la loi du 26/04/2024 (en vigueur le 18/10/2024) | Art. 21 : sécurité de la chaîne d'approvisionnement, journalisation |
| **OSV** | Open Source Vulnerabilities : base et API publiques (osv.dev, Google) qui agrègent les avis de sécurité par écosystème (Maven, npm…) et version | `POST https://api.osv.dev/v1/query` |
| **PSIRT** | Product Security Incident Response Team : équipe interne qui qualifie les vulnérabilités de vos produits et décide de notifier | Destinataire du dossier `open_cra_triage` |
| **RGPD** | Règlement général sur la protection des données (UE) 2016/679 | Art. 25 (privacy by design), art. 30 (registre) |
| **RSSI** | Responsable de la sécurité des systèmes d'information (en anglais : CISO) | Fixe les seuils de blocage et la rétention des journaux |
| **SBOM** | Software Bill of Materials : inventaire de tous les composants d'un logiciel et de leurs versions (format CycloneDX ici) | `target/classes/META-INF/sbom/application.cdx.json`, archivé en CI |
| **SIEM** | Security Information and Event Management : plateforme qui centralise et corrèle les journaux de sécurité (Sentinel, Elastic…) | Cible des logs `AI_AUDIT` et `CRA_TRIAGE` |
