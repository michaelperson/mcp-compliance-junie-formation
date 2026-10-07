#!/usr/bin/env bash
# Vérification de bout en bout du compliance-mcp-server (Linux / macOS / Git Bash).
# Usage : ./scripts/verify.sh            (tout)
#         ./scripts/verify.sh --offline  (sans les tests réseau OSV / KEV)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER="$ROOT/compliance-mcp-server"
BASE="http://127.0.0.1:8085"
LOG="$(mktemp -t compliance-mcp.XXXXXX.log)"
OFFLINE=0; [[ "${1:-}" == "--offline" ]] && OFFLINE=1
PASS=0; FAIL=0; PID=""

ok()   { echo "  [OK]   $1"; PASS=$((PASS+1)); }
ko()   { echo "  [KO]   $1"; FAIL=$((FAIL+1)); }
step() { echo; echo "== $1"; }
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }
trap cleanup EXIT

step "1. Prérequis"
java -version 2>&1 | grep -Eq 'version "(2[1-9]|[3-9][0-9])' && ok "JDK 21+" || ko "JDK 21+ requis"
if [[ -x "$SERVER/mvnw" ]]; then MVN="./mvnw"; ok "Maven Wrapper (mvnw)"
elif command -v mvn >/dev/null; then MVN="mvn"; ok "Maven présent"
else MVN=""; ko "Ni mvnw ni mvn : IntelliJ > Maven > Execute Maven Goal : mvn wrapper:wrapper -Dtype=only-script"; fi
command -v curl >/dev/null && ok "curl présent"  || ko "curl absent"
command -v node >/dev/null && ok "Node présent (MCP Inspector)" || echo "  [--]   Node absent : MCP Inspector indisponible (non bloquant)"
[[ $FAIL -gt 0 ]] && { echo; echo "Prérequis manquants : corriger puis relancer."; exit 1; }

step "2. Build + tests unitaires (mvn verify)"
if (cd "$SERVER" && $MVN -B -q verify); then
  ok "Compilation, tests et SBOM"
  [[ -f "$SERVER/target/classes/META-INF/sbom/application.cdx.json" ]] && ok "SBOM CycloneDX généré (embarqué dans le jar)" || ko "SBOM absent (target/classes/META-INF/sbom/)"
else
  ko "mvn verify en échec : corriger avant d'aller plus loin"; echo; echo "Résultat : $PASS OK, $FAIL KO"; exit 1
fi

step "3. Fail-fast sans clé API"
(cd "$SERVER" && env -u COMPLIANCE_MCP_API_KEY java -jar target/compliance-mcp-server-*.jar > "$LOG.nokey" 2>&1) &
NK=$!; sleep 12
if kill -0 "$NK" 2>/dev/null; then kill "$NK"; ko "Le server démarre sans clé (il devrait refuser)"
else grep -q "COMPLIANCE_MCP_API_KEY" "$LOG.nokey" && ok "Démarrage refusé sans clé" || ko "Arrêt sans le message attendu (voir $LOG.nokey)"; fi

step "4. Démarrage avec clé"
export COMPLIANCE_MCP_API_KEY="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
(cd "$SERVER" && java -jar target/compliance-mcp-server-*.jar > "$LOG" 2>&1) &
PID=$!
for i in $(seq 1 60); do curl -fs "$BASE/actuator/health" >/dev/null && break; sleep 1; done
curl -fs "$BASE/actuator/health" | grep -q UP && ok "Health UP" || { ko "Server non joignable (log : $LOG)"; exit 1; }

step "5. Sécurité HTTP"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
C=$(code -X POST "$BASE/mcp");                                     [[ "$C" =~ ^40[13]$ ]] && ok "Sans clé -> $C" || ko "Sans clé -> $C (attendu 401/403)"
C=$(code -X POST -H "X-API-Key: mauvaise-cle" "$BASE/mcp");         [[ "$C" =~ ^40[13]$ ]] && ok "Mauvaise clé -> $C" || ko "Mauvaise clé -> $C"
C=$(code -X POST -H "X-API-Key: $COMPLIANCE_MCP_API_KEY" -H "Origin: https://evil.example" "$BASE/mcp")
[[ "$C" == "403" ]] && ok "Origin étranger -> 403" || ko "Origin étranger -> $C (attendu 403)"
sleep 1
grep -q 'AUTH_REJECTED reason=API_KEY_INVALID' "$LOG" && grep -q 'AUTH_REJECTED reason=ORIGIN_NOT_ALLOWED' "$LOG" \
  && ok "Refus journalisés (AUTH_REJECTED)" || ko "Pas de ligne AUTH_REJECTED dans $LOG"
grep -qF "$COMPLIANCE_MCP_API_KEY" "$LOG" && ko "La clé apparaît en clair dans le log !" || ok "Clé absente du log"

step "6. Protocole MCP (initialize, tools/list)"
H=(-H "X-API-Key: $COMPLIANCE_MCP_API_KEY" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")
INIT=$(curl -s -D - "${H[@]}" -X POST "$BASE/mcp" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"verify.sh","version":"1"}}}')
SID=$(echo "$INIT" | grep -i '^mcp-session-id:' | awk '{print $2}' | tr -d '\r')
echo "$INIT" | grep -q '"serverInfo"' && ok "initialize (session ${SID:-aucune})" || ko "initialize sans réponse valide"
SH=(); [[ -n "$SID" ]] && SH=(-H "Mcp-Session-Id: $SID")
curl -s "${H[@]}" "${SH[@]}" -X POST "$BASE/mcp" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
call() { curl -s "${H[@]}" "${SH[@]}" -X POST "$BASE/mcp" -d "$1"; }
TOOLS=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
for t in get_data_classification check_dependency get_cve_status open_cra_triage declare_ai_assisted_change; do
  echo "$TOOLS" | grep -q "\"$t\"" && ok "outil $t exposé" || ko "outil $t absent"
done
call '{"jsonrpc":"2.0","id":3,"method":"resources/list"}' | grep -q 'policy://secure-sdlc' && ok "ressource policy://secure-sdlc" || ko "ressource absente"

step "7. Appels d'outils (hors réseau)"
R=$(call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_data_classification","arguments":{"entity":"Customer"}}}')
echo "$R" | grep -q 'PERSONAL' && ok "Customer classé (PERSONAL)" || ko "Customer : $R"
R=$(call '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_data_classification","arguments":{"entity":"Employee"}}}')
echo "$R" | grep -q 'DPO' && ok "Employee -> renvoi DPO" || ko "Employee : $R"
R=$(call '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"check_dependency","arguments":{"groupId":"com.thoughtworks.xstream","artifactId":"xstream"}}}')
echo "$R" | grep -q 'FORBIDDEN' && ok "xstream FORBIDDEN" || ko "xstream : $R"
R=$(call '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"open_cra_triage","arguments":{"cveId":"CVE-2021-44228","component":"org.apache.logging.log4j:log4j-core","version":"2.14.1","product":"portail-client"}}}')
echo "$R" | grep -q 'earlyWarningDueBy' && ok "Dossier CRA avec échéances" || ko "open_cra_triage : $R"
grep -q 'CRA_TRIAGE' "$LOG" && ok "Alerte WARN CRA_TRIAGE dans les logs" || ko "Pas de ligne CRA_TRIAGE"
grep -q 'AI_AUDIT\|tool=get_data_classification' "$LOG" && ok "Journal d'audit alimenté" || ko "Journal d'audit vide"

if [[ $OFFLINE -eq 0 ]]; then
  step "8. OSV.dev + CISA KEV (réseau)"
  for i in $(seq 1 30); do grep -q 'Catalogue KEV chargé' "$LOG" && break; sleep 1; done
  grep -q 'Catalogue KEV chargé' "$LOG" && ok "Catalogue KEV chargé" || ko "KEV non chargé (www.cisa.gov bloqué ?)"
  R=$(call '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_cve_status","arguments":{"ecosystem":"MAVEN","packageName":"org.apache.logging.log4j:log4j-core","version":"2.14.1"}}}')
  echo "$R" | grep -q 'EXPLOITED' && ok "log4j 2.14.1 -> EXPLOITED" || ko "log4j : verdict inattendu ($(echo "$R" | grep -o '"verdict[^,]*' | head -1))"
  R=$(call '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_cve_status","arguments":{"ecosystem":"NPM","packageName":"lodash","version":"4.17.15"}}}')
  echo "$R" | grep -q 'VULNERABLE' && ok "lodash 4.17.15 -> VULNERABLE" || ko "lodash : verdict inattendu"
  R=$(call '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_cve_status","arguments":{"ecosystem":"MAVEN","packageName":"log4j-core","version":"2.14.1"}}}')
  echo "$R" | grep -qi 'groupId:artifactId\|isError' && ok "Entrée invalide rejetée" || ko "Entrée invalide acceptée"
else
  echo; echo "== 8. Tests réseau ignorés (--offline)"
fi

echo; echo "Résultat : $PASS OK, $FAIL KO   (log du server : $LOG)"
[[ $FAIL -eq 0 ]]
