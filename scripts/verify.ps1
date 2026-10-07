# Vérification de bout en bout du compliance-mcp-server (Windows PowerShell 7+).
# Usage : pwsh ./scripts/verify.ps1            (tout)
#         pwsh ./scripts/verify.ps1 -Offline   (sans les tests réseau OSV / KEV)
param([switch]$Offline)

$ErrorActionPreference = 'Continue'
$Root   = Split-Path -Parent $PSScriptRoot
$Server = Join-Path $Root 'compliance-mcp-server'
$Base   = 'http://127.0.0.1:8085'
$Log    = Join-Path ([IO.Path]::GetTempPath()) 'compliance-mcp.log'
$script:Pass = 0; $script:Fail = 0; $proc = $null

function Ok($m)   { Write-Host "  [OK]   $m" -ForegroundColor Green; $script:Pass++ }
function Ko($m)   { Write-Host "  [KO]   $m" -ForegroundColor Red;   $script:Fail++ }
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Code($Method, $Headers) {
  try { (Invoke-WebRequest "$Base/mcp" -Method $Method -Headers $Headers -SkipHttpErrorCheck).StatusCode } catch { 0 }
}

try {
  Step '1. Prérequis'
  # Java : JAVA_HOME d'abord (c'est ce que Maven utilise), sinon le java du PATH
  $java = if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME/bin/java.exe")) { "$env:JAVA_HOME/bin/java.exe" }
          elseif (Get-Command java -ErrorAction SilentlyContinue) { (Get-Command java).Source } else { $null }
  if (-not $java) {
    Ko 'Aucun JDK trouvé (ni JAVA_HOME, ni java dans le PATH)'
    Write-Host '         -> winget install EclipseAdoptium.Temurin.21.JDK  puis rouvrir le terminal' -ForegroundColor Yellow
  } else {
    $ver = (& $java -version 2>&1 | Out-String)
    if ($ver -match 'version "(\d+)') { $major = [int]$Matches[1] } else { $major = 0 }
    if ($major -ge 21) { Ok "JDK $major ($java)" }
    else { Ko "JDK $major trouvé ($java), 21+ requis"; Write-Host '         -> winget install EclipseAdoptium.Temurin.21.JDK, puis JAVA_HOME vers ce JDK' -ForegroundColor Yellow }
  }
  # Maven : le wrapper du projet d'abord (pas d'installation globale), sinon mvn du PATH
  $wrapper = Join-Path $Server 'mvnw.cmd'
  $mvn = if (Test-Path $wrapper) { $wrapper } elseif (Get-Command mvn -ErrorAction SilentlyContinue) { 'mvn' } else { $null }
  if ($mvn) { Ok "Maven : $mvn" }
  else {
    Ko 'Ni Maven Wrapper (mvnw.cmd) ni mvn dans le PATH'
    Write-Host '         -> IntelliJ, fenêtre Maven, Execute Maven Goal : mvn wrapper:wrapper -Dtype=only-script' -ForegroundColor Yellow
  }
  if (Get-Command node -ErrorAction SilentlyContinue) { Ok 'Node présent (MCP Inspector)' } else { Write-Host '  [--]   Node absent (non bloquant)' }
  if ($script:Fail -gt 0) { Write-Host "`nPrérequis manquants : corriger puis relancer." -ForegroundColor Yellow; throw 'stop' }

  Step '2. Build + tests unitaires (mvn verify)'
  Push-Location $Server; & $mvn -B -q verify; $mvnOk = ($LASTEXITCODE -eq 0); Pop-Location
  if (-not $mvnOk) { Ko 'mvn verify en échec : corriger avant d''aller plus loin'; throw 'stop' }
  Ok 'Compilation, tests et SBOM'
  $sbom = Join-Path $Server 'target/classes/META-INF/sbom/application.cdx.json'
  if (Test-Path $sbom) { Ok "SBOM CycloneDX généré ($([math]::Round((Get-Item $sbom).Length/1KB)) Ko, embarqué dans le jar)" } else { Ko 'SBOM absent (target/classes/META-INF/sbom/application.cdx.json)' }
  $jar = Get-ChildItem "$Server/target/compliance-mcp-server-*.jar" | Where-Object Name -notlike '*.original' | Select-Object -First 1

  Step '3. Fail-fast sans clé API'
  $env:COMPLIANCE_MCP_API_KEY = $null
  $nk = Start-Process $java -ArgumentList '-jar', $jar.FullName -PassThru -NoNewWindow -RedirectStandardOutput "$Log.nokey"
  Start-Sleep 12
  if (-not $nk.HasExited) { Stop-Process $nk.Id; Ko 'Le server démarre sans clé (il devrait refuser)' } else { Ok 'Démarrage refusé sans clé' }

  Step '4. Démarrage avec clé'
  $env:COMPLIANCE_MCP_API_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
  $proc = Start-Process $java -ArgumentList '-jar', $jar.FullName -PassThru -NoNewWindow -RedirectStandardOutput $Log
  foreach ($i in 1..60) { try { if ((Invoke-RestMethod "$Base/actuator/health").status -eq 'UP') { break } } catch { Start-Sleep 1 } }
  try { if ((Invoke-RestMethod "$Base/actuator/health").status -eq 'UP') { Ok 'Health UP' } } catch { Ko "Server non joignable (log : $Log)"; throw 'stop' }

  Step '5. Sécurité HTTP'
  $c = Code POST @{};                                   if ($c -in 401,403) { Ok "Sans clé -> $c" } else { Ko "Sans clé -> $c" }
  $c = Code POST @{ 'X-API-Key' = 'mauvaise-cle' };     if ($c -in 401,403) { Ok "Mauvaise clé -> $c" } else { Ko "Mauvaise clé -> $c" }
  $c = Code POST @{ 'X-API-Key' = $env:COMPLIANCE_MCP_API_KEY; 'Origin' = 'https://evil.example' }
  if ($c -eq 403) { Ok 'Origin étranger -> 403' } else { Ko "Origin étranger -> $c" }
  Start-Sleep 1
  $rej = Select-String -Path $Log -Pattern 'AUTH_REJECTED' -SimpleMatch
  if (($rej | Where-Object { $_ -match 'API_KEY_INVALID' }) -and ($rej | Where-Object { $_ -match 'ORIGIN_NOT_ALLOWED' })) { Ok 'Refus journalisés (AUTH_REJECTED)' } else { Ko 'Pas de ligne AUTH_REJECTED dans le log' }
  if (Select-String -Path $Log -Pattern ([regex]::Escape($env:COMPLIANCE_MCP_API_KEY)) -Quiet) { Ko 'La clé apparaît en clair dans le log !' } else { Ok 'Clé absente du log' }

  Step '6. Protocole MCP'
  # curl.exe (fourni avec Windows 10+) gère mieux que Invoke-WebRequest les réponses SSE et les 202 sans corps
  $key = $env:COMPLIANCE_MCP_API_KEY
  $hdr = Join-Path ([IO.Path]::GetTempPath()) 'mcp-init-headers.txt'
  function Post([string]$body, [string]$sid) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) 'mcp-body.json'
    [IO.File]::WriteAllText($tmp, $body)
    $a = @('-s', '-N', '--max-time', '30', '-X', 'POST', "$Base/mcp",
           '-H', "X-API-Key: $key", '-H', 'Content-Type: application/json',
           '-H', 'Accept: application/json, text/event-stream', '--data-binary', "@$tmp")
    if ($sid) { $a += @('-H', "Mcp-Session-Id: $sid") }
    (& curl.exe @a) -join "`n"
  }
  $initBody = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"verify.ps1","version":"1"}}}'
  [IO.File]::WriteAllText((Join-Path ([IO.Path]::GetTempPath()) 'mcp-body.json'), $initBody)
  $init = (& curl.exe -s -N --max-time 30 -D $hdr -X POST "$Base/mcp" -H "X-API-Key: $key" -H 'Content-Type: application/json' `
           -H 'Accept: application/json, text/event-stream' --data-binary "@$(Join-Path ([IO.Path]::GetTempPath()) 'mcp-body.json')") -join "`n"
  if ($init -match 'serverInfo') { Ok 'initialize' } else { Ko "initialize sans réponse valide : $init" }
  $sid = (Get-Content $hdr | Where-Object { $_ -match '^mcp-session-id:' } | ForEach-Object { ($_ -split ':\s*', 2)[1].Trim() }) | Select-Object -First 1
  if ($sid) { Ok "session MCP $sid" } else { Write-Host '  [--]   pas de Mcp-Session-Id (server stateless)' }
  function Call($body) { Post $body $sid }
  Call '{"jsonrpc":"2.0","method":"notifications/initialized"}' | Out-Null
  $tools = Call '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  foreach ($t in 'get_data_classification','check_dependency','get_cve_status','open_cra_triage','declare_ai_assisted_change') {
    if ($tools -match "`"$t`"") { Ok "outil $t exposé" } else { Ko "outil $t absent" } }
  if ((Call '{"jsonrpc":"2.0","id":3,"method":"resources/list"}') -match 'policy://secure-sdlc') { Ok 'ressource policy://secure-sdlc' } else { Ko 'ressource absente' }

  Step '7. Appels d''outils (hors réseau)'
  if ((Call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_data_classification","arguments":{"entity":"Customer"}}}') -match 'PERSONAL') { Ok 'Customer classé' } else { Ko 'Customer' }
  if ((Call '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_data_classification","arguments":{"entity":"Employee"}}}') -match 'DPO') { Ok 'Employee -> renvoi DPO' } else { Ko 'Employee' }
  if ((Call '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"check_dependency","arguments":{"groupId":"com.thoughtworks.xstream","artifactId":"xstream"}}}') -match 'FORBIDDEN') { Ok 'xstream FORBIDDEN' } else { Ko 'xstream' }
  if ((Call '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"open_cra_triage","arguments":{"cveId":"CVE-2021-44228","component":"org.apache.logging.log4j:log4j-core","version":"2.14.1","product":"portail-client"}}}') -match 'earlyWarningDueBy') { Ok 'Dossier CRA avec échéances' } else { Ko 'open_cra_triage' }
  Start-Sleep 1
  if (Select-String -Path $Log -Pattern 'CRA_TRIAGE' -Quiet) { Ok 'Alerte WARN CRA_TRIAGE dans les logs' } else { Ko 'Pas de ligne CRA_TRIAGE' }

  if (-not $Offline) {
    Step '8. OSV.dev + CISA KEV (réseau)'
    foreach ($i in 1..30) { if (Select-String -Path $Log -Pattern 'Catalogue KEV' -Quiet) { break }; Start-Sleep 1 }
    if (Select-String -Path $Log -Pattern 'Catalogue KEV charg' -Quiet) { Ok 'Catalogue KEV chargé' } else { Ko 'KEV non chargé (www.cisa.gov bloqué ?)' }
    if ((Call '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_cve_status","arguments":{"ecosystem":"MAVEN","packageName":"org.apache.logging.log4j:log4j-core","version":"2.14.1"}}}') -match 'EXPLOITED') { Ok 'log4j 2.14.1 -> EXPLOITED' } else { Ko 'log4j : verdict inattendu' }
    if ((Call '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_cve_status","arguments":{"ecosystem":"NPM","packageName":"lodash","version":"4.17.15"}}}') -match 'VULNERABLE') { Ok 'lodash 4.17.15 -> VULNERABLE' } else { Ko 'lodash : verdict inattendu' }
  } else { Write-Host "`n== 8. Tests réseau ignorés (-Offline)" }
}
catch { if ($_.ToString() -ne 'stop') { Ko $_ } }
finally {
  if ($proc -and -not $proc.HasExited) { Stop-Process $proc.Id }
  Write-Host "`nRésultat : $script:Pass OK, $script:Fail KO   (log du server : $Log)"
  if ($script:Fail -gt 0) { exit 1 }
}
