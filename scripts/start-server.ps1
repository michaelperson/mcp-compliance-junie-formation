# Démarre le compliance-mcp-server avec une clé API de 64 caractères.
# La clé est générée si elle n'existe pas encore dans CE terminal, puis copiée dans le presse-papier
# pour MCP Inspector. Usage, depuis la racine du kit :
#   pwsh ./scripts/start-server.ps1                    # clé générée
#   pwsh ./scripts/start-server.ps1 -UpdateJunieConfig # + écrit la clé dans ~/.junie/mcp/mcp.json
#   pwsh ./scripts/start-server.ps1 -AllowInspector    # autorise aussi l'origine de MCP Inspector (démo uniquement)
#   pwsh ./scripts/start-server.ps1 -AllowInspector -OpenInspector -UpdateJunieConfig   # tout
param([switch]$AllowInspector, [switch]$OpenInspector, [switch]$UpdateJunieConfig)

$Server = Join-Path (Split-Path -Parent $PSScriptRoot) 'compliance-mcp-server'

if (-not $env:COMPLIANCE_MCP_API_KEY -or $env:COMPLIANCE_MCP_API_KEY.Length -lt 32) {
  $env:COMPLIANCE_MCP_API_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
  Write-Host 'Clé API générée pour cette session.' -ForegroundColor Green
}
$key = $env:COMPLIANCE_MCP_API_KEY
$key | Set-Clipboard
# La clé n'est jamais affichée en entier (écran partagé, enregistrement de la séance, historique du terminal)
Write-Host "Clé ($($key.Length) caractères, $($key.Substring(0,6))…) copiée dans le presse-papier." -ForegroundColor Cyan
Write-Host '  -> MCP Inspector : en-tête X-API-Key = Ctrl+V  (ne pas confondre avec le jeton de session d''Inspector)' -ForegroundColor Cyan

if ($UpdateJunieConfig) {
  # Configuration MCP de Junie au niveau utilisateur : hors de tout dépôt Git.
  # Les autres serveurs MCP déjà déclarés sont conservés ; seule l'entrée "compliance" est mise à jour.
  $dir  = Join-Path $env:USERPROFILE '.junie\mcp'
  $file = Join-Path $dir 'mcp.json'
  New-Item -ItemType Directory -Force $dir | Out-Null
  $cfg = if (Test-Path $file) { Get-Content $file -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
  if (-not $cfg) { $cfg = @{} }
  if (-not $cfg.ContainsKey('mcpServers')) { $cfg['mcpServers'] = @{} }
  $cfg['mcpServers']['compliance'] = @{
    url     = 'http://127.0.0.1:8085/mcp'   # format « remote server » de la doc Junie : url + headers, pas de champ type
    headers = @{ 'X-API-Key' = $key }
  }
  $cfg | ConvertTo-Json -Depth 10 | Set-Content $file -Encoding utf8NoBOM
  # Fichier lisible par l'utilisateur courant uniquement (moindre privilège)
  icacls $file /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
  Write-Host "Junie : clé écrite dans $file (redémarrer Junie pour la prendre en compte)." -ForegroundColor Green
}

if ($AllowInspector) {
  $env:MCP_SECURITY_ALLOWED_ORIGINS = 'http://127.0.0.1:6274,http://localhost:6274'
  Write-Host "Origines autorisées (démo) : $env:MCP_SECURITY_ALLOWED_ORIGINS" -ForegroundColor Yellow
}

if ($OpenInspector) {
  # Inspector tourne dans sa propre fenêtre : il ouvre le navigateur sur http://127.0.0.1:6274 dès qu'il est prêt
  Start-Process pwsh -ArgumentList '-NoExit', '-Command', 'npx -y @modelcontextprotocol/inspector'
  Write-Host 'MCP Inspector lancé dans une nouvelle fenêtre (le navigateur s''ouvre dans quelques secondes).' -ForegroundColor Cyan
}

Write-Host "`nDémarrage sur http://127.0.0.1:8085/mcp  (Ctrl+C pour arrêter)`n"
Push-Location $Server
try { & .\mvnw.cmd spring-boot:run } finally { Pop-Location }
