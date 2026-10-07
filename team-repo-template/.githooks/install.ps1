# Active le hook pre-commit gitleaks pour ce dépôt (Windows, PowerShell 7).
# Usage, depuis la racine du projet : pwsh ./.githooks/install.ps1
# - installe gitleaks 8.30.1 dans %LOCALAPPDATA%\gitleaks si absent, après vérification SHA-256
# - ajoute ce dossier au PATH utilisateur
# - active les hooks versionnés : git config core.hooksPath .githooks
$ErrorActionPreference = 'Stop'
$Version  = '8.30.1'
$Sha256   = 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e'   # gitleaks_8.30.1_checksums.txt
$Dir      = Join-Path $env:LOCALAPPDATA 'gitleaks'

if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
  $zip = Join-Path ([IO.Path]::GetTempPath()) "gitleaks_$Version.zip"
  $url = "https://github.com/gitleaks/gitleaks/releases/download/v$Version/gitleaks_${Version}_windows_x64.zip"
  Write-Host "Téléchargement de gitleaks $Version..." -ForegroundColor Cyan
  Invoke-WebRequest $url -OutFile $zip
  # Chaîne d'approvisionnement : on n'exécute pas un binaire dont l'empreinte n'est pas celle publiée
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $Sha256) { Remove-Item $zip; throw "Empreinte SHA-256 inattendue ($actual) : installation annulée." }
  New-Item -ItemType Directory -Force $Dir | Out-Null
  Expand-Archive $zip -DestinationPath $Dir -Force
  Remove-Item $zip
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($userPath -notlike "*$Dir*") { [Environment]::SetEnvironmentVariable('Path', "$userPath;$Dir", 'User') }
  $env:Path += ";$Dir"
  Write-Host "gitleaks installé dans $Dir (empreinte vérifiée). Rouvrir IntelliJ pour qu'il voie le nouveau PATH." -ForegroundColor Green
}
gitleaks version
git config core.hooksPath .githooks
Write-Host 'Hook pre-commit actif : tout commit contenant un secret sera bloqué.' -ForegroundColor Green
