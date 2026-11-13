<#
.SYNOPSIS
    Audit en lecture seule d'un poste Windows : persistance, traces d'activateurs Office/Windows,
    signes de compromission. Produit un rapport HTML et JSON.

.DESCRIPTION
    Complément d'un antivirus, pas un remplaçant. Le script ne modifie rien sur le système
    (seule exception : -LoadUserHives monte puis démonte les ruches NTUSER.DAT des utilisateurs
    déconnectés). Compatible Windows PowerShell 5.1 et PowerShell 7.

    Sévérités : Critique (compromission probable), Élevé (à traiter), Moyen (à vérifier), Info (inventaire).
    Codes de sortie : 0 = rien au-dessus d'Info, 1 = au moins un Moyen, 2 = au moins un Élevé ou Critique.

.PARAMETER OutputDir
    Dossier des rapports (défaut : .\reports à côté du script).
.PARAMETER Days
    Profondeur d'analyse des journaux et des fichiers récents, en jours (défaut : 30).
.PARAMETER Only
    Ne lancer que certains contrôles (noms affichés par -ListChecks, jokers acceptés).
.PARAMETER Skip
    Exclure certains contrôles.
.PARAMETER LoadUserHives
    Charger temporairement le registre des utilisateurs déconnectés pour l'analyser aussi.
.PARAMETER PassThru
    Renvoyer les résultats sous forme d'objets (pour un traitement en pipeline).
.PARAMETER NoHtml
    Ne pas générer le rapport HTML (JSON seulement).
.PARAMETER ListChecks
    Afficher la liste des contrôles et quitter.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-WinTriage.ps1
.EXAMPLE
    .\Invoke-WinTriage.ps1 -Days 90 -LoadUserHives -OutputDir \\serveur\partage\triage
.EXAMPLE
    .\Invoke-WinTriage.ps1 -Only 'Activateurs*','Tâches*' -PassThru | Where-Object Severity -ne 'Info'
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [int]$Days = 30,
    [string[]]$Only,
    [string[]]$Skip,
    [switch]$LoadUserHives,
    [switch]$PassThru,
    [switch]$NoHtml,
    [switch]$ListChecks,
    [string]$IndicatorsFile,
    # Réservé aux tests : script chargé après la définition des fonctions d'accès au système (voir tests\)
    [string]$TestHooks
)

$ErrorActionPreference = 'SilentlyContinue'
# Les cmdlets issues de modules ignorent $ErrorActionPreference sous PowerShell 5.1
$PSDefaultParameterValues = @{ '*:ErrorAction' = 'SilentlyContinue' }
$script:Version = '1.0.0'
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir)      { $OutputDir = Join-Path $ScriptDir 'reports' }
if (-not $IndicatorsFile) { $IndicatorsFile = Join-Path $ScriptDir 'indicators.psd1' }
if (-not (Test-Path -LiteralPath $IndicatorsFile)) { Write-Host "Fichier d'indicateurs introuvable : $IndicatorsFile" -ForegroundColor Red; exit 3 }
$IOC = Import-PowerShellDataFile -LiteralPath $IndicatorsFile
if (-not $IOC) { Write-Host "Fichier d'indicateurs illisible : $IndicatorsFile" -ForegroundColor Red; exit 3 }
$Since = (Get-Date).AddDays(-$Days)
# Racines du système (variables plutôt que $env: pour pouvoir les rediriger dans les tests)
$SysRoot = $env:SystemRoot; $PF = $env:ProgramFiles; $PF86 = ${env:ProgramFiles(x86)}; $PData = $env:ProgramData
$PublicDir = $env:PUBLIC; $CommonPF = $env:CommonProgramFiles; $CommonPF86 = ${env:CommonProgramFiles(x86)}
function Expand-IocPath([string]$p) {
    $map = @{ '%SystemRoot%' = $SysRoot; '%ProgramFiles%' = $PF; '%ProgramFiles(x86)%' = $PF86; '%ProgramData%' = $PData; '%PUBLIC%' = $PublicDir }
    foreach ($k in $map.Keys) { if ($map[$k]) { $p = $p -ireplace [regex]::Escape($k), $map[$k].Replace('$', '$$') } }
    [Environment]::ExpandEnvironmentVariables($p)
}

# =====================================================================================
#  Résultats
# =====================================================================================
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Checks   = New-Object System.Collections.Generic.List[object]
$script:Cur      = $null
$SevRank  = @{ Critique = 0; Eleve = 1; Moyen = 2; Info = 3 }
$SevLabel = @{ Critique = 'Critique'; Eleve = 'Élevé'; Moyen = 'Moyen'; Info = 'Info' }

function Add-Finding {
    param([ValidateSet('Critique', 'Eleve', 'Moyen', 'Info')][string]$Severity, [string]$Category, [string]$Title,
          [string]$Detail, [string]$Evidence, [string]$Advice)
    if (-not $Category -and $script:Cur) { $Category = $script:Cur.Name }
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail; Evidence = $Evidence; Advice = $Advice
        Check = $(if ($script:Cur) { $script:Cur.Name } else { '' })
    })
    if ($script:Cur) { $script:Cur.Results++ }
}
function Add-Examined([int]$n = 1) { if ($script:Cur) { $script:Cur.Examined += $n } }
function Add-Note([string]$t) { if ($script:Cur) { $script:Cur.Notes += $t } }
function Format-When($d) { if ($d -is [datetime]) { $d.ToString('dd/MM/yyyy HH:mm') } else { "$d" } }
function Limit-Text([string]$s, [int]$max = 300) { if ($s -and $s.Length -gt $max) { $s.Substring(0, $max) + '…' } else { $s } }

# =====================================================================================
#  Accès au système (fonctions remplaçables par -TestHooks)
# =====================================================================================
function Test-IsAdmin {
    try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false }
}
function Get-RegValues([string]$Path) {
    $k = Get-Item -LiteralPath $Path
    if (-not $k) { return $null }
    $h = @{}
    foreach ($n in $k.GetValueNames()) { $h[$n] = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    return $h
}
function Get-RegSubKeys([string]$Path) {
    $k = Get-Item -LiteralPath $Path
    if ($k) { return @($k.GetSubKeyNames()) }
    return @()
}
function Get-HostInfo {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [pscustomobject]@{
        Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"
        OS = "$($os.Caption) $($os.Version)"; InstallDate = $os.InstallDate; LastBoot = $os.LastBootUpTime
        PartOfDomain = [bool]$cs.PartOfDomain; Domain = "$($cs.Domain)"
        PSVersion = "$($PSVersionTable.PSVersion)"
    }
}
function Get-TasksData {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-ScheduledTask)) {
        $acts = @()
        foreach ($a in @($t.Actions)) {
            if ($a.Execute) { $acts += ("$($a.Execute) $($a.Arguments)").Trim() }
            elseif ($a.ClassId) { $acts += "COM:$($a.ClassId)" }
        }
        $out.Add([pscustomobject]@{ Path = "$($t.TaskPath)"; Name = "$($t.TaskName)"; Actions = $acts; Author = "$($t.Author)"
                                    Date = "$($t.Date)"; User = "$($t.Principal.UserId)"; State = "$($t.State)" })
    }
    return $out
}
function Get-ServicesData {
    @(Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName)
}
function Get-ProcessesData {
    @(Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
}
function Get-ListeningPorts {
    @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess)
}
function Get-WmiSubscriptions {
    $o = @()
    foreach ($c in @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer)) {
        $cls = "$($c.CimClass.CimClassName)"
        $d = ''
        if ($cls -eq 'CommandLineEventConsumer') { $d = "$($c.ExecutablePath) $($c.CommandLineTemplate)" }
        elseif ($cls -eq 'ActiveScriptEventConsumer') { $d = "[$($c.ScriptingEngine)] $($c.ScriptFileName) $($c.ScriptText)" }
        $o += [pscustomobject]@{ Class = $cls; Name = "$($c.Name)"; Detail = $d.Trim() }
    }
    foreach ($f in @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter)) {
        $o += [pscustomobject]@{ Class = '__EventFilter'; Name = "$($f.Name)"; Detail = "$($f.Query)" }
    }
    return $o
}
function Get-LicensingProducts {
    @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter 'PartialProductKey IS NOT NULL' |
        Select-Object Name, Description, LicenseStatus, GracePeriodRemaining, PartialProductKey, KeyManagementServiceMachine, DiscoveredKeyManagementServiceMachineName)
}
function Get-DefenderData {
    $st = Get-MpComputerStatus
    if (-not $st) { return $null }
    [pscustomobject]@{
        Status = $st; Prefs = (Get-MpPreference); Detections = @(Get-MpThreatDetection); Threats = @(Get-MpThreat)
        OtherAV = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { "$($_.displayName)" })
    }
}
function Get-EventData([string]$Log, [int[]]$Ids, [datetime]$Start, [string]$Provider) {
    $f = @{ LogName = $Log; Id = $Ids; StartTime = $Start }
    if ($Provider) { $f.ProviderName = $Provider }
    @(Get-WinEvent -FilterHashtable $f -MaxEvents 3000 | ForEach-Object {
        [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Message = "$($_.Message)"; Props = @($_.Properties | ForEach-Object { "$($_.Value)" }) }
    })
}
function Get-LocalUsersData {
    @(Get-LocalUser | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Enabled = [bool]$_.Enabled; SID = "$($_.SID)"; LastLogon = $_.LastLogon; PasswordLastSet = $_.PasswordLastSet } })
}
function Get-LocalAdmins {
    $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.Name)" })
    if ($m.Count) { return $m }
    # Repli : Get-LocalGroupMember échoue quand le groupe contient un SID orphelin
    try {
        $grp = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value -replace '^.*\\', ''
        $lines = @(net.exe localgroup $grp 2>$null)
        $start = [array]::IndexOf($lines, ($lines | Where-Object { $_ -match '^-{5,}' } | Select-Object -First 1))
        if ($start -ge 0) { return @($lines[($start + 1)..($lines.Count - 1)] | Where-Object { $_ -and $_ -notmatch '^(La commande|The command)' }) }
    } catch { }
    return @()
}
function Resolve-Lnk([string]$Path) {
    try { $s = (New-Object -ComObject WScript.Shell).CreateShortcut($Path); return ("$($s.TargetPath) $($s.Arguments)").Trim() } catch { return $null }
}
function Get-BitsJobs {
    $out = @(); $cur = $null
    foreach ($l in @(bitsadmin.exe /list /allusers /verbose 2>$null)) {
        if ($l -match "^GUID:\s*(\S+)\s+DISPLAY:\s*'?(.*?)'?\s*$") { if ($cur) { $out += $cur }; $cur = [pscustomobject]@{ Name = $Matches[2]; NotifyCmd = ''; Urls = @() } }
        elseif ($cur -and $l -match '^NOTIFICATION COMMAND LINE:\s*(.+)$') { if ($Matches[1].Trim() -ne 'none') { $cur.NotifyCmd = $Matches[1].Trim() } }
        elseif ($cur -and $l -match '(https?://\S+)') { $cur.Urls += $Matches[1] }
    }
    if ($cur) { $out += $cur }
    return $out
}
function Get-Sha256([string]$Path) { if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } }
$script:SigCache = @{}
function Get-Sig([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Exists = $false; Signed = $false; Microsoft = $false; Signer = ''; Status = 'Inconnu' } }
    $key = $Path.ToLower()
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }
    $r = [pscustomobject]@{ Exists = $false; Signed = $false; Microsoft = $false; Signer = ''; Status = 'Fichier introuvable' }
    if ($Path -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\[^\\]+\.exe$') {
        # Alias d'exécution d'une application du Store : point d'analyse sans contenu, non vérifiable
        $r.Exists = $true; $r.Signed = $true; $r.Status = 'Alias d''application du Microsoft Store'
    }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        $r.Exists = $true; $r.Status = 'Non signé'
        $s = Get-AuthenticodeSignature -LiteralPath $Path
        if (-not $s) { $r.Signed = $true; $r.Status = 'Signature illisible (fichier verrouillé ou accès refusé)' }   # doute : pas d'alerte
        else {
            if ("$($s.Status)" -eq 'Valid') { $r.Signed = $true; $r.Status = 'Signé' } elseif ("$($s.Status)" -ne 'NotSigned') { $r.Status = "Signature invalide ($($s.Status))" }
            if ($s.SignerCertificate) {
                $r.Signer = ($s.SignerCertificate.Subject -replace '^CN="?([^,"]+).*$', '$1')
                if ($r.Signed -and $s.SignerCertificate.Subject -match 'O=Microsoft Corporation') { $r.Microsoft = $true }
            }
        }
    }
    $script:SigCache[$key] = $r
    return $r
}
$script:LoadedHives = @()
function Get-UserContexts {
    $list = @()
    if ($script:IsAdmin) {
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($sid in @(Get-RegSubKeys $pl)) {
            if ($sid -notmatch '^S-1-5-21-' -and $sid -ne 'S-1-5-18') { continue }
            $v = Get-RegValues "$pl\$sid"
            if (-not $v) { continue }
            $p = [Environment]::ExpandEnvironmentVariables("$($v['ProfileImagePath'])")
            if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
            $root = $null
            if (Test-Path -LiteralPath "Registry::HKEY_USERS\$sid") { $root = "Registry::HKEY_USERS\$sid" }
            elseif ($LoadUserHives -and (Test-Path -LiteralPath (Join-Path $p 'NTUSER.DAT'))) {
                $name = "WinTriage_$($script:LoadedHives.Count)"
                $global:LASTEXITCODE = 1
                $null = reg.exe load "HKU\$name" (Join-Path $p 'NTUSER.DAT') 2>$null
                if ($LASTEXITCODE -eq 0) { $script:LoadedHives += $name; $root = "Registry::HKEY_USERS\$name" }
            }
            $list += [pscustomobject]@{ Name = (Split-Path $p -Leaf); Sid = $sid; Profile = $p; RegRoot = $root }
        }
    }
    if (-not $list.Count) { $list += [pscustomobject]@{ Name = $env:USERNAME; Sid = ''; Profile = $env:USERPROFILE; RegRoot = 'HKCU:' } }
    return $list
}

# =====================================================================================
#  Analyse d'une commande de démarrage automatique
# =====================================================================================
$WritableRegex = '(?i)\\(AppData|Temp|Tmp|Downloads|Desktop|Documents|Public|ProgramData|\$Recycle\.Bin|PerfLogs)\\|^[A-Z]:\\Users\\[^\\]+\\[^\\]+$|\\Windows\\(Temp|Tasks|debug|Tracing)\\'
$StrongCmd = @(
    @{ L = 'commande PowerShell encodée';        R = '(?i)(powershell|pwsh).*\s-(e|ec|enc|enco[a-z]*)\s+[A-Za-z0-9+/=]{20,}' }
    @{ L = 'téléchargement depuis Internet';     R = '(?i)downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|\b(iwr|irm|curl|wget)(\.exe)?\s.*https?://|bitsadmin.+/transfer|certutil.+-urlcache|start-bitstransfer' }
    @{ L = 'exécution de code en mémoire';       R = '(?i)\biex\b|invoke-expression|frombase64string|reflection\.assembly|\]::load\(' }
    @{ L = 'scriptlet ou script distant';        R = '(?i)regsvr32.+(/i:|scrobj)|mshta.+(https?:|javascript:|vbscript:)|rundll32.+(javascript:|vbscript:)' }
)
$MediumCmd = @(
    @{ L = 'fenêtre masquée';                    R = '(?i)\s-w(in|indowstyle)?\s+h(id|idden)?\b' }
    @{ L = 'adresse web dans la commande';       R = '(?i)https?://' }
    @{ L = 'script lancé par un interpréteur';   R = '(?i)\b(wscript|cscript|mshta)(\.exe)?\b.+\.(js|jse|vbs|vbe|wsf|hta)\b|\bpowershell(\.exe)?\b.+-(f|file)\s|\bcmd(\.exe)?\s+/c\b' }
    @{ L = 'DLL chargée depuis un dossier modifiable'; R = '(?i)rundll32(\.exe)?\s+"?[A-Z]:\\(Users|ProgramData|Windows\\Temp)\\' }
)
function Resolve-ExePath([string]$Cmd) {
    if (-not $Cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    if ($c -match '^(?i)\\SystemRoot\\(.*)$') { $c = Join-Path $SysRoot $Matches[1] }
    elseif ($c -match '^(?i)(system32|syswow64)\\') { $c = Join-Path $SysRoot $c }
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    $parts = $c -split ' '
    $acc = ''
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($i -eq 0) { $acc = $parts[0] } else { $acc = "$acc $($parts[$i])" }
        foreach ($cand in @($acc, "$acc.exe")) { if ($cand -match '[\\/]' -and (Test-Path -LiteralPath $cand -PathType Leaf)) { return $cand } }
    }
    $first = $parts[0]
    if ($first -and $first -notmatch '[\\/]') {
        $g = Get-Command -Name $first -CommandType Application | Select-Object -First 1
        if ($g) { return $g.Source }
    }
    return $first
}
# Classe une entrée de démarrage. -Quiet : ne rien émettre en dessous de Moyen (zones bruyantes).
function Add-Autorun {
    param([string]$Category, [string]$Kind, [string]$Name, [string]$Command, [string]$Where, [switch]$Quiet, [string]$Advice)
    Add-Examined
    if (-not $Command) { return }
    $exe = Resolve-ExePath $Command
    $sig = Get-Sig $exe
    $reasons = @(); $sev = 'Info'
    foreach ($p in $StrongCmd) { if ($Command -match $p.R) { $reasons += $p.L; $sev = 'Eleve' } }
    if ("$Name $Command" -match $IOC.ActivatorRegex) { $reasons += 'nom ou commande d''activateur connu'; $sev = 'Eleve'; $Category = 'Activateurs et licences' }
    $writable = ($exe -match $WritableRegex)
    $what = if ($exe -match '(?i)\.(cmd|bat|ps1|vbs|vbe|js|jse|wsf|hta)$') { 'script' } else { 'binaire non signé' }
    if ($sig.Exists -and -not $sig.Signed -and $writable) { $reasons += "$what dans un dossier modifiable par l'utilisateur"; $sev = 'Eleve' }
    if ($sev -eq 'Info') {
        if (-not $Quiet) { foreach ($p in $MediumCmd) { if ($Command -match $p.R) { $reasons += $p.L; $sev = 'Moyen' } } }
        if ($sig.Exists -and -not $sig.Signed) { $reasons += $what; $sev = 'Moyen' }
    }
    if ($sev -eq 'Info') {
        if ($sig.Microsoft) { return }                       # signé Microsoft, rien de suspect : compté, pas listé
        if ($Quiet) { return }
        if (-not $sig.Exists) { $reasons += 'binaire non résolu (entrée orpheline ou commande complexe)' }
    }
    $signer = if ($sig.Signer) { "$($sig.Status) — $($sig.Signer)" } else { $sig.Status }
    $detail = if ($reasons.Count) { ($reasons -join ' ; ') } else { 'entrée tierce, sans signe suspect' }
    Add-Finding -Severity $sev -Category $Category -Title "$Kind : $Name" -Detail $detail `
        -Evidence ("Emplacement : $Where`nCommande    : $(Limit-Text $Command 500)`nBinaire     : $exe`nSignature   : $signer") -Advice $Advice
}
function Test-NameList([string]$Name, [string[]]$Patterns) { foreach ($p in $Patterns) { if ($Name -like $p) { return $true } }; return $false }

# =====================================================================================
#  Contrôles
# =====================================================================================
function Check-Activators {
    $cat = 'Activateurs et licences'
    $advOhook = 'Désinstaller l''activateur (MAS propose une option de désinstallation Ohook), réparer Office, puis activer avec une licence valide.'

    # --- 1. Ohook : sppc.dll non Microsoft et lien sppcs.dll dans les dossiers d'Office
    $roots = @("$PF\Microsoft Office", "$PF86\Microsoft Office",
               "$CommonPF\microsoft shared\OfficeSoftwareProtectionPlatform",
               "$CommonPF86\microsoft shared\OfficeSoftwareProtectionPlatform") | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($r in $roots) {
        foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -Depth 5 -File -Filter 'sppc*.dll' -Force)) {
            Add-Examined
            if ($f.Name -eq 'sppcs.dll') {
                Add-Finding Eleve $cat 'Ohook : lien sppcs.dll dans le dossier d''Office' 'Ce fichier est créé par Ohook pour rediriger vers la vraie bibliothèque de licences de Windows.' "Fichier : $($f.FullName)`nType    : $($f.LinkType) $($f.Target)" $advOhook
                continue
            }
            $sig = Get-Sig $f.FullName
            if (-not $sig.Microsoft) {
                $vi = $f.VersionInfo
                $what = if ("$($vi.FileDescription) $($vi.ProductName)" -match '(?i)ohook') { "Ohook $($vi.FileVersion)" } else { 'bibliothèque de licences non signée par Microsoft' }
                Add-Finding Eleve $cat "Ohook : $($f.Name) remplacée dans le dossier d'Office ($what)" 'Cette DLL intercepte la vérification de licence d''Office et répond « licencié ».' `
                    "Fichier   : $($f.FullName)`nTaille    : $($f.Length) octets`nDescription : $($vi.FileDescription) / $($vi.CompanyName)`nSignature : $($sig.Status) $($sig.Signer)`nModifié   : $(Format-When $f.LastWriteTime)" $advOhook
            }
        }
    }

    # --- 2. Fichiers et dossiers connus
    foreach ($p in $IOC.ActivatorPaths) {
        $e = Expand-IocPath $p
        Add-Examined
        if ($e -match '%') { continue }
        foreach ($i in @(Get-Item -Path $e -Force)) {
            Add-Finding Eleve $cat "Fichier ou dossier d'activateur : $($i.Name)" 'Emplacement utilisé par un outil d''activation connu.' "Chemin : $($i.FullName)`nCréé   : $(Format-When $i.CreationTime)`nModifié : $(Format-When $i.LastWriteTime)" 'Identifier qui l''a déposé et quand, puis supprimer après collecte.'
        }
    }

    # --- 3. Tâches planifiées et services d'activateurs
    foreach ($t in $script:Tasks) {
        Add-Examined
        if ((Test-NameList $t.Name $IOC.ActivatorTaskNames) -or ($IOC.ActivatorTaskFolders | Where-Object { $t.Path -like "$_*" })) {
            Add-Finding Eleve $cat "Tâche planifiée d'activateur : $($t.Path)$($t.Name)" 'Tâche de renouvellement automatique de l''activation.' "Actions : $($t.Actions -join ' | ')`nCompte  : $($t.User)`nCréée   : $($t.Date)" 'Supprimer la tâche et le script qu''elle lance.'
        }
    }
    foreach ($s in $script:Services) {
        Add-Examined
        if (Test-NameList $s.Name $IOC.ActivatorServices) {
            Add-Finding Eleve $cat "Service d'activateur : $($s.Name)" 'Service installé par un émulateur KMS.' "Commande : $($s.PathName)`nÉtat     : $($s.State) / $($s.StartMode)" 'Arrêter et supprimer le service, puis analyser le binaire.'
        }
    }

    # --- 4. Serveur KMS configuré dans le registre
    $kmsKeys = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
                 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform')
    $seen = @{}
    foreach ($base in $kmsKeys) {
        $paths = @($base)
        foreach ($app in @(Get-RegSubKeys $base)) {
            if ($app -notmatch '^[0-9a-fA-F-]{36}$') { continue }
            $paths += "$base\$app"
            foreach ($sku in @(Get-RegSubKeys "$base\$app")) { $paths += "$base\$app\$sku" }
        }
        foreach ($k in $paths) {
            $v = Get-RegValues $k
            Add-Examined
            if (-not $v -or -not $v['KeyManagementServiceName']) { continue }
            $h = "$($v['KeyManagementServiceName'])".Trim()
            if ($seen["$h|$base"]) { continue }
            $seen["$h|$base"] = $true
            $ev = "Clé     : $k`nServeur : $h`nPort    : $($v['KeyManagementServicePort'])"
            if ($IOC.KmsPlaceholderHosts -contains $h) {
                Add-Finding Eleve $cat "Adresse KMS factice : $h" 'Adresse posée par un activateur (MAS utilise 10.0.0.10 pour Ohook/Online KMS et 127.0.0.2 pour verrouiller KMS38).' $ev 'Supprimer la valeur (slmgr /ckms) et réactiver avec une licence valide.'
            } elseif ($h -match $IOC.PublicKmsRegex) {
                Add-Finding Eleve $cat "Serveur KMS public pirate : $h" 'Le poste demande son activation à un serveur KMS tiers sur Internet.' $ev 'Supprimer la valeur (slmgr /ckms) et réactiver avec une licence valide.'
            } elseif ($script:HostInfo.PartOfDomain) {
                Add-Finding Info $cat "Serveur KMS configuré : $h" 'Poste joint à un domaine : serveur KMS d''entreprise probable.' $ev
            } else {
                Add-Finding Moyen $cat "Serveur KMS configuré sur un poste hors domaine : $h" 'Un poste hors domaine n''a normalement pas de serveur KMS.' $ev 'Vérifier que ce serveur appartient bien à votre organisation.'
            }
        }
    }

    # --- 5. État des licences (KMS38, KMS4k/TSforge, licence en volume inattendue)
    $status = @{ 0 = 'Sans licence'; 1 = 'Activé'; 2 = 'Période de grâce initiale'; 3 = 'Grâce (matériel modifié)'; 4 = 'Grâce (non authentique)'; 5 = 'Notification'; 6 = 'Grâce étendue' }
    foreach ($p in @(Get-LicensingProducts)) {
        Add-Examined
        $days = [math]::Round([double]$p.GracePeriodRemaining / 1440)
        $ev = "Produit : $($p.Name)`nCanal   : $($p.Description)`nÉtat    : $($status[[int]$p.LicenseStatus])`nClé     : …$($p.PartialProductKey)`nValidité restante : $days jours`nServeur KMS : $($p.KeyManagementServiceMachine) $($p.DiscoveredKeyManagementServiceMachineName)"
        if ("$($p.Description)" -match 'KMSCLIENT|KMS_' -and [double]$p.GracePeriodRemaining -gt 270000) {
            Add-Finding Eleve $cat "Activation KMS d'une durée anormale ($days jours) : $($p.Name)" 'Une activation KMS légitime dure 180 jours. Une durée de plusieurs années correspond à KMS38 ou à KMS4k (TSforge).' $ev 'Réinstaller une clé légitime (slmgr /ipk) et réactiver.'
        } elseif ("$($p.Description)" -match 'KMSCLIENT' -and -not $script:HostInfo.PartOfDomain) {
            Add-Finding Moyen $cat "Licence en volume (KMS) sur un poste hors domaine : $($p.Name)" 'Les éditions en volume s''activent auprès d''un serveur KMS d''entreprise. Hors domaine, c''est souvent le signe d''un activateur.' $ev 'Vérifier l''origine de la licence.'
        } else {
            Add-Finding Info $cat "Licence : $($p.Name)" "$($status[[int]$p.LicenseStatus])" $ev
        }
    }
    Add-Note 'Les activations HWID et TSforge (ZeroCID) sont indiscernables d''une activation légitime une fois posées : seules leurs traces annexes sont détectables.'

    # --- 6. Restes d'activation HWID et stratégie NoGenTicket
    foreach ($f in @(Get-ChildItem -LiteralPath "$PData\Microsoft\Windows\ClipSVC\GenuineTicket" -File -Force)) {
        Add-Finding Moyen $cat "Ticket d'activation resté sur le disque : $($f.Name)" 'Windows consomme et supprime normalement ces tickets. Un reste peut provenir d''une activation HWID forcée.' "Fichier : $($f.FullName)`nCréé    : $(Format-When $f.CreationTime)"
    }
    $pol = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    if ($pol -and "$($pol['NoGenTicket'])" -eq '1') {
        $sev = if ($script:HostInfo.PartOfDomain) { 'Info' } else { 'Moyen' }
        Add-Finding $sev $cat 'Validation en ligne de l''activation KMS désactivée (NoGenTicket)' 'Stratégie posée par les activateurs KMS, parfois aussi par une GPO d''entreprise.' 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket = 1'
    }

    # --- 7. Valeur de registre Office posée par Ohook (par utilisateur)
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $v = Get-RegValues "$($u.RegRoot)\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency"
        Add-Examined
        if ($v -and "$($v['TimeOfLastHeartbeatFailure'])" -match '^(20[3-9]\d|2[1-9]\d\d)') {
            Add-Finding Eleve $cat "Ohook : contrôle d'abonnement Office neutralisé pour $($u.Name)" 'La date est placée loin dans le futur pour empêcher Office de vérifier l''abonnement en ligne.' "Clé    : $($u.RegRoot)\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency`nValeur : TimeOfLastHeartbeatFailure = $($v['TimeOfLastHeartbeatFailure'])" $advOhook
        }
    }

    # --- 8. Détournement du service de licences (KMS_VL_ALL, KMSpico)
    foreach ($img in 'SppExtComObj.exe', 'osppsvc.exe', 'sppsvc.exe') {
        foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
            $v = Get-RegValues "$base\$img"
            Add-Examined
            if ($v -and ($v['Debugger'] -or $v['VerifierDlls'])) {
                Add-Finding Eleve $cat "Service de licences détourné : $img" 'Technique des émulateurs KMS locaux (KMS_VL_ALL, KMSpico).' "Clé : $base\$img`nDebugger : $($v['Debugger'])`nVerifierDlls : $($v['VerifierDlls'])" 'Supprimer la clé et la DLL associée.'
            }
        }
    }
}

function Check-PSHistory {
    foreach ($u in $script:Users) {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $u.Profile 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine') -File -Filter '*_history.txt' -Force)) {
            Add-Examined
            $lines = @(Get-Content -LiteralPath $f.FullName)
            foreach ($p in $IOC.HistoryPatterns) {
                $hits = @($lines | Where-Object { $_ -match $p.Regex })
                if (-not $hits.Count) { continue }
                $shown = ($hits | Select-Object -Unique -First 6 | ForEach-Object { '  ' + (Limit-Text $_ 240) }) -join "`n"
                Add-Finding $p.Severity $p.Category "$($p.Label) — historique de $($u.Name)" "$($hits.Count) commande(s) dans l'historique PowerShell. L'historique ne porte pas de date." "Fichier : $($f.FullName) (modifié le $(Format-When $f.LastWriteTime))`n$shown" 'Recouper avec l''utilisateur et les journaux pour dater l''exécution.'
            }
        }
    }
    # Blocs de script journalisés (si la journalisation PowerShell est active)
    $ev = @(Get-EventData 'Microsoft-Windows-PowerShell/Operational' @(4104) $Since)
    Add-Examined $ev.Count
    foreach ($p in $IOC.HistoryPatterns) {
        $hits = @($ev | Where-Object { $_.Message -match $p.Regex })
        if (-not $hits.Count) { continue }
        $shown = ($hits | Select-Object -First 5 | ForEach-Object { "  $(Format-When $_.Time) : " + (Limit-Text (($_.Message -split "`n" | Where-Object { $_ -match $p.Regex } | Select-Object -First 1)) 220) }) -join "`n"
        Add-Finding $p.Severity $p.Category "$($p.Label) — journal PowerShell" "$($hits.Count) bloc(s) de script journalisé(s) depuis $Days jours." $shown
    }
}

function Check-RunKeys {
    $cat = 'Démarrage automatique'
    $sub = @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'Software\Microsoft\Windows\CurrentVersion\RunOnceEx', 'Software\Microsoft\Windows\CurrentVersion\RunServices',
             'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
             'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; Who = 'tous les utilisateurs' })
    foreach ($u in $script:Users) { if ($u.RegRoot) { $roots += [pscustomobject]@{ Root = $u.RegRoot; Who = $u.Name } } else { Add-Note "Registre de $($u.Name) non analysé (session fermée ; utiliser -LoadUserHives)." } }
    foreach ($r in $roots) {
        foreach ($s in $sub) {
            $v = Get-RegValues "$($r.Root)\$s"
            if (-not $v) { continue }
            foreach ($n in $v.Keys) { if ($n) { Add-Autorun -Category $cat -Kind "Clé Run ($($r.Who))" -Name $n -Command "$($v[$n])" -Where "$($r.Root)\$s" } }
        }
        # Script d'ouverture de session et économiseur d'écran
        if ($r.Root -ne 'HKLM:') {
            $e = Get-RegValues "$($r.Root)\Environment"
            if ($e -and $e['UserInitMprLogonScript']) { Add-Finding Eleve $cat "Script d'ouverture de session pour $($r.Who)" 'Mécanisme de persistance rarement légitime.' "$($r.Root)\Environment\UserInitMprLogonScript = $($e['UserInitMprLogonScript'])" }
            $d = Get-RegValues "$($r.Root)\Control Panel\Desktop"
            if ($d -and $d['SCRNSAVE.EXE'] -and "$($d['SCRNSAVE.EXE'])" -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\[^\\]+\.scr$') { Add-Autorun -Category $cat -Kind "Économiseur d'écran ($($r.Who))" -Name 'SCRNSAVE.EXE' -Command "$($d['SCRNSAVE.EXE'])" -Where "$($r.Root)\Control Panel\Desktop" }
        }
    }
    # Active Setup : ne signaler que le suspect
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        foreach ($k in @(Get-RegSubKeys $base)) {
            $v = Get-RegValues "$base\$k"
            if ($v -and $v['StubPath']) { Add-Autorun -Category $cat -Kind 'Active Setup' -Name $k -Command "$($v['StubPath'])" -Where "$base\$k" -Quiet }
        }
    }
}

function Check-StartupFolders {
    $cat = 'Démarrage automatique'
    $dirs = @([pscustomobject]@{ Dir = "$PData\Microsoft\Windows\Start Menu\Programs\StartUp"; Who = 'tous les utilisateurs' })
    foreach ($u in $script:Users) { $dirs += [pscustomobject]@{ Dir = (Join-Path $u.Profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); Who = $u.Name } }
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d.Dir -File -Force)) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $cmd = $f.FullName
            if ($f.Extension -eq '.lnk') { $t = Resolve-Lnk $f.FullName; if ($t) { $cmd = $t } }
            if ($f.Extension -match '(?i)^\.(bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|pif)$') {
                Add-Examined
                $sev = if ("$($f.Name)" -match $IOC.ActivatorRegex) { 'Eleve' } else { 'Moyen' }
                Add-Finding $sev $cat "Script dans le dossier Démarrage ($($d.Who)) : $($f.Name)" 'Un script posé directement dans le dossier Démarrage est exécuté à chaque ouverture de session.' "Fichier : $($f.FullName)`nCréé    : $(Format-When $f.CreationTime)`nDébut   : $(Limit-Text ((Get-Content -LiteralPath $f.FullName -TotalCount 3) -join ' ⏎ ') 300)" 'Lire le script et identifier qui l''a déposé.'
            } else {
                Add-Autorun -Category $cat -Kind "Dossier Démarrage ($($d.Who))" -Name $f.Name -Command $cmd -Where $f.FullName
            }
        }
    }
}

function Check-Tasks {
    $cat = 'Tâches planifiées'
    foreach ($t in $script:Tasks) {
        $ms = ($t.Path -like '\Microsoft\*')
        if ((Test-NameList $t.Name $IOC.ActivatorTaskNames) -or ($IOC.ActivatorTaskFolders | Where-Object { $t.Path -like "$_*" })) { Add-Examined; continue }   # déjà signalé dans Activateurs
        foreach ($a in @($t.Actions)) {
            if ($a -like 'COM:*') { Add-Examined; continue }
            Add-Autorun -Category $cat -Kind 'Tâche' -Name "$($t.Path)$($t.Name)" -Command $a -Where "Compte : $($t.User) — créée : $($t.Date) — auteur : $($t.Author)" -Quiet:$ms
        }
    }
    if (-not $script:Tasks.Count) { Add-Note 'Aucune tâche lue (module ScheduledTasks indisponible ?).' }
    # Tâches masquées : présentes dans le registre mais privées de descripteur de sécurité ou invisibles de l'API
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $known = @{}
    foreach ($t in $script:Tasks) { $known[("$($t.Path)$($t.Name)").ToLower()] = $true }
    $stack = New-Object System.Collections.Stack
    $stack.Push('')
    $n = 0
    while ($stack.Count -and $n -lt 5000) {
        $rel = $stack.Pop(); $n++
        foreach ($k in @(Get-RegSubKeys "$tree$rel")) { $stack.Push("$rel\$k") }
        if (-not $rel) { continue }
        $v = Get-RegValues "$tree$rel"
        if (-not $v -or -not $v['Id']) { continue }                 # dossier, pas une tâche
        Add-Examined
        $act = ''
        $tv = Get-RegValues "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$($v['Id'])"
        if ($tv -and $tv['Actions']) { $act = ([Text.Encoding]::Unicode.GetString([byte[]]$tv['Actions']) -replace '[^\x20-\x7E]+', ' ').Trim() }
        $ev = "Clé     : $tree$rel`nId      : $($v['Id'])`nActions : $(Limit-Text $act 400)"
        $isAct = ("$rel $act" -match $IOC.ActivatorRegex) -or (Test-NameList (Split-Path $rel -Leaf) $IOC.ActivatorTaskNames)
        if (-not $v.ContainsKey('SD')) {
            Add-Finding Eleve $cat "Tâche masquée (descripteur de sécurité supprimé) : $rel" 'Supprimer la valeur SD rend une tâche invisible dans le Planificateur et pour schtasks, tout en la laissant active (technique « Tarrask »).' $ev 'Exporter la clé, analyser l''action, puis supprimer la tâche.'
        } elseif ($script:IsAdmin -and $script:Tasks.Count -and -not $known[$rel.ToLower()]) {
            $sev = if ($isAct) { 'Eleve' } else { 'Moyen' }
            $c2 = if ($isAct) { 'Activateurs et licences' } else { $cat }
            Add-Finding $sev $c2 "Tâche présente dans le registre mais invisible de l'API : $rel" 'Reste d''une tâche supprimée de façon incomplète, ou tâche volontairement dissimulée.' $ev 'Vérifier l''action enregistrée et la présence du fichier C:\Windows\System32\Tasks correspondant.'
        }
    }
}

function Check-Services {
    $cat = 'Services'
    foreach ($s in $script:Services) {
        if (Test-NameList $s.Name $IOC.ActivatorServices) { Add-Examined; continue }     # déjà signalé dans Activateurs
        $cmd = "$($s.PathName)"
        if ($cmd -match '(?i)\\svchost\.exe') {
            $p = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters"
            if ($p -and $p['ServiceDll']) { $cmd = '"' + [Environment]::ExpandEnvironmentVariables("$($p['ServiceDll'])") + '"' }
        }
        Add-Autorun -Category $cat -Kind 'Service' -Name "$($s.Name) ($($s.DisplayName))" -Command $cmd -Where "Démarrage : $($s.StartMode) — état : $($s.State) — compte : $($s.StartName)"
    }
}

function Check-Wmi {
    $cat = 'WMI'
    foreach ($w in @(Get-WmiSubscriptions)) {
        Add-Examined
        if ($w.Class -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
            $sev = if ($w.Name -eq 'BVTConsumer') { 'Info' } else { 'Eleve' }
            Add-Finding $sev $cat "Abonnement WMI exécutant du code : $($w.Name)" 'Les abonnements WMI permanents lancent une commande sur un événement système. Très rares en usage légitime, courants chez les attaquants.' "Type     : $($w.Class)`nCommande : $(Limit-Text $w.Detail 600)" 'Identifier le filtre associé, puis supprimer filtre, consommateur et liaison.'
        } elseif ($w.Class -eq '__EventFilter' -and $w.Name -notmatch '^(SCM Event Log Filter|BVTFilter)$') {
            Add-Finding Moyen $cat "Filtre d'événements WMI : $($w.Name)" 'Filtre permanent non standard.' "Requête : $($w.Detail)"
        }
    }
}

function Check-RegistryPersistence {
    $cat = 'Registre (persistance avancée)'
    $nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    # Winlogon
    $w = Get-RegValues "$nt\Winlogon"
    Add-Examined 3
    if ($w) {
        if ($w['Shell'] -and "$($w['Shell'])".Trim() -notmatch '^(?i)explorer\.exe$') { Add-Finding Eleve $cat 'Winlogon : interpréteur de session modifié' 'La valeur Shell doit être explorer.exe.' "$nt\Winlogon\Shell = $($w['Shell'])" }
        if ($w['Userinit'] -and "$($w['Userinit'])".Trim() -notmatch '^(?i)([A-Z]:\\Windows\\system32\\)?userinit\.exe,?$') { Add-Finding Eleve $cat 'Winlogon : Userinit modifié' 'La valeur doit être C:\Windows\system32\userinit.exe,' "$nt\Winlogon\Userinit = $($w['Userinit'])" }
        if ($w['Taskman']) { Add-Finding Moyen $cat 'Winlogon : valeur Taskman présente' 'Valeur absente par défaut.' "$nt\Winlogon\Taskman = $($w['Taskman'])" }
    }
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $uw = Get-RegValues "$($u.RegRoot)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if ($uw -and $uw['Shell']) { Add-Finding Eleve $cat "Winlogon : interpréteur de session défini pour $($u.Name)" 'Cette valeur n''existe pas par défaut au niveau utilisateur.' "Shell = $($uw['Shell'])" }
        foreach ($root in "$($u.RegRoot)\Software\Microsoft\Office test\Special\Perf") {
            $ot = Get-RegValues $root
            if ($ot -and $ot['']) { Add-Finding Eleve $cat "Clé « Office test » pour $($u.Name)" 'DLL chargée par toutes les applications Office au démarrage : technique de persistance connue.' "$root = $($ot[''])" }
        }
    }
    # AppInit / AppCert
    foreach ($k in "$nt\Windows", 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $v = Get-RegValues $k
        Add-Examined
        if ($v -and "$($v['AppInit_DLLs'])".Trim()) {
            $sev = if ("$($v['LoadAppInit_DLLs'])" -eq '1') { 'Eleve' } else { 'Moyen' }
            Add-Finding $sev $cat 'AppInit_DLLs renseigné' 'DLL injectées dans tous les processus graphiques.' "$k`nAppInit_DLLs = $($v['AppInit_DLLs'])`nLoadAppInit_DLLs = $($v['LoadAppInit_DLLs'])"
        }
    }
    $ac = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if ($ac -and $ac.Count) { Add-Finding Eleve $cat 'AppCertDlls renseigné' 'DLL injectées dans tout processus qui en crée un autre.' (($ac.Keys | ForEach-Object { "$_ = $($ac[$_])" }) -join "`n") }
    # Session Manager
    $sm = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if ($sm -and $sm['BootExecute']) {
        $bad = @($sm['BootExecute'] | Where-Object { $_ -and $_ -notmatch '^(?i)autocheck autochk ' })
        if ($bad.Count) { Add-Finding Eleve $cat 'BootExecute modifié' 'Programme lancé très tôt au démarrage, avant les protections.' ("BootExecute = " + ($sm['BootExecute'] -join ' | ')) }
    }
    # Image File Execution Options
    $access = 'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe'
    foreach ($base in "$nt\Image File Execution Options", 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($img in @(Get-RegSubKeys $base)) {
            Add-Examined
            if ($img -match '(?i)^(SppExtComObj|osppsvc|sppsvc)\.exe$') { continue }      # traité dans Activateurs
            $v = Get-RegValues "$base\$img"
            if ($v -and $v['Debugger']) {
                $sev = if ($access -contains $img.ToLower()) { 'Critique' } else { 'Eleve' }
                $why = if ($sev -eq 'Critique') { 'Porte dérobée classique : l''outil d''accessibilité de l''écran de connexion lance un autre programme avec les droits SYSTEM.' } else { 'Le programme indiqué est lancé à la place (ou autour) de l''exécutable visé.' }
                Add-Finding $sev $cat "Débogueur attaché à $img" $why "$base\$img\Debugger = $($v['Debugger'])"
            }
        }
    }
    foreach ($img in @(Get-RegSubKeys "$nt\SilentProcessExit")) {
        $v = Get-RegValues "$nt\SilentProcessExit\$img"
        if ($v -and $v['MonitorProcess']) { Add-Finding Eleve $cat "Programme lancé à la fermeture de $img" 'Persistance via SilentProcessExit.' "MonitorProcess = $($v['MonitorProcess'])" }
    }
    # Outils d'accessibilité remplacés
    $shells = @{}
    foreach ($n in 'cmd.exe', 'WindowsPowerShell\v1.0\powershell.exe', 'taskmgr.exe', 'mmc.exe', 'wscript.exe') { $h = Get-Sha256 (Join-Path $SysRoot "System32\$n"); if ($h) { $shells[$h] = $n } }
    $h = Get-Sha256 (Join-Path $SysRoot 'explorer.exe'); if ($h) { $shells[$h] = 'explorer.exe' }
    foreach ($a in $access) {
        $p = Join-Path $SysRoot "System32\$a"
        $s = Get-Sig $p
        Add-Examined
        $h = Get-Sha256 $p
        if ($h -and $shells[$h]) { Add-Finding Critique $cat "Outil d'accessibilité remplacé par $($shells[$h]) : $a" 'Porte dérobée classique : depuis l''écran de connexion, ce raccourci d''accessibilité ouvre un interpréteur avec les droits SYSTEM.' "Fichier : $p`nSHA-256 identique à $($shells[$h])" 'Restaurer le fichier d''origine (sfc /scannow) et rechercher l''intrusion.' }
        elseif ($s.Exists -and -not $s.Signed) { Add-Finding Critique $cat "Outil d'accessibilité non signé : $a" 'Fichier système remplacé : porte dérobée possible sur l''écran de connexion.' "Fichier : $p`nSignature : $($s.Status)" 'Restaurer le fichier d''origine (sfc /scannow) et rechercher l''intrusion.' }
    }
    # LSA
    $lsa = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($lsa) {
        $std = @{ 'Authentication Packages' = '^(msv1_0)$'; 'Notification Packages' = '^(scecli|rassfm)$'; 'Security Packages' = '^("")?$|^(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|livessp)$' }
        foreach ($n in $std.Keys) {
            $extra = @(@($lsa[$n]) | Where-Object { $_ -and "$_".Trim() -notmatch "(?i)$($std[$n])" })
            Add-Examined
            if ($extra.Count) { Add-Finding Moyen $cat "LSA : module supplémentaire dans « $n »" 'Module chargé dans le processus d''authentification (lsass). Légitime pour certains produits de sécurité ou de synchronisation de mots de passe, sinon suspect.' "$n = $(@($lsa[$n]) -join ', ')`nNon standard : $($extra -join ', ')" 'Identifier l''éditeur de la DLL correspondante dans System32.' }
        }
    }
    # Moniteurs d'impression et assistants netsh
    foreach ($m in @(Get-RegSubKeys 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors')) {
        $v = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\$m"
        if (-not $v -or -not $v['Driver']) { continue }
        Add-Examined
        $dll = "$($v['Driver'])"; if ($dll -notmatch '[\\/]') { $dll = Join-Path $SysRoot "System32\$dll" }
        $s = Get-Sig $dll
        if ($s.Exists -and -not $s.Signed) { Add-Finding Eleve $cat "Moniteur d'impression non signé : $m" 'DLL chargée par le spouleur avec les droits SYSTEM.' "Driver = $dll`nSignature : $($s.Status)" }
    }
    $ns = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\NetSh'
    if ($ns) {
        foreach ($n in $ns.Keys) {
            $dll = "$($ns[$n])"; if ($dll -notmatch '[\\/]') { $dll = Join-Path $SysRoot "System32\$dll" }
            $s = Get-Sig $dll
            Add-Examined
            if ($s.Exists -and -not $s.Microsoft) { Add-Finding Moyen $cat "Assistant netsh tiers : $n" 'DLL chargée à chaque exécution de netsh.' "DLL : $dll`nSignature : $($s.Status) $($s.Signer)" }
        }
    }
    # Détournement COM par utilisateur
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $base = "$($u.RegRoot)\Software\Classes\CLSID"
        foreach ($clsid in @(Get-RegSubKeys $base)) {
            $v = Get-RegValues "$base\$clsid\InprocServer32"
            if (-not $v -or -not $v['']) { continue }
            Add-Examined
            $dll = [Environment]::ExpandEnvironmentVariables(("$($v[''])" -replace '"', ''))
            $s = Get-Sig $dll
            if ($s.Exists -and -not $s.Signed) {
                $sev = if ($dll -match $WritableRegex) { 'Eleve' } else { 'Moyen' }
                Add-Finding $sev $cat "Composant COM utilisateur non signé ($($u.Name)) : $clsid" 'Une DLL enregistrée au niveau utilisateur prend le pas sur le composant système : technique de détournement COM.' "DLL : $dll`nSignature : $($s.Status)"
            }
        }
    }
}

function Check-Office {
    $cat = 'Office (macros et démarrage)'
    foreach ($u in $script:Users) {
        if ($u.RegRoot) {
            foreach ($ver in '16.0', '15.0', '14.0') {
                foreach ($app in 'Word', 'Excel', 'PowerPoint', 'Access', 'Outlook') {
                    $sec = "$($u.RegRoot)\Software\Microsoft\Office\$ver\$app\Security"
                    $v = Get-RegValues $sec
                    Add-Examined
                    if ($v) {
                        if ("$($v['VBAWarnings'])" -eq '1') { Add-Finding Moyen $cat "$app $ver : toutes les macros sont activées ($($u.Name))" 'Un document piégé s''exécute sans avertissement.' "$sec\VBAWarnings = 1" 'Remettre « Désactiver toutes les macros avec notification ».' }
                        if ("$($v['AccessVBOM'])" -eq '1') { Add-Finding Moyen $cat "$app $ver : accès au modèle objet VBA autorisé ($($u.Name))" 'Permet à une macro de modifier d''autres macros.' "$sec\AccessVBOM = 1" }
                    }
                    foreach ($loc in @(Get-RegSubKeys "$sec\Trusted Locations")) {
                        $tl = Get-RegValues "$sec\Trusted Locations\$loc"
                        if (-not $tl -or -not $tl['Path']) { continue }
                        $path = "$($tl['Path'])"
                        if ($path -match '(?i)^\\\\|^https?:|\\(Temp|Tmp|Downloads|Desktop)(\\|$)' -or $path -match '^(?i)[A-Z]:\\?$') {
                            Add-Finding Moyen $cat "$app $ver : emplacement approuvé risqué ($($u.Name))" 'Les fichiers ouverts depuis un emplacement approuvé exécutent leurs macros sans avertissement.' "Path = $path`nSous-dossiers autorisés : $($tl['AllowSubFolders'])"
                        }
                    }
                }
            }
        }
        # Dossiers de démarrage d'Office
        foreach ($d in 'AppData\Roaming\Microsoft\Word\STARTUP', 'AppData\Roaming\Microsoft\Excel\XLSTART', 'AppData\Roaming\Microsoft\AddIns') {
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $u.Profile $d) -File -Force)) {
                Add-Examined
                $sev = if ($f.CreationTime -ge $Since) { 'Moyen' } else { 'Info' }
                Add-Finding $sev $cat "Fichier chargé au démarrage d'Office ($($u.Name)) : $($f.Name)" 'Modèle ou complément ouvert automatiquement, macros comprises.' "Fichier : $($f.FullName)`nCréé    : $(Format-When $f.CreationTime)" 'Vérifier que ce complément est connu.'
            }
        }
    }
}

function Check-Accounts {
    $cat = 'Comptes'
    foreach ($a in @(Get-LocalUsersData)) {
        Add-Examined
        if ($a.Name -match '\$$') { Add-Finding Eleve $cat "Compte local masqué par un « $ » final : $($a.Name)" 'Convention utilisée pour cacher un compte dans les outils d''administration.' "SID : $($a.SID) — actif : $($a.Enabled)" }
        elseif ($a.Enabled -and $a.SID -match '-501$') { Add-Finding Moyen $cat "Compte Invité activé : $($a.Name)" 'Désactivé par défaut.' "SID : $($a.SID)" }
        elseif ($a.Enabled) { Add-Finding Info $cat "Compte local actif : $($a.Name)" '' "Dernière connexion : $($a.LastLogon) — mot de passe défini le : $($a.PasswordLastSet)" }
    }
    $adm = @(Get-LocalAdmins)
    if ($adm.Count) { Add-Finding Info $cat "Membres du groupe Administrateurs ($($adm.Count))" 'À relire : tout compte inattendu est un signal fort.' ($adm -join "`n") }
    $hidden = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if ($hidden) { foreach ($n in $hidden.Keys) { if ("$($hidden[$n])" -eq '0') { Add-Finding Eleve $cat "Compte masqué de l'écran de connexion : $n" 'Technique utilisée pour dissimuler un compte créé par un attaquant.' 'Winlogon\SpecialAccounts\UserList' } } }
}

function Check-RemoteAccess {
    $cat = 'Accès à distance'
    $ts = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Add-Examined
    if ($ts -and "$($ts['fDenyTSConnections'])" -eq '0') { Add-Finding Info $cat 'Bureau à distance (RDP) activé' 'Normal si voulu ; vérifier qu''il n''est pas exposé sur Internet.' 'fDenyTSConnections = 0' }
    $sshd = $script:Services | Where-Object { $_.Name -eq 'sshd' }
    if ($sshd) { Add-Finding Moyen $cat 'Serveur OpenSSH installé' 'Rare sur un poste de travail. Les portes dérobées récentes (extension Claude Code piégée) s''appuient dessus.' "État : $($sshd.State) / $($sshd.StartMode)" 'Désinstaller s''il n''est pas voulu.' }
    $keys = @("$PData\ssh\administrators_authorized_keys")
    foreach ($u in $script:Users) { $keys += (Join-Path $u.Profile '.ssh\authorized_keys') }
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        Add-Examined
        $i = Get-Item -LiteralPath $k -Force
        $lines = @(Get-Content -LiteralPath $k | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' })
        $sev = if ($i.LastWriteTime -ge $Since) { 'Eleve' } else { 'Moyen' }
        Add-Finding $sev $cat "Clés SSH autorisées : $k" "$($lines.Count) clé(s) permettent une connexion sans mot de passe$(if ($sev -eq 'Eleve') { ' ; fichier modifié récemment' })." ("Modifié : $(Format-When $i.LastWriteTime)`n" + (($lines | ForEach-Object { $p = $_ -split '\s+'; "  $($p[0]) …$("$($p[1])".PadLeft(12).Substring([math]::Max(0, "$($p[1])".Length - 12))) $($p[2])" }) -join "`n")) 'Vérifier que chaque clé est connue.'
    }
    $seen = @{}
    foreach ($s in $script:Services) { if ("$($s.Name) $($s.DisplayName) $($s.PathName)" -match $IOC.RemoteToolsRegex) { $seen[$Matches[0].ToLower()] = "service $($s.Name) ($($s.State))" } }
    foreach ($p in $script:Processes) { if ("$($p.Name) $($p.ExecutablePath)" -match $IOC.RemoteToolsRegex -and -not $seen[$Matches[0].ToLower()]) { $seen[$Matches[0].ToLower()] = "processus $($p.Name) (PID $($p.ProcessId))" } }
    foreach ($k in $seen.Keys) { Add-Finding Moyen $cat "Outil d'accès à distance présent : $k" 'Outil légitime, mais aussi le moyen de prise de contrôle le plus utilisé par les attaquants et les faux supports techniques.' $seen[$k] 'Confirmer qu''il a été installé volontairement.' }
    $pp = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
    if ($pp -and $pp.Count) { Add-Finding Moyen $cat 'Redirection de ports (netsh portproxy)' 'Relaie des connexions vers une autre machine. Utilisé par WSL et certains outils, mais aussi pour pivoter.' (($pp.Keys | ForEach-Object { "$_ -> $($pp[$_])" }) -join "`n") }
}

function Check-Defender {
    $cat = 'Antivirus (Defender)'
    $d = Get-DefenderData
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') {
        $v = Get-RegValues $k
        Add-Examined
        if ($v) { foreach ($n in 'DisableAntiSpyware', 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection') { if ("$($v[$n])" -eq '1') { Add-Finding Eleve $cat "Protection désactivée par stratégie : $n" 'Valeur souvent posée par un malware ou un outil de « débridage ».' "$k\$n = 1" } } }
    }
    if (-not $d) { Add-Note 'État de Microsoft Defender illisible (module absent ou autre antivirus).'; return }
    $other = @($d.OtherAV | Where-Object { $_ -and $_ -notmatch '(?i)defender' })
    if ($other.Count) { Add-Finding Info $cat "Antivirus tiers déclaré : $($other -join ', ')" 'Defender se met alors en mode passif : une protection en temps réel inactive est normale.' '' }
    Add-Examined 2
    if (-not $d.Status.RealTimeProtectionEnabled -and -not $other.Count) { Add-Finding Eleve $cat 'Protection en temps réel désactivée' 'Aucun autre antivirus n''est déclaré.' "AntivirusEnabled = $($d.Status.AntivirusEnabled) ; RealTimeProtectionEnabled = $($d.Status.RealTimeProtectionEnabled)" 'Réactiver la protection et chercher ce qui l''a coupée.' }
    if ($d.Status.PSObject.Properties['IsTamperProtected'] -and -not $d.Status.IsTamperProtected -and -not $other.Count) { Add-Finding Moyen $cat 'Protection contre les falsifications désactivée' 'Elle empêche un programme de couper l''antivirus.' '' }
    if ($d.Status.AntivirusSignatureLastUpdated -and $d.Status.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-14) -and -not $other.Count) { Add-Finding Moyen $cat 'Signatures antivirus anciennes' '' "Dernière mise à jour : $($d.Status.AntivirusSignatureLastUpdated)" }
    # Exclusions
    $broad = '(?i)^[A-Z]:\\?$|^[A-Z]:\\(Users|Windows|ProgramData)\\?$|\\AppData\\?$|\\Temp\\?$|\\Downloads\\?$|^\*|^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr)$|powershell|cmd\.exe|wscript|mshta|rundll32'
    foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
        foreach ($e in @($d.Prefs.$kind)) {
            if (-not $e) { continue }
            if ("$e" -match 'N/A:') { Add-Note 'Exclusions Defender illisibles sans droits administrateur.'; break }
            Add-Examined
            if ("$e" -match $IOC.ActivatorRegex) { Add-Finding Eleve 'Activateurs et licences' "Exclusion antivirus pour un activateur : $e" 'Les activateurs demandent d''exclure leurs fichiers de l''analyse.' "$kind = $e" }
            elseif ("$e" -match $broad) { Add-Finding Eleve $cat "Exclusion antivirus très large : $e" 'Tout ce qui se trouve ici échappe à l''antivirus.' "$kind = $e" 'Supprimer l''exclusion sauf justification documentée.' }
            else { Add-Finding Moyen $cat "Exclusion antivirus : $e" 'À justifier : les malwares s''ajoutent souvent eux-mêmes aux exclusions.' "$kind = $e" }
        }
    }
    # Historique des détections
    $names = @{}
    foreach ($t in $d.Threats) { $names["$($t.ThreatID)"] = "$($t.ThreatName)" }
    foreach ($x in $d.Detections) {
        Add-Examined
        $n = $names["$($x.ThreatID)"]; if (-not $n) { $n = "menace $($x.ThreatID)" }
        $isAct = ("$n $($x.Resources -join ' ')" -match $IOC.ActivatorThreatRegex) -or ("$($x.Resources -join ' ')" -match $IOC.ActivatorRegex)
        $c2 = if ($isAct) { 'Activateurs et licences' } else { $cat }
        $sev = if ($isAct -or $x.InitialDetectionTime -ge $Since) { 'Eleve' } else { 'Moyen' }
        Add-Finding $sev $c2 "Détection antivirus : $n" "Détectée le $(Format-When $x.InitialDetectionTime)$(if (-not $x.ActionSuccess) { ' ; action corrective NON aboutie' })." ("Processus : $($x.ProcessName)`n" + (@($x.Resources | Select-Object -First 6) -join "`n")) 'Vérifier que le fichier a bien été supprimé et comprendre comment il est arrivé.'
    }
}

function Check-Network {
    $cat = 'Réseau'
    $hosts = "$SysRoot\System32\drivers\etc\hosts"
    $entries = @(Get-Content -LiteralPath $hosts | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
    Add-Examined $entries.Count
    $lic = @(); $sec = @(); $other = @()
    foreach ($e in $entries) {
        $names = @(($e -split '\s+') | Select-Object -Skip 1)
        if ($names | Where-Object { $IOC.LicensingHosts -contains $_.ToLower() }) { $lic += $e }
        elseif ($e -match $IOC.SecurityHostsRegex) { $sec += $e }
        elseif ($e -notmatch '^(127\.0\.0\.1|::1)\s+localhost$') { $other += $e }
    }
    if ($lic.Count) { Add-Finding Eleve 'Activateurs et licences' "Domaines de licence Microsoft redirigés dans le fichier hosts ($($lic.Count))" 'Blocage volontaire des serveurs d''activation ou de vérification d''abonnement, typique des activateurs.' ($lic -join "`n") 'Retirer ces lignes.' }
    if ($sec.Count) { Add-Finding Eleve $cat "Domaines de sécurité ou de mise à jour redirigés dans le fichier hosts ($($sec.Count))" 'Empêche les mises à jour ou l''antivirus de joindre ses serveurs.' ($sec -join "`n") 'Retirer ces lignes et chercher ce qui les a ajoutées.' }
    if ($other.Count) { Add-Finding Info $cat "Autres entrées du fichier hosts ($($other.Count))" '' (($other | Select-Object -First 40) -join "`n") }
    # Pare-feu
    foreach ($p in 'DomainProfile', 'StandardProfile', 'PublicProfile') {
        $v = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p"
        Add-Examined
        if ($v -and "$($v['EnableFirewall'])" -eq '0') { Add-Finding Moyen $cat "Pare-feu Windows désactivé ($p)" 'Normal seulement si un pare-feu tiers le remplace.' "EnableFirewall = 0" }
    }
    # Proxy par utilisateur
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $v = Get-RegValues "$($u.RegRoot)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Add-Examined
        if (-not $v) { continue }
        $sev = if ($script:HostInfo.PartOfDomain) { 'Info' } else { 'Moyen' }
        if ($v['AutoConfigURL']) { Add-Finding $sev $cat "Script de configuration de proxy pour $($u.Name)" 'Tout le trafic web peut être dirigé vers un serveur tiers.' "AutoConfigURL = $($v['AutoConfigURL'])" 'Vérifier que cette adresse est celle de votre organisation.' }
        if ("$($v['ProxyEnable'])" -eq '1' -and $v['ProxyServer']) { Add-Finding $sev $cat "Proxy configuré pour $($u.Name)" '' "ProxyServer = $($v['ProxyServer'])" }
    }
    # Ports en écoute
    $byPid = @{}
    foreach ($p in $script:Processes) { $byPid["$($p.ProcessId)"] = $p }
    foreach ($g in @(Get-ListeningPorts | Group-Object OwningProcess)) {
        $p = $byPid["$($g.Name)"]
        if (-not $p -or -not $p.ExecutablePath) { continue }
        Add-Examined
        $s = Get-Sig $p.ExecutablePath
        if ($s.Microsoft) { continue }
        $ports = (@($g.Group | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) | Select-Object -Unique -First 12) -join ', '
        $sev = if (-not $s.Signed -and $p.ExecutablePath -match $WritableRegex) { 'Eleve' } elseif (-not $s.Signed) { 'Moyen' } else { 'Info' }
        Add-Finding $sev $cat "Programme en écoute sur le réseau : $($p.Name)" $(if ($sev -ne 'Info') { 'Programme non signé qui accepte des connexions entrantes.' } else { '' }) "Ports     : $ports`nBinaire   : $($p.ExecutablePath)`nSignature : $($s.Status) $($s.Signer)"
    }
}

function Check-Processes {
    $cat = 'Processus'
    foreach ($p in $script:Processes) {
        Add-Examined
        $path = "$($p.ExecutablePath)"; $cmd = "$($p.CommandLine)"
        if ($p.ProcessId -eq $PID) { continue }
        if ($path -and ($IOC.SystemProcessNames -contains "$($p.Name)".ToLower()) -and $path -notmatch '(?i)^[A-Z]:\\Windows\\(System32|SysWOW64|WinSxS)\\|^[A-Z]:\\Windows\\explorer\.exe$') {
            Add-Finding Critique $cat "Processus usurpant un nom système : $($p.Name)" 'Un processus portant le nom d''un composant Windows s''exécute depuis un emplacement anormal.' "PID $($p.ProcessId) — $path`n$(Limit-Text $cmd 400)" 'Isoler le poste et analyser le binaire.'
            continue
        }
        $reasons = @()
        foreach ($r in $StrongCmd) { if ($cmd -match $r.R) { $reasons += $r.L } }
        if ("$($p.Name) $cmd" -match $IOC.ActivatorRegex) { Add-Finding Eleve 'Activateurs et licences' "Processus d'activateur en cours : $($p.Name)" '' "PID $($p.ProcessId) — $(Limit-Text $cmd 400)"; continue }
        $s = if ($path) { Get-Sig $path } else { $null }
        if ($s -and $s.Exists -and -not $s.Signed -and $path -match $WritableRegex) { $reasons += "binaire non signé dans un dossier modifiable par l'utilisateur" }
        if ($reasons.Count) { Add-Finding Eleve $cat "Processus suspect : $($p.Name) (PID $($p.ProcessId))" ($reasons -join ' ; ') "Binaire  : $path`nCommande : $(Limit-Text $cmd 500)`nParent   : PID $($p.ParentProcessId)" 'Identifier le processus parent et l''origine du fichier.' }
    }
}

function Check-RecentFiles {
    $cat = 'Fichiers récents'
    $dirs = @("$SysRoot\Temp", "$SysRoot\Tasks", "$PData", "$PublicDir")
    foreach ($u in $script:Users) { $dirs += (Join-Path $u.Profile 'AppData\Local\Temp'); $dirs += (Join-Path $u.Profile 'AppData\Roaming') }
    $pe = New-Object System.Collections.Generic.List[object]; $scripts = New-Object System.Collections.Generic.List[object]
    foreach ($d in ($dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -File -Force | Where-Object { $_.CreationTime -ge $Since -and $_.Extension -match '(?i)^\.(exe|dll|scr|com|pif|cpl|sys|hta|js|jse|vbs|vbe|wsf|bat|cmd|ps1)$' })) {
            Add-Examined
            if ($f.Extension -match '(?i)^\.(exe|dll|scr|com|pif|cpl|sys)$') { $s = Get-Sig $f.FullName; if (-not $s.Signed) { $pe.Add($f) } } else { $scripts.Add($f) }
        }
    }
    foreach ($f in ($pe | Sort-Object CreationTime -Descending | Select-Object -First 40)) {
        Add-Finding Moyen $cat "Exécutable non signé récent : $($f.Name)" 'Déposé récemment dans un dossier où les malwares s''installent habituellement. Souvent un installeur légitime, à vérifier.' "Fichier : $($f.FullName)`nCréé    : $(Format-When $f.CreationTime)`nTaille  : $($f.Length) octets" 'En cas de doute, soumettre l''empreinte SHA-256 à VirusTotal.'
    }
    if ($pe.Count -gt 40) { Add-Note "$($pe.Count) exécutables non signés récents, 40 affichés." }
    if ($scripts.Count) { Add-Finding Info $cat "Scripts récents dans les dossiers temporaires et de données ($($scripts.Count))" '' (($scripts | Sort-Object CreationTime -Descending | Select-Object -First 40 | ForEach-Object { "$(Format-When $_.CreationTime)  $($_.FullName)" }) -join "`n") }
}

function Check-Events {
    $cat = 'Journaux d''événements'
    if (-not $script:IsAdmin) { Add-Note 'Journal Sécurité illisible sans droits administrateur.' }
    foreach ($e in @(Get-EventData 'Security' @(1102) $Since) + @(Get-EventData 'System' @(104) $Since)) {
        Add-Examined
        Add-Finding Eleve $cat "Journal d'événements effacé le $(Format-When $e.Time)" 'L''effacement des journaux sert à masquer des traces.' (Limit-Text $e.Message 300)
    }
    foreach ($e in @(Get-EventData 'System' @(7045) $Since 'Service Control Manager')) {
        Add-Autorun -Category $cat -Kind "Service installé le $(Format-When $e.Time)" -Name $e.Props[0] -Command $e.Props[1] -Where "Compte : $($e.Props[4]) — type : $($e.Props[2])" -Quiet
    }
    foreach ($e in @(Get-EventData 'Security' @(4698) $Since)) {
        Add-Examined
        $m = $e.Message
        $hit = $false; foreach ($r in $StrongCmd) { if ($m -match $r.R) { $hit = $true } }
        if ($m -match $IOC.ActivatorRegex) { Add-Finding Eleve 'Activateurs et licences' "Création d'une tâche d'activateur le $(Format-When $e.Time)" '' (Limit-Text $m 600) }
        elseif ($hit -or $m -match $WritableRegex) { Add-Finding Moyen $cat "Tâche planifiée créée le $(Format-When $e.Time) avec une action à vérifier" '' (Limit-Text $m 600) }
    }
    foreach ($e in @(Get-EventData 'Security' @(4720) $Since)) { Add-Examined; Add-Finding Moyen $cat "Compte local créé le $(Format-When $e.Time) : $($e.Props[0])" 'Vérifier que cette création est connue.' "Créé par : $($e.Props[4])" }
    foreach ($e in @(Get-EventData 'Security' @(4732) $Since)) { Add-Examined; if ($e.Props -contains 'S-1-5-32-544') { Add-Finding Moyen $cat "Compte ajouté au groupe Administrateurs le $(Format-When $e.Time)" '' "Membre : $($e.Props[1]) $($e.Props[0])" } }
    $fail = @(Get-EventData 'Security' @(4625) $Since)
    Add-Examined $fail.Count
    if ($fail.Count -ge 50) { Add-Finding Moyen $cat "$($fail.Count) échecs d'ouverture de session en $Days jours" 'Peut indiquer une recherche de mot de passe par force brute.' (($fail | Group-Object { $_.Props[5] } | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Count) × compte « $($_.Name) »" }) -join "`n") }
    foreach ($e in @(Get-EventData 'Microsoft-Windows-Windows Defender/Operational' @(5001, 5010, 5012) $Since)) { Add-Examined; Add-Finding Moyen 'Antivirus (Defender)' "Protection antivirus désactivée le $(Format-When $e.Time)" '' (Limit-Text $e.Message 300) }
    foreach ($e in @(Get-EventData 'Microsoft-Windows-Windows Defender/Operational' @(5007) $Since | Where-Object { $_.Message -match '(?i)\\Exclusions\\' } | Select-Object -First 15)) {
        Add-Examined; Add-Finding Moyen 'Antivirus (Defender)' "Exclusion antivirus modifiée le $(Format-When $e.Time)" '' (Limit-Text (($e.Message -split "`n" | Where-Object { $_ -match 'Exclusions' }) -join ' ') 400)
    }
}

function Check-Bits {
    $cat = 'BITS'
    foreach ($j in @(Get-BitsJobs)) {
        Add-Examined
        if ($j.NotifyCmd) { Add-Finding Eleve $cat "Tâche BITS avec commande de notification : $($j.Name)" 'BITS relance la commande à chaque fin de transfert : persistance discrète.' "Commande : $($j.NotifyCmd)`nAdresses : $($j.Urls -join ', ')" }
        elseif ($j.Urls.Count -and ($j.Urls -join ' ') -notmatch '(?i)microsoft\.com|windowsupdate\.com|googleapis\.com|gvt1\.com|edgedl\.me|adobe\.com|mozilla\.') { Add-Finding Info $cat "Transfert BITS : $($j.Name)" '' ($j.Urls -join "`n") }
    }
}

# =====================================================================================
#  Orchestration
# =====================================================================================
$AllChecks = [ordered]@{
    'Activateurs et licences'        = { Check-Activators }
    'Historique PowerShell'          = { Check-PSHistory }
    'Démarrage automatique'          = { Check-RunKeys; Check-StartupFolders }
    'Tâches planifiées'              = { Check-Tasks }
    'Services'                       = { Check-Services }
    'WMI'                            = { Check-Wmi }
    'Registre (persistance avancée)' = { Check-RegistryPersistence }
    'Office (macros et démarrage)'   = { Check-Office }
    'Comptes'                        = { Check-Accounts }
    'Accès à distance'               = { Check-RemoteAccess }
    'Antivirus (Defender)'           = { Check-Defender }
    'Réseau'                         = { Check-Network }
    'Processus'                      = { Check-Processes }
    'Fichiers récents'               = { Check-RecentFiles }
    'Journaux d''événements'         = { Check-Events }
    'BITS'                           = { Check-Bits }
}
if ($ListChecks) { $AllChecks.Keys; exit 0 }
if ($TestHooks) { . $TestHooks }

$script:IsAdmin  = [bool](Test-IsAdmin)
$script:HostInfo = Get-HostInfo
$started = Get-Date
Write-Host "WinTriage $($script:Version) — $($script:HostInfo.Computer) — $(Format-When $started)" -ForegroundColor White
if (-not $script:IsAdmin) { Write-Host '[ATTENTION] Exécuté sans droits administrateur : analyse limitée au profil courant, journal Sécurité et exclusions antivirus illisibles.' -ForegroundColor Yellow }

try {
    $script:Users     = @(Get-UserContexts)
    $script:Tasks     = @(Get-TasksData)
    $script:Services  = @(Get-ServicesData)
    $script:Processes = @(Get-ProcessesData)

    foreach ($name in $AllChecks.Keys) {
        if ($Only -and -not (Test-NameList $name $Only)) { continue }
        if ($Skip -and (Test-NameList $name $Skip)) { continue }
        $script:Cur = [pscustomobject]@{ Name = $name; Examined = 0; Results = 0; Notes = @(); Error = ''; Seconds = 0 }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { & $AllChecks[$name] } catch { $script:Cur.Error = "$($_.Exception.Message) (ligne $($_.InvocationInfo.ScriptLineNumber))" }
        $script:Cur.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        $script:Checks.Add($script:Cur)
        $mine = @($script:Findings | Where-Object { $_.Check -eq $name -and $_.Severity -ne 'Info' })
        $color = if ($script:Cur.Error) { 'Magenta' } elseif ($mine | Where-Object { $_.Severity -in 'Critique', 'Eleve' }) { 'Red' } elseif ($mine.Count) { 'Yellow' } else { 'Green' }
        Write-Host ("  {0,-34} {1,5} éléments   {2,3} à examiner   {3,5}s {4}" -f $name, $script:Cur.Examined, $mine.Count, $script:Cur.Seconds, $(if ($script:Cur.Error) { "ERREUR : $($script:Cur.Error)" })) -ForegroundColor $color
    }
} finally {
    $script:Cur = $null
    if ($script:LoadedHives.Count) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        foreach ($h in $script:LoadedHives) { $null = reg.exe unload "HKU\$h" 2>$null }
    }
}

# =====================================================================================
#  Rapport
# =====================================================================================
$sorted = @($script:Findings | Sort-Object @{ Expression = { $SevRank[$_.Severity] } }, Category, Title)
$count = @{}
foreach ($s in $SevRank.Keys) { $count[$s] = @($sorted | Where-Object { $_.Severity -eq $s }).Count }
$verdict = if ($count.Critique) { 'Signes de compromission : à traiter immédiatement' } elseif ($count.Eleve) { 'Éléments à traiter' } elseif ($count.Moyen) { 'Rien d''alarmant, des points à vérifier' } else { 'Aucun élément suspect relevé par ces contrôles' }

$null = New-Item -ItemType Directory -Path $OutputDir -Force
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$base = Join-Path $OutputDir ("WinTriage_{0}_{1}" -f $script:HostInfo.Computer, $stamp)
$meta = [ordered]@{
    Tool = "WinTriage $($script:Version)"; Started = $started.ToString('s'); DurationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds)
    Computer = $script:HostInfo.Computer; User = $script:HostInfo.User; Admin = $script:IsAdmin; OS = $script:HostInfo.OS
    Domain = $(if ($script:HostInfo.PartOfDomain) { $script:HostInfo.Domain } else { 'hors domaine' })
    Days = $Days; Profiles = @($script:Users | ForEach-Object { "$($_.Profile)$(if (-not $_.RegRoot) { ' (registre non chargé)' })" })
    Verdict = $verdict; Counts = $count
}
[ordered]@{ Meta = $meta; Checks = $script:Checks; Findings = $sorted } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$base.json" -Encoding UTF8

if (-not $NoHtml) {
    $H = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append(@"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinTriage — $(& $H $script:HostInfo.Computer)</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--mut:#5c6b7a;--line:#dde2e8;--crit:#b00020;--high:#c2410c;--med:#a16207;--info:#51627a;--ok:#15803d}
@media(prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b222b;--fg:#e6eaf0;--mut:#9aa8b8;--line:#2c3644;--crit:#ff6b81;--high:#fb923c;--med:#facc15;--info:#93a4ba;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0;overflow-wrap:anywhere}
.verdict{font-size:18px;font-weight:600;border-left:6px solid var(--ok)}.verdict.Critique{border-left-color:var(--crit)}.verdict.Eleve{border-left-color:var(--high)}.verdict.Moyen{border-left-color:var(--med)}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.tile{text-align:center;cursor:pointer;user-select:none}.tile b{display:block;font-size:28px}
.tile.off{opacity:.4}.Critique b,.sev.Critique{color:var(--crit)}.Eleve b,.sev.Eleve{color:var(--high)}.Moyen b,.sev.Moyen{color:var(--med)}.Info b,.sev.Info{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.f{border-left:5px solid var(--info)}.f.Critique{border-left-color:var(--crit)}.f.Eleve{border-left-color:var(--high)}.f.Moyen{border-left-color:var(--med)}.scroll{overflow-x:auto}
.f h3{font-size:15px;margin:0 0 4px;overflow-wrap:anywhere}.sev{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-right:8px}
.cat{font-size:12px;color:var(--mut)}pre{margin:8px 0 0;padding:10px;background:var(--bg);border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.45 Consolas,monospace}
.adv{margin-top:8px;font-size:14px}.adv b{color:var(--mut)}input[type=search]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit;margin:10px 0}
.hide{display:none}.err{color:var(--crit)}@media(max-width:600px){.tiles{grid-template-columns:repeat(2,1fr)}}
@media print{.tile,input{display:none}.hide{display:block}}
</style></head><body><main>
<h1>Rapport WinTriage</h1>
<div class="mut">$(& $H $meta.Computer) · $(& $H $meta.OS) · $(& $H $meta.Domain) · lancé le $($started.ToString('dd/MM/yyyy à HH:mm')) par $(& $H $meta.User) $(if ($script:IsAdmin) { '(administrateur)' } else { '<b class="err">(SANS droits administrateur : analyse partielle)</b>' })</div>
<div class="card verdict $(if ($count.Critique) { 'Critique' } elseif ($count.Eleve) { 'Eleve' } elseif ($count.Moyen) { 'Moyen' })">$(& $H $verdict)</div>
<div class="tiles">
"@)
    foreach ($s in 'Critique', 'Eleve', 'Moyen', 'Info') { $null = $sb.Append("<div class='card tile $s$(if ($s -eq 'Info') { ' off' })' data-sev='$s'><b>$($count[$s])</b>$($SevLabel[$s])</div>") }
    $null = $sb.Append("</div><div class='mut'>Cliquer sur une tuile pour afficher ou masquer un niveau. Les éléments « Info » (inventaire) sont masqués par défaut.</div>")
    $null = $sb.Append("<input type='search' id='q' placeholder='Filtrer : nom de fichier, catégorie, mot-clé…'>")
    $null = $sb.Append("<h2>Résultats</h2><div id='list'>")
    foreach ($f in $sorted) {
        $null = $sb.Append("<div class='card f $($f.Severity)$(if ($f.Severity -eq 'Info') { ' hide' })' data-sev='$($f.Severity)'><span class='sev $($f.Severity)'>$($SevLabel[$f.Severity])</span><span class='cat'>$(& $H $f.Category)</span><h3>$(& $H $f.Title)</h3>")
        if ($f.Detail)   { $null = $sb.Append("<div>$(& $H $f.Detail)</div>") }
        if ($f.Evidence) { $null = $sb.Append("<pre>$(& $H $f.Evidence)</pre>") }
        if ($f.Advice)   { $null = $sb.Append("<div class='adv'><b>Que faire :</b> $(& $H $f.Advice)</div>") }
        $null = $sb.Append('</div>')
    }
    if (-not $sorted.Count) { $null = $sb.Append("<div class='card'>Aucun résultat.</div>") }
    $null = $sb.Append("</div><h2>Contrôles effectués</h2><div class='card scroll'><table><tr><th>Contrôle</th><th class='n'>Éléments examinés</th><th class='n'>Résultats</th><th class='n'>Durée</th><th>Remarques</th></tr>")
    foreach ($c in $script:Checks) {
        $rem = @($c.Notes | Select-Object -Unique | ForEach-Object { & $H $_ })
        if ($c.Error) { $rem = @("<span class='err'>Contrôle interrompu : $(& $H $c.Error)</span>") + $rem }
        $null = $sb.Append("<tr><td>$(& $H $c.Name)</td><td class='n'>$($c.Examined)</td><td class='n'>$($c.Results)</td><td class='n'>$($c.Seconds) s</td><td>$($rem -join '<br>')</td></tr>")
    }
    $null = $sb.Append("</table></div><h2>Périmètre</h2><div class='card'><b>Profils analysés :</b><br>$(($meta.Profiles | ForEach-Object { & $H $_ }) -join '<br>')<br><br><b>Période :</b> $Days derniers jours pour les journaux et les fichiers récents.</div>")
    $null = $sb.Append(@"
<h2>Limites</h2><div class="card mut">Cet outil complète un antivirus, il ne le remplace pas. Il examine les emplacements de persistance les plus utilisés et des traces connues :
un rapport sans alerte ne prouve pas que la machine est saine (rootkits, implants en mémoire, techniques non couvertes).
Un élément « Moyen » demande une vérification, pas forcément une action. Les activations HWID et TSforge ne laissent presque aucune trace distinctive.
<br><br>WinTriage $($script:Version) — rapport généré en $($meta.DurationSeconds) s — aucune modification apportée au système.</div>
<script>
const off=new Set(['Info']),q=document.getElementById('q');
function apply(){const t=q.value.toLowerCase();document.querySelectorAll('#list .f').forEach(e=>{e.classList.toggle('hide',off.has(e.dataset.sev)||(t&&!e.textContent.toLowerCase().includes(t)))})}
document.querySelectorAll('.tile').forEach(e=>e.onclick=()=>{const s=e.dataset.sev;off.has(s)?off.delete(s):off.add(s);e.classList.toggle('off',off.has(s));apply()});q.oninput=apply;
</script></main></body></html>
"@)
    [IO.File]::WriteAllText("$base.html", $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

# =====================================================================================
#  Synthèse console
# =====================================================================================
Write-Host ''
Write-Host "== $verdict ==" -ForegroundColor $(if ($count.Critique -or $count.Eleve) { 'Red' } elseif ($count.Moyen) { 'Yellow' } else { 'Green' })
Write-Host ("Critique : {0}   Élevé : {1}   Moyen : {2}   Info : {3}" -f $count.Critique, $count.Eleve, $count.Moyen, $count.Info)
foreach ($f in @($sorted | Where-Object { $_.Severity -in 'Critique', 'Eleve' } | Select-Object -First 25)) {
    Write-Host ("  [{0}] {1} — {2}" -f $SevLabel[$f.Severity].ToUpper(), $f.Category, $f.Title) -ForegroundColor $(if ($f.Severity -eq 'Critique') { 'Magenta' } else { 'Red' })
}
$errs = @($script:Checks | Where-Object { $_.Error })
if ($errs.Count) { Write-Host "$($errs.Count) contrôle(s) interrompu(s) par une erreur : voir le rapport." -ForegroundColor Magenta }
Write-Host ''
if (-not $NoHtml) { Write-Host "Rapport HTML : $base.html" }
Write-Host "Données JSON : $base.json"

if ($PassThru) { $sorted }
if ($count.Critique -or $count.Eleve) { exit 2 } elseif ($count.Moyen) { exit 1 } else { exit 0 }
