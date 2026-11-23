<#
.SYNOPSIS
    Read-only audit of a Windows host: persistence, traces of Office/Windows activators,
    signs of compromise. Produces an HTML and a JSON report.

.DESCRIPTION
    A complement to an antivirus, not a replacement. The script changes nothing on the system
    (single exception: -LoadUserHives mounts and then unmounts the NTUSER.DAT hives of
    logged-off users). Works with Windows PowerShell 5.1 and PowerShell 7.

    Severities: Critical (probable compromise), High (act on it), Medium (verify), Info (inventory).
    Exit codes: 0 = nothing above Info, 1 = at least one Medium, 2 = at least one High or Critical.

    The HTML report carries both English and French text and can be switched inside the page.

.PARAMETER OutputDir
    Report folder (default: .\reports next to the script).
.PARAMETER Days
    Depth of event log and recent file analysis, in days (default: 30).
.PARAMETER Only
    Run only some checks (names shown by -ListChecks, wildcards accepted).
.PARAMETER Skip
    Exclude some checks.
.PARAMETER Language
    Language the HTML report opens in: en (default) or fr. Both languages are always embedded
    in the report; a switch in the page changes it at any time.
.PARAMETER Baseline
    JSON report of a previous run. Findings already present there are marked as known, so the
    report highlights what appeared since. Accepts a file or a folder (the newest JSON is used).
.PARAMETER NewOnly
    With -Baseline, list only the findings that are new. The exit code then follows what is listed.
.PARAMETER AllowlistFile
    Suppression rules (default: .\allowlist.psd1 next to the script, used when present). Matching
    findings are moved out of the results into a "suppressed" section that states who accepted them.
.PARAMETER NoAllowlist
    Ignore the suppression rules for this run.
.PARAMETER FixScript
    Also write a <report>.fix.ps1 containing the suggested remediation for each finding, entirely
    commented out. It is written to be read and edited, never run as is.
.PARAMETER LoadUserHives
    Temporarily load the registry of logged-off users so they are analysed too.
.PARAMETER PassThru
    Return the findings as objects (for pipeline processing).
.PARAMETER NoHtml
    Do not generate the HTML report (JSON only).
.PARAMETER ListChecks
    Print the list of checks and exit.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-WinTriage.ps1
.EXAMPLE
    .\Invoke-WinTriage.ps1 -Days 90 -LoadUserHives -Language fr -OutputDir \\server\share\triage
.EXAMPLE
    .\Invoke-WinTriage.ps1 -Baseline .\reports -NewOnly -FixScript
.EXAMPLE
    .\Invoke-WinTriage.ps1 -Only 'Activators','ScheduledTasks' -PassThru | Where-Object Severity -ne 'Info'
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [int]$Days = 30,
    [string[]]$Only,
    [string[]]$Skip,
    [ValidateSet('en', 'fr')][string]$Language = 'en',
    [string]$Baseline,
    [switch]$NewOnly,
    [string]$AllowlistFile,
    [switch]$NoAllowlist,
    [switch]$FixScript,
    [switch]$LoadUserHives,
    [switch]$PassThru,
    [switch]$NoHtml,
    [switch]$ListChecks,
    [string]$IndicatorsFile,
    # Reserved for the tests: script dot-sourced after the system access functions are defined (see tests\)
    [string]$TestHooks
)

$ErrorActionPreference = 'SilentlyContinue'
# Cmdlets coming from modules ignore $ErrorActionPreference under PowerShell 5.1
$PSDefaultParameterValues = @{ '*:ErrorAction' = 'SilentlyContinue' }
$script:Version = '1.2.0'
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir)      { $OutputDir = Join-Path $ScriptDir 'reports' }
if (-not $IndicatorsFile) { $IndicatorsFile = Join-Path $ScriptDir 'indicators.psd1' }
if (-not $AllowlistFile)  { $AllowlistFile = Join-Path $ScriptDir 'allowlist.psd1' }
if (-not (Test-Path -LiteralPath $IndicatorsFile)) { Write-Host "Indicator file not found: $IndicatorsFile" -ForegroundColor Red; exit 3 }
$IOC = Import-PowerShellDataFile -LiteralPath $IndicatorsFile
if (-not $IOC) { Write-Host "Indicator file unreadable: $IndicatorsFile" -ForegroundColor Red; exit 3 }
$Since = (Get-Date).AddDays(-$Days)
# System roots (variables rather than $env: so the tests can redirect them)
$SysRoot = $env:SystemRoot; $PF = $env:ProgramFiles; $PF86 = ${env:ProgramFiles(x86)}; $PData = $env:ProgramData
$PublicDir = $env:PUBLIC; $CommonPF = $env:CommonProgramFiles; $CommonPF86 = ${env:CommonProgramFiles(x86)}
function Expand-IocPath([string]$p) {
    $map = @{ '%SystemRoot%' = $SysRoot; '%ProgramFiles%' = $PF; '%ProgramFiles(x86)%' = $PF86; '%ProgramData%' = $PData; '%PUBLIC%' = $PublicDir }
    foreach ($k in $map.Keys) { if ($map[$k]) { $p = $p -ireplace [regex]::Escape($k), $map[$k].Replace('$', '$$') } }
    [Environment]::ExpandEnvironmentVariables($p)
}

# =====================================================================================
#  Bilingual text
#     Findings carry both languages so the HTML report can switch between them.
#     L <english> <french> builds such a pair; a plain string is used for both languages.
# =====================================================================================
function L([string]$En, [string]$Fr) { @{ en = $En; fr = $(if ($Fr) { $Fr } else { $En }) } }
function Loc($x) {
    if ($null -eq $x) { return @{ en = ''; fr = '' } }
    if ($x -is [hashtable]) { return @{ en = "$($x.en)"; fr = "$(if ($x.fr) { $x.fr } else { $x.en })" } }
    return @{ en = "$x"; fr = "$x" }
}
function Join-L([object[]]$Items, [string]$Sep = ' ; ') {
    $en = @(); $fr = @()
    foreach ($i in $Items) { $l = Loc $i; $en += $l.en; $fr += $l.fr }
    @{ en = ($en -join $Sep); fr = ($fr -join $Sep) }
}

# Labels of the left column in the evidence block
$EvLabel = @{
    file = @{ en = 'File'; fr = 'Fichier' };                path = @{ en = 'Path'; fr = 'Chemin' }
    type = @{ en = 'Type'; fr = 'Type' };                   size = @{ en = 'Size'; fr = 'Taille' }
    desc = @{ en = 'Description'; fr = 'Description' };     company = @{ en = 'Publisher'; fr = 'Éditeur' }
    sig = @{ en = 'Signature'; fr = 'Signature' };          modified = @{ en = 'Modified'; fr = 'Modifié' }
    created = @{ en = 'Created'; fr = 'Créé' };             key = @{ en = 'Key'; fr = 'Clé' }
    value = @{ en = 'Value'; fr = 'Valeur' };               values = @{ en = 'Values'; fr = 'Valeurs' }
    command = @{ en = 'Command'; fr = 'Commande' };         binary = @{ en = 'Binary'; fr = 'Binaire' }
    location = @{ en = 'Location'; fr = 'Emplacement' };    account = @{ en = 'Account'; fr = 'Compte' }
    state = @{ en = 'State'; fr = 'État' };                 startmode = @{ en = 'Startup'; fr = 'Démarrage' }
    actions = @{ en = 'Actions'; fr = 'Actions' };          id = @{ en = 'Id'; fr = 'Id' }
    product = @{ en = 'Product'; fr = 'Produit' };          channel = @{ en = 'Channel'; fr = 'Canal' }
    status = @{ en = 'Status'; fr = 'État' };               pkey = @{ en = 'Product key'; fr = 'Clé de produit' }
    remaining = @{ en = 'Time left'; fr = 'Validité restante' }
    kms = @{ en = 'KMS server'; fr = 'Serveur KMS' };       server = @{ en = 'Server'; fr = 'Serveur' }
    port = @{ en = 'Port'; fr = 'Port' };                   process = @{ en = 'Process'; fr = 'Processus' }
    pid = @{ en = 'PID'; fr = 'PID' };                      parent = @{ en = 'Parent'; fr = 'Parent' }
    ports = @{ en = 'Ports'; fr = 'Ports' };                dll = @{ en = 'DLL'; fr = 'DLL' }
    driver = @{ en = 'Driver'; fr = 'Pilote' };             query = @{ en = 'Query'; fr = 'Requête' }
    detected = @{ en = 'Detected'; fr = 'Détecté le' };     sid = @{ en = 'SID'; fr = 'SID' }
    enabled = @{ en = 'Enabled'; fr = 'Actif' };            lastlogon = @{ en = 'Last logon'; fr = 'Dernière connexion' }
    pwdset = @{ en = 'Password set'; fr = 'Mot de passe défini le' }
    urls = @{ en = 'URLs'; fr = 'Adresses' };               notify = @{ en = 'Notify command'; fr = 'Commande de notification' }
    author = @{ en = 'Author'; fr = 'Auteur' };             target = @{ en = 'Target'; fr = 'Cible' }
    sha256 = @{ en = 'SHA-256'; fr = 'SHA-256' };           head = @{ en = 'First lines'; fr = 'Début' }
    subfolders = @{ en = 'Subfolders allowed'; fr = 'Sous-dossiers autorisés' }
    nonstd = @{ en = 'Non-standard'; fr = 'Non standard' }; createdby = @{ en = 'Created by'; fr = 'Créé par' }
    member = @{ en = 'Member'; fr = 'Membre' };             time = @{ en = 'Time'; fr = 'Heure' }
    task = @{ en = 'Task'; fr = 'Tâche' };                  service = @{ en = 'Service'; fr = 'Service' }
}
# Builds an evidence block: pass @('key', 'value') pairs and/or raw text lines.
# Values and raw lines may themselves be bilingual pairs built with L.
function Ev {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Items)
    $rows = @()
    foreach ($i in $Items) {
        if ($null -eq $i) { continue }
        if ($i -is [hashtable]) {
            $t = Loc $i
            if ("$($t.en)$($t.fr)".Trim()) { $rows += [pscustomobject]@{ En = ''; Fr = ''; VEn = $t.en; VFr = $t.fr } }
            continue
        }
        if ($i -is [array]) {
            $v = Loc $i[1]
            if (-not "$($v.en)$($v.fr)".Trim()) { continue }
            $lab = $EvLabel["$($i[0])"]
            if (-not $lab) { $lab = @{ en = "$($i[0])"; fr = "$($i[0])" } }
            $rows += [pscustomobject]@{ En = $lab.en; Fr = $lab.fr; VEn = $v.en; VFr = $v.fr }
            continue
        }
        $t = "$i"
        if ($t.Trim()) { $rows += [pscustomobject]@{ En = ''; Fr = ''; VEn = $t; VFr = $t } }
    }
    $we = 0; $wf = 0
    foreach ($r in $rows) { if ($r.En.Length -gt $we) { $we = $r.En.Length }; if ($r.Fr.Length -gt $wf) { $wf = $r.Fr.Length } }
    $en = @(); $fr = @()
    foreach ($r in $rows) {
        if ($r.En) { $en += ('{0} : {1}' -f $r.En.PadRight($we), $r.VEn); $fr += ('{0} : {1}' -f $r.Fr.PadRight($wf), $r.VFr) }
        else { $en += $r.VEn; $fr += $r.VFr }
    }
    @{ en = ($en -join "`n"); fr = ($fr -join "`n") }
}

# Check and category names. These keys are what -Only, -Skip and -ListChecks use.
$CatLabel = [ordered]@{
    Activators        = @{ en = 'Activators and licensing'; fr = 'Activateurs et licences' }
    PowerShellHistory = @{ en = 'PowerShell history'; fr = 'Historique PowerShell' }
    Autostart         = @{ en = 'Autostart'; fr = 'Démarrage automatique' }
    ScheduledTasks    = @{ en = 'Scheduled tasks'; fr = 'Tâches planifiées' }
    Services          = @{ en = 'Services'; fr = 'Services' }
    WMI               = @{ en = 'WMI'; fr = 'WMI' }
    Registry          = @{ en = 'Registry (advanced persistence)'; fr = 'Registre (persistance avancée)' }
    Office            = @{ en = 'Office (macros and startup)'; fr = 'Office (macros et démarrage)' }
    Accounts          = @{ en = 'Accounts'; fr = 'Comptes' }
    Credentials       = @{ en = 'Credential theft traces'; fr = "Traces de vol d'identifiants" }
    Hardening         = @{ en = 'Security settings'; fr = 'Paramètres de sécurité' }
    RemoteAccess      = @{ en = 'Remote access'; fr = 'Accès à distance' }
    Defender          = @{ en = 'Antivirus (Defender)'; fr = 'Antivirus (Defender)' }
    Network           = @{ en = 'Network'; fr = 'Réseau' }
    Drivers           = @{ en = 'Kernel drivers'; fr = 'Pilotes noyau' }
    Browsers          = @{ en = 'Browser extensions'; fr = 'Extensions de navigateur' }
    Processes         = @{ en = 'Processes'; fr = 'Processus' }
    RecentFiles       = @{ en = 'Recent files'; fr = 'Fichiers récents' }
    EventLogs         = @{ en = 'Event logs'; fr = "Journaux d'événements" }
    BITS              = @{ en = 'BITS'; fr = 'BITS' }
}

# =====================================================================================
#  Findings
# =====================================================================================
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Checks   = New-Object System.Collections.Generic.List[object]
$script:Cur      = $null
$SevRank  = @{ Critical = 0; High = 1; Medium = 2; Info = 3 }
$SevLabel = @{ Critical = @{ en = 'Critical'; fr = 'Critique' }; High = @{ en = 'High'; fr = 'Élevé' }
               Medium   = @{ en = 'Medium'; fr = 'Moyen' };      Info = @{ en = 'Info'; fr = 'Info' } }

# Stable identity of a finding, so a baseline, a suppression rule and the triage state in the
# report all point at the same thing across runs. Derived from what the finding says, not when.
function Get-FindingKey([string]$Category, [string]$TitleEn, [string]$EvidenceEn) {
    $t = "$Category|$TitleEn|$EvidenceEn"
    # Volatile parts must not change the key: timestamps in any of the shapes we may print,
    # process ids, sizes and counters.
    $t = $t -replace '\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?', '<date>'
    $t = $t -replace '\d{1,2}/\d{1,2}/\d{2,4}([ ,]+\d{1,2}:\d{2}(:\d{2})?( ?[AaPp]\.?[Mm]\.?)?)?', '<date>'
    $t = $t -replace '\d{1,2}:\d{2}(:\d{2})?', '<time>' -replace '\bPID \d+', 'PID <n>' -replace '\b\d{3,}\b', '<n>'
    $md5 = [Security.Cryptography.MD5]::Create()
    try { ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($t)) | ForEach-Object { $_.ToString('x2') }) -join '' | ForEach-Object { $_.Substring(0, 12) } }
    finally { $md5.Dispose() }
}

function Add-Finding {
    param([ValidateSet('Critical', 'High', 'Medium', 'Info')][string]$Severity, [string]$Category,
          $Title, $Detail, $Evidence, $Advice, [string]$Fix)
    if (-not $Category -and $script:Cur) { $Category = $script:Cur.Name }
    $t = Loc $Title; $d = Loc $Detail; $e = Loc $Evidence; $a = Loc $Advice
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category
        Title = $t; Detail = $d; Evidence = $e; Advice = $a
        Key = (Get-FindingKey $Category $t.en $e.en); Fix = $Fix; New = $true; Suppressed = $null
        Check = $(if ($script:Cur) { $script:Cur.Name } else { '' })
    })
    if ($script:Cur) { $script:Cur.Results++ }
}
function Add-Examined([int]$n = 1) { if ($script:Cur) { $script:Cur.Examined += $n } }
function Add-Note($t) { if ($script:Cur) { $script:Cur.Notes += (Loc $t) } }
# One dated event for the report's timeline. Only call it with a date that comes from the system.
$script:Timeline = New-Object System.Collections.Generic.List[object]
function Add-Timeline($When, $What, [string]$Severity = 'Info') {
    if (-not ($When -is [datetime])) { try { $When = [datetime]$When } catch { return } }
    if ($When -le [datetime]'2000-01-01' -or $When -gt (Get-Date).AddDays(1)) { return }
    $script:Timeline.Add([pscustomobject]@{
        When = $When; Category = $(if ($script:Cur) { $script:Cur.Name } else { '' })
        What = (Loc $What); Severity = $Severity
    })
}
function Format-When($d) { if ($d -is [datetime]) { $d.ToString('yyyy-MM-dd HH:mm') } else { "$d" } }
function Limit-Text([string]$s, [int]$max = 300) { if ($s -and $s.Length -gt $max) { $s.Substring(0, $max) + [char]0x2026 } else { $s } }

# =====================================================================================
#  System access (functions replaceable through -TestHooks)
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
function Get-DriversData {
    @(Get-CimInstance -ClassName Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, StartMode)
}
# Boot options that switch off driver signing or kernel integrity. bcdedit needs administrator rights.
function Get-BootConfig {
    $h = @{}
    foreach ($l in @(bcdedit.exe /enum '{current}' 2>$null)) {
        if ($l -match '^\s*(testsigning|nointegritychecks|integrityservices|safeboot|recoveryenabled|hypervisorlaunchtype|debug)\s+(\S+)') { $h[$Matches[1].ToLower()] = $Matches[2] }
    }
    return $h
}
# Browser extension folders of one user profile, with what their manifest declares.
function Get-BrowserExtensions([string]$ProfileDir) {
    $out = @()
    $vendors = @(
        @{ Name = 'Chrome';   Dir = 'AppData\Local\Google\Chrome\User Data' }
        @{ Name = 'Edge';     Dir = 'AppData\Local\Microsoft\Edge\User Data' }
        @{ Name = 'Brave';    Dir = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
        @{ Name = 'Vivaldi';  Dir = 'AppData\Local\Vivaldi\User Data' }
        @{ Name = 'Opera';    Dir = 'AppData\Roaming\Opera Software\Opera Stable' }
    )
    foreach ($v in $vendors) {
        $root = Join-Path $ProfileDir $v.Dir
        if (-not (Test-Path -LiteralPath $root)) { continue }
        # Browser profiles sit under User Data (Default, Profile 1, ...); Opera keeps them at the root.
        $extRoots = @()
        foreach ($p in @(, (Get-Item -LiteralPath $root -Force)) + @(Get-ChildItem -LiteralPath $root -Directory -Force)) {
            if ($p) { $extRoots += (Join-Path $p.FullName 'Extensions') }
        }
        $manifests = @()
        foreach ($er in ($extRoots | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $er)) { continue }
            foreach ($id in @(Get-ChildItem -LiteralPath $er -Directory -Force | Where-Object { $_.Name -match '^[a-p]{32}$' })) {
                foreach ($ver in @(Get-ChildItem -LiteralPath $id.FullName -Directory -Force)) {
                    $mf = Join-Path $ver.FullName 'manifest.json'
                    if (Test-Path -LiteralPath $mf -PathType Leaf) { $manifests += (Get-Item -LiteralPath $mf -Force) }
                }
            }
        }
        foreach ($ext in $manifests) {
            $m = $null
            try { $m = Get-Content -LiteralPath $ext.FullName -Raw | ConvertFrom-Json } catch { }
            if (-not $m) { continue }
            $id = (Split-Path (Split-Path $ext.FullName -Parent) -Parent | Split-Path -Leaf)
            $dir = Split-Path $ext.FullName -Parent
            $name = "$($m.name)"
            # Localized name: resolve it from the extension's own message catalogue
            if ($name -match '^__MSG_(\w+)__$') {
                $key = $Matches[1]
                foreach ($loc in 'en', 'en_US', "$($m.default_locale)") {
                    if (-not $loc) { continue }
                    $msg = Join-Path $dir "_locales\$loc\messages.json"
                    if (-not (Test-Path -LiteralPath $msg)) { continue }
                    try { $j = Get-Content -LiteralPath $msg -Raw | ConvertFrom-Json; if ($j.$key.message) { $name = "$($j.$key.message)"; break } } catch { }
                }
            }
            $perms = @(@($m.permissions) + @($m.optional_permissions) + @($m.host_permissions) | Where-Object { $_ -is [string] })
            $out += [pscustomobject]@{
                Browser = $v.Name; Id = $id; Name = $name; Version = "$($m.version)"
                Permissions = $perms; Installed = $ext.LastWriteTime; Path = $dir
            }
        }
    }
    return $out
}
function Get-LocalAdmins {
    $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.Name)" })
    if ($m.Count) { return $m }
    # Fallback: Get-LocalGroupMember fails when the group holds an orphaned SID
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
function Get-RootCertificates {
    @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\Root' | ForEach-Object {
        [pscustomobject]@{ Subject = "$($_.Subject)"; Issuer = "$($_.Issuer)"; NotBefore = $_.NotBefore
                           NotAfter = $_.NotAfter; Thumbprint = "$($_.Thumbprint)" }
    })
}
# Windows Firewall rules as stored in the registry: readable without administrator rights,
# unlike Get-NetFirewallRule on some builds, and parseable the same way everywhere.
function Get-FirewallRules {
    $out = @()
    foreach ($base in 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
                      'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules') {
        $v = Get-RegValues $base
        if (-not $v) { continue }
        foreach ($n in $v.Keys) {
            $raw = "$($v[$n])"
            if (-not $raw) { continue }
            $f = @{}
            foreach ($part in ($raw -split '\|')) { if ($part -match '^([A-Za-z0-9_]+)=(.*)$') { $f[$Matches[1]] = $Matches[2] } }
            $out += [pscustomobject]@{
                Id = $n; Source = $base; Name = "$($f['Name'])"; Action = "$($f['Action'])"; Dir = "$($f['Dir'])"
                Active = "$($f['Active'])"; App = "$($f['App'])"; Svc = "$($f['Svc'])"; LPort = "$($f['LPort'])"
                RA4 = "$($f['RA4'])"; Profile = "$($f['Profile'])"; Raw = $raw
            }
        }
    }
    return $out
}
# Static DNS servers, DNS-over-HTTPS templates and NRPT policy rules, per interface
function Get-DnsConfig {
    $out = @()
    $ifBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    foreach ($guid in @(Get-RegSubKeys $ifBase)) {
        $v = Get-RegValues "$ifBase\$guid"
        if (-not $v) { continue }
        $ns = "$($v['NameServer'])".Trim()
        if ($ns) { $out += [pscustomobject]@{ Kind = 'static'; Interface = $guid; Value = $ns } }
    }
    $doh = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
    foreach ($guid in @(Get-RegSubKeys $doh)) {
        foreach ($ip in @(Get-RegSubKeys "$doh\$guid\DohInterfaceSettings\Doh")) {
            $v = Get-RegValues "$doh\$guid\DohInterfaceSettings\Doh\$ip"
            if ($v -and $v['DohTemplate']) { $out += [pscustomobject]@{ Kind = 'doh'; Interface = $guid; Value = "$ip $($v['DohTemplate'])" } }
        }
    }
    $nrpt = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig'
    foreach ($rule in @(Get-RegSubKeys $nrpt)) {
        $v = Get-RegValues "$nrpt\$rule"
        if (-not $v) { continue }
        $srv = @($v['GenericDNSServers']) -join ', '
        $out += [pscustomobject]@{ Kind = 'nrpt'; Interface = $rule; Value = "$(@($v['Name']) -join ', ') -> $srv" }
    }
    return $out
}
function Get-Sha256([string]$Path) { try { if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } } catch { $null } }
# First bytes of a file, to recognise a format without trusting its extension
function Get-FileMagic([string]$Path, [int]$n = 4) {
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try { $b = New-Object byte[] $n; $null = $fs.Read($b, 0, $n); return ([Text.Encoding]::ASCII.GetString($b)) } finally { $fs.Dispose() }
    } catch { return '' }
}
$script:SigCache = @{}
function Get-Sig([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Exists = $false; Signed = $false; Microsoft = $false; MsClaim = $false; Signer = ''; Status = (L 'Unknown' 'Inconnu') } }
    $key = $Path.ToLower()
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }
    # MsClaim: the file states Microsoft as its publisher. Metadata is trivial to forge, so it is only
    # used to soften findings on system files whose catalogue entry is missing, never to clear a file.
    $r = [pscustomobject]@{ Exists = $false; Signed = $false; Microsoft = $false; MsClaim = $false; Signer = ''; Status = (L 'File not found' 'Fichier introuvable') }
    if ($Path -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\.+\.exe$') {
        # Store app execution alias: a reparse point with no content, not verifiable
        $r.Exists = $true; $r.Signed = $true; $r.Status = (L 'Microsoft Store app alias' "Alias d'application du Microsoft Store")
    }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        $r.Exists = $true; $r.Status = (L 'Unsigned' 'Non signé')
        try { $r.MsClaim = ((Get-Item -LiteralPath $Path -Force).VersionInfo.CompanyName -match 'Microsoft Corporation') } catch { }
        $s = $null
        try { $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } catch { }
        # A script with no signature block reports UnknownError: treat it as plainly unsigned
        if ($s -and "$($s.Status)" -eq 'UnknownError' -and $Path -match '(?i)\.(bat|cmd|vbs|js|ps1|txt|ini)$') { $s = [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
        if (-not $s) { $r.Signed = $true; $r.Status = (L 'Signature unreadable (file locked or access denied)' 'Signature illisible (fichier verrouillé ou accès refusé)') }   # in doubt: no alert
        else {
            if ("$($s.Status)" -eq 'Valid') { $r.Signed = $true; $r.Status = (L 'Signed' 'Signé') }
            elseif ("$($s.Status)" -ne 'NotSigned') { $r.Status = (L "Invalid signature ($($s.Status))" "Signature invalide ($($s.Status))") }
            if ($s.SignerCertificate) {
                $r.Signer = ($s.SignerCertificate.Subject -replace '^CN="?([^,"]+).*$', '$1')
                if ($r.Signed -and $s.SignerCertificate.Subject -match 'O=Microsoft Corporation') { $r.Microsoft = $true }
            }
        }
    }
    $script:SigCache[$key] = $r
    return $r
}
# "Signed - Contoso Ltd" as a bilingual pair, for the Signature line of the evidence block
function Format-Signer($Sig) {
    $st = Loc $Sig.Status
    if ($Sig.Signer) { return (L "$($st.en) $([char]0x2014) $($Sig.Signer)" "$($st.fr) $([char]0x2014) $($Sig.Signer)") }
    return $st
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
#  Analysis of an autostart command
# =====================================================================================
$WritableRegex = '(?i)\\(AppData|Temp|Tmp|Downloads|Desktop|Documents|Public|ProgramData|\$Recycle\.Bin|PerfLogs)\\|^[A-Z]:\\Users\\[^\\]+\\[^\\]+$|\\Windows\\(Temp|Tasks|debug|Tracing)\\'
# Narrower than $WritableRegex: the folders things get dropped into, not every per-user install
# folder. Used where "writable" alone would flag ordinary software (shortcuts, firewall rules).
$DropZoneRegex = '(?i)\\(Temp|Tmp|Downloads|Public|ProgramData|\$Recycle\.Bin|PerfLogs)\\|\\Windows\\(Temp|Tasks|debug|Tracing)\\|^[A-Z]:\\Users\\[^\\]+\\[^\\]+$'
# Interpreters and signed Microsoft binaries that run what they are given: a shortcut or a
# recovery command pointing at one of these is worth a look whatever its signature says.
$LolBinRegex = '(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msbuild|installutil|regasm|regsvcs|cmstp|forfiles|pcalua|conhost|wmic|bitsadmin|certutil|curl|msiexec)\.exe\b'
$StrongCmd = @(
    @{ L = (L 'encoded PowerShell command' 'commande PowerShell encodée');     R = '(?i)(powershell|pwsh).*\s-(e|ec|enc|enco[a-z]*)\s+[A-Za-z0-9+/=]{20,}' }
    @{ L = (L 'download from the internet' 'téléchargement depuis Internet'); R = '(?i)downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|\b(iwr|irm|curl|wget)(\.exe)?\s.*https?://|bitsadmin.+/transfer|certutil.+-urlcache|start-bitstransfer' }
    @{ L = (L 'in-memory code execution' 'exécution de code en mémoire');     R = '(?i)\biex\b|invoke-expression|frombase64string|reflection\.assembly|\]::load\(' }
    @{ L = (L 'remote scriptlet or script' 'scriptlet ou script distant');     R = '(?i)regsvr32.+(/i:|scrobj)|mshta.+(https?:|javascript:|vbscript:)|rundll32.+(javascript:|vbscript:)' }
)
$MediumCmd = @(
    @{ L = (L 'hidden window' 'fenêtre masquée');                                           R = '(?i)\s-w(in|indowstyle)?\s+h(id|idden)?\b' }
    @{ L = (L 'web address in the command' 'adresse web dans la commande');                 R = '(?i)https?://' }
    @{ L = (L 'script launched by an interpreter' 'script lancé par un interpréteur');       R = '(?i)\b(wscript|cscript|mshta)(\.exe)?\b.+\.(js|jse|vbs|vbe|wsf|hta)\b|\bpowershell(\.exe)?\b.+-(f|file)\s|\bcmd(\.exe)?\s+/c\b' }
    @{ L = (L 'DLL loaded from a user-writable folder' 'DLL chargée depuis un dossier modifiable'); R = '(?i)rundll32(\.exe)?\s+"?[A-Z]:\\(Users|ProgramData|Windows\\Temp)\\' }
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
    # Unquoted path followed by arguments, for a file that no longer exists
    if ($c -match '^(?i)([A-Z]:\\.+?\.(exe|com|bat|cmd|ps1|vbs|js|dll|scr))(\s|$)') { return $Matches[1] }
    $first = $parts[0]
    if ($first -and $first -notmatch '[\\/]') {
        $g = Get-Command -Name $first -CommandType Application | Select-Object -First 1
        if ($g) { return $g.Source }
    }
    return $first
}
# Classifies an autostart entry. -Quiet: emit nothing below Medium (noisy areas).
function Add-Autorun {
    param([string]$Category, $Kind, [string]$Name, [string]$Command, $Where, [switch]$Quiet, $Advice)
    Add-Examined
    if (-not $Command) { return }
    $exe = Resolve-ExePath $Command
    $sig = Get-Sig $exe
    $reasons = @(); $sev = 'Info'
    foreach ($p in $StrongCmd) { if ($Command -match $p.R) { $reasons += $p.L; $sev = 'High' } }
    if ("$Name $Command" -match $IOC.ActivatorRegex) {
        $reasons += (L 'known activator name or command' "nom ou commande d'activateur connu"); $sev = 'High'; $Category = 'Activators'
    }
    $writable = ($exe -match $WritableRegex)
    $what = if ($exe -match '(?i)\.(cmd|bat|ps1|vbs|vbe|js|jse|wsf|hta)$') { (L 'script' 'script') } else { (L 'unsigned binary' 'binaire non signé') }
    if ($sig.Exists -and -not $sig.Signed -and $writable) {
        $reasons += (L "$($what.en) in a user-writable folder" "$($what.fr) dans un dossier modifiable par l'utilisateur"); $sev = 'High'
    }
    if ($sev -eq 'Info') {
        if (-not $Quiet) { foreach ($p in $MediumCmd) { if ($Command -match $p.R) { $reasons += $p.L; $sev = 'Medium' } } }
        if ($sig.Exists -and -not $sig.Signed) { $reasons += $what; $sev = 'Medium' }
    }
    if ($sev -eq 'Info') {
        if ($sig.Microsoft) { return }                       # Microsoft-signed, nothing suspicious: counted, not listed
        if ($Quiet) { return }
        if (-not $sig.Exists) { $reasons += (L 'binary not resolved (orphaned entry or complex command)' 'binaire non résolu (entrée orpheline ou commande complexe)') }
    }
    $kind = Loc $Kind
    $detail = if ($reasons.Count) { Join-L $reasons } else { (L 'third-party entry, nothing suspicious' 'entrée tierce, sans signe suspect') }
    Add-Finding -Severity $sev -Category $Category `
        -Title (L "$($kind.en): $Name" "$($kind.fr) : $Name") -Detail $detail `
        -Evidence (Ev @('location', $Where) @('command', (Limit-Text $Command 500)) @('binary', $exe) @('sig', (Format-Signer $sig))) `
        -Advice $Advice
}
function Test-NameList([string]$Name, [string[]]$Patterns) { foreach ($p in $Patterns) { if ($Name -like $p) { return $true } }; return $false }
# Machine scope plus every user hive we can read, for checks that exist at both levels
function Get-RegScopes {
    $s = @([pscustomobject]@{ Name = (L 'all users' 'tous les utilisateurs'); Root = 'HKLM:' })
    foreach ($u in $script:Users) { if ($u.RegRoot) { $s += [pscustomobject]@{ Name = (L $u.Name $u.Name); Root = $u.RegRoot } } }
    return $s
}

# =====================================================================================
#  Checks
# =====================================================================================
$AdvOhook   = L 'Uninstall the activator (MAS offers an Ohook uninstall option), repair Office, then activate with a valid licence.' "Désinstaller l'activateur (MAS propose une option de désinstallation Ohook), réparer Office, puis activer avec une licence valide."
$AdvCkms    = L 'Clear the value (slmgr /ckms) and reactivate with a valid licence.' "Supprimer la valeur (slmgr /ckms) et réactiver avec une licence valide."
$AdvRestore = L 'Restore the original file (sfc /scannow) and look for the intrusion.' "Restaurer le fichier d'origine (sfc /scannow) et rechercher l'intrusion."
$AdvHosts   = L 'Remove these lines.' 'Retirer ces lignes.'

function Check-Activators {
    $cat = 'Activators'

    # --- 1. Ohook: non-Microsoft sppc.dll and sppcs.dll link inside the Office folders
    $roots = @("$PF\Microsoft Office", "$PF86\Microsoft Office",
               "$CommonPF\microsoft shared\OfficeSoftwareProtectionPlatform",
               "$CommonPF86\microsoft shared\OfficeSoftwareProtectionPlatform") | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($r in $roots) {
        foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -Depth 5 -File -Filter 'sppc*.dll' -Force)) {
            Add-Examined
            if ($f.Name -eq 'sppcs.dll') {
                Add-Finding High $cat `
                    (L 'Ohook: sppcs.dll link inside the Office folder' "Ohook : lien sppcs.dll dans le dossier d'Office") `
                    (L 'This file is created by Ohook to redirect to the real Windows licensing library.' "Ce fichier est créé par Ohook pour rediriger vers la vraie bibliothèque de licences de Windows.") `
                    (Ev @('file', $f.FullName) @('type', "$($f.LinkType) $($f.Target)")) $AdvOhook
                continue
            }
            $sig = Get-Sig $f.FullName
            if (-not $sig.Microsoft) {
                $vi = $f.VersionInfo
                $what = if ("$($vi.FileDescription) $($vi.ProductName)" -match '(?i)ohook') { L "Ohook $($vi.FileVersion)" "Ohook $($vi.FileVersion)" } else { L 'licensing library not signed by Microsoft' 'bibliothèque de licences non signée par Microsoft' }
                Add-Finding High $cat `
                    (L "Ohook: $($f.Name) replaced in the Office folder ($($what.en))" "Ohook : $($f.Name) remplacée dans le dossier d'Office ($($what.fr))") `
                    (L "This DLL intercepts the Office licence check and answers 'licensed'." "Cette DLL intercepte la vérification de licence d'Office et répond « licencié ».") `
                    (Ev @('file', $f.FullName) @('size', (L "$($f.Length) bytes" "$($f.Length) octets")) `
                        @('desc', "$($vi.FileDescription) / $($vi.CompanyName)") @('sig', (Format-Signer $sig)) @('modified', (Format-When $f.LastWriteTime))) $AdvOhook
            }
        }
    }

    # --- 2. Known files and folders
    foreach ($p in $IOC.ActivatorPaths) {
        $e = Expand-IocPath $p
        Add-Examined
        if ($e -match '%') { continue }
        foreach ($i in @(Get-Item -Path $e -Force)) {
            Add-Finding High $cat `
                (L "Activator file or folder: $($i.Name)" "Fichier ou dossier d'activateur : $($i.Name)") `
                (L 'Location used by a known activation tool.' "Emplacement utilisé par un outil d'activation connu.") `
                (Ev @('path', $i.FullName) @('created', (Format-When $i.CreationTime)) @('modified', (Format-When $i.LastWriteTime))) `
                (L 'Identify who dropped it and when, then delete it once the evidence is collected.' "Identifier qui l'a déposé et quand, puis supprimer après collecte.")
            Add-Timeline $i.CreationTime (L "Activator dropped: $($i.Name)" "Activateur déposé : $($i.Name)") 'High'
        }
    }

    # --- 3. Activator scheduled tasks and services
    foreach ($t in $script:Tasks) {
        Add-Examined
        if ((Test-NameList $t.Name $IOC.ActivatorTaskNames) -or ($IOC.ActivatorTaskFolders | Where-Object { $t.Path -like "$_*" })) {
            Add-Finding High $cat `
                (L "Activator scheduled task: $($t.Path)$($t.Name)" "Tâche planifiée d'activateur : $($t.Path)$($t.Name)") `
                (L 'Task that renews the activation automatically.' "Tâche de renouvellement automatique de l'activation.") `
                (Ev @('actions', ($t.Actions -join ' | ')) @('account', $t.User) @('created', $t.Date)) `
                (L 'Delete the task and the script it launches.' "Supprimer la tâche et le script qu'elle lance.")
        }
    }
    foreach ($s in $script:Services) {
        Add-Examined
        if (Test-NameList $s.Name $IOC.ActivatorServices) {
            Add-Finding High $cat `
                (L "Activator service: $($s.Name)" "Service d'activateur : $($s.Name)") `
                (L 'Service installed by a KMS emulator.' 'Service installé par un émulateur KMS.') `
                (Ev @('command', $s.PathName) @('state', "$($s.State) / $($s.StartMode)")) `
                (L 'Stop and delete the service, then analyse the binary.' 'Arrêter et supprimer le service, puis analyser le binaire.')
        }
    }

    # --- 4. KMS server configured in the registry
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
            $ev = Ev @('key', $k) @('server', $h) @('port', $v['KeyManagementServicePort'])
            if ($IOC.KmsPlaceholderHosts -contains $h) {
                Add-Finding High $cat `
                    (L "Dummy KMS address: $h" "Adresse KMS factice : $h") `
                    (L 'Address written by an activator (MAS uses 10.0.0.10 for Ohook/Online KMS and 127.0.0.2 to lock KMS38).' "Adresse posée par un activateur (MAS utilise 10.0.0.10 pour Ohook/Online KMS et 127.0.0.2 pour verrouiller KMS38).") $ev $AdvCkms
            } elseif ($h -match $IOC.PublicKmsRegex) {
                Add-Finding High $cat `
                    (L "Public pirate KMS server: $h" "Serveur KMS public pirate : $h") `
                    (L 'The host asks a third-party KMS server on the internet to activate it.' "Le poste demande son activation à un serveur KMS tiers sur Internet.") $ev $AdvCkms
            } elseif ($script:HostInfo.PartOfDomain) {
                Add-Finding Info $cat `
                    (L "KMS server configured: $h" "Serveur KMS configuré : $h") `
                    (L 'Domain-joined host: most likely a corporate KMS server.' "Poste joint à un domaine : serveur KMS d'entreprise probable.") $ev
            } else {
                Add-Finding Medium $cat `
                    (L "KMS server configured on a host that is not domain-joined: $h" "Serveur KMS configuré sur un poste hors domaine : $h") `
                    (L 'A host outside a domain normally has no KMS server.' "Un poste hors domaine n'a normalement pas de serveur KMS.") $ev `
                    (L 'Check that this server belongs to your organisation.' "Vérifier que ce serveur appartient bien à votre organisation.")
            }
        }
    }

    # --- 5. Licence status (KMS38, KMS4k/TSforge, unexpected volume licence)
    $status = @{ 0 = (L 'Unlicensed' 'Sans licence'); 1 = (L 'Licensed' 'Activé'); 2 = (L 'Initial grace period' 'Période de grâce initiale')
                 3 = (L 'Grace period (hardware changed)' 'Grâce (matériel modifié)'); 4 = (L 'Grace period (non-genuine)' 'Grâce (non authentique)')
                 5 = (L 'Notification' 'Notification'); 6 = (L 'Extended grace period' 'Grâce étendue') }
    foreach ($p in @(Get-LicensingProducts)) {
        Add-Examined
        $days = [math]::Round([double]$p.GracePeriodRemaining / 1440)
        $st = Loc $status[[int]$p.LicenseStatus]
        $ev = Ev @('product', $p.Name) @('channel', $p.Description) @('status', $st) @('pkey', "...$($p.PartialProductKey)") `
                 @('remaining', (L "$days days" "$days jours")) @('kms', "$($p.KeyManagementServiceMachine) $($p.DiscoveredKeyManagementServiceMachineName)")
        if ("$($p.Description)" -match 'KMSCLIENT|KMS_' -and [double]$p.GracePeriodRemaining -gt 270000) {
            Add-Finding High $cat `
                (L "KMS activation with an abnormal duration ($days days): $($p.Name)" "Activation KMS d'une durée anormale ($days jours) : $($p.Name)") `
                (L 'A legitimate KMS activation lasts 180 days. A duration of several years means KMS38 or KMS4k (TSforge).' "Une activation KMS légitime dure 180 jours. Une durée de plusieurs années correspond à KMS38 ou à KMS4k (TSforge).") $ev `
                (L 'Install a legitimate key (slmgr /ipk) and reactivate.' 'Réinstaller une clé légitime (slmgr /ipk) et réactiver.')
        } elseif ("$($p.Description)" -match 'KMSCLIENT' -and -not $script:HostInfo.PartOfDomain) {
            Add-Finding Medium $cat `
                (L "Volume (KMS) licence on a host that is not domain-joined: $($p.Name)" "Licence en volume (KMS) sur un poste hors domaine : $($p.Name)") `
                (L 'Volume editions activate against a corporate KMS server. Outside a domain this often means an activator.' "Les éditions en volume s'activent auprès d'un serveur KMS d'entreprise. Hors domaine, c'est souvent le signe d'un activateur.") $ev `
                (L 'Check where the licence comes from.' "Vérifier l'origine de la licence.")
        } else {
            Add-Finding Info $cat (L "Licence: $($p.Name)" "Licence : $($p.Name)") $st $ev
        }
    }
    Add-Note (L 'Once applied, HWID and TSforge (ZeroCID) activations are indistinguishable from a legitimate activation: only their side traces can be detected.' "Les activations HWID et TSforge (ZeroCID) sont indiscernables d'une activation légitime une fois posées : seules leurs traces annexes sont détectables.")

    # --- 6. HWID activation leftovers and the NoGenTicket policy
    foreach ($f in @(Get-ChildItem -LiteralPath "$PData\Microsoft\Windows\ClipSVC\GenuineTicket" -File -Force)) {
        Add-Finding Medium $cat `
            (L "Activation ticket left on disk: $($f.Name)" "Ticket d'activation resté sur le disque : $($f.Name)") `
            (L 'Windows normally consumes and deletes these tickets. A leftover may come from a forced HWID activation.' "Windows consomme et supprime normalement ces tickets. Un reste peut provenir d'une activation HWID forcée.") `
            (Ev @('file', $f.FullName) @('created', (Format-When $f.CreationTime)))
    }
    $pol = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    if ($pol -and "$($pol['NoGenTicket'])" -eq '1') {
        $sev = if ($script:HostInfo.PartOfDomain) { 'Info' } else { 'Medium' }
        Add-Finding $sev $cat `
            (L 'Online validation of the KMS activation disabled (NoGenTicket)' "Validation en ligne de l'activation KMS désactivée (NoGenTicket)") `
            (L 'Policy written by KMS activators, sometimes also by a corporate GPO.' "Stratégie posée par les activateurs KMS, parfois aussi par une GPO d'entreprise.") `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\NoGenTicket = 1'
    }

    # --- 7. Office registry value written by Ohook (per user)
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $v = Get-RegValues "$($u.RegRoot)\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency"
        Add-Examined
        if ($v -and "$($v['TimeOfLastHeartbeatFailure'])" -match '^(20[3-9]\d|2[1-9]\d\d)') {
            Add-Finding High $cat `
                (L "Ohook: Office subscription check neutralised for $($u.Name)" "Ohook : contrôle d'abonnement Office neutralisé pour $($u.Name)") `
                (L 'The date is set far in the future so Office never verifies the subscription online.' "La date est placée loin dans le futur pour empêcher Office de vérifier l'abonnement en ligne.") `
                (Ev @('key', "$($u.RegRoot)\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency") @('value', "TimeOfLastHeartbeatFailure = $($v['TimeOfLastHeartbeatFailure'])")) $AdvOhook
        }
    }

    # --- 8. Licensing service hijack (KMS_VL_ALL, KMSpico)
    foreach ($img in 'SppExtComObj.exe', 'osppsvc.exe', 'sppsvc.exe') {
        foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
            $v = Get-RegValues "$base\$img"
            Add-Examined
            if ($v -and ($v['Debugger'] -or $v['VerifierDlls'])) {
                Add-Finding High $cat `
                    (L "Licensing service hijacked: $img" "Service de licences détourné : $img") `
                    (L 'Technique used by local KMS emulators (KMS_VL_ALL, KMSpico).' 'Technique des émulateurs KMS locaux (KMS_VL_ALL, KMSpico).') `
                    (Ev @('key', "$base\$img") @('value', "Debugger = $($v['Debugger'])") @('value', "VerifierDlls = $($v['VerifierDlls'])")) `
                    (L 'Delete the key and the DLL it points to.' 'Supprimer la clé et la DLL associée.')
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
                $hits = @($lines | Where-Object { $_ -match $p.Regex } | Select-Object -Unique)
                if (-not $hits.Count) { continue }
                $sev = $p.Severity
                $lab = Loc $p.Label
                # Every matching line is a known official installer: inventory, not a signal
                if ($IOC.HistoryAllowRegex -and -not @($hits | Where-Object { $_ -notmatch $IOC.HistoryAllowRegex }).Count) {
                    $sev = 'Info'; $lab = @{ en = "$($lab.en) (known installer)"; fr = "$($lab.fr) (installateur connu)" }
                }
                $shown = ($hits | Select-Object -First 8 | ForEach-Object { '  ' + (Limit-Text $_ 240) }) -join "`n"
                Add-Finding $sev $p.Category `
                    (L "$($lab.en) $([char]0x2014) history of $($u.Name)" "$($lab.fr) $([char]0x2014) historique de $($u.Name)") `
                    (L "$($hits.Count) command(s) in the PowerShell history. The history carries no timestamp." "$($hits.Count) commande(s) dans l'historique PowerShell. L'historique ne porte pas de date.") `
                    (Ev @('file', (L "$($f.FullName) (modified $(Format-When $f.LastWriteTime))" "$($f.FullName) (modifié le $(Format-When $f.LastWriteTime))")) $shown) `
                    (L 'Cross-check with the user and the event logs to date the execution.' "Recouper avec l'utilisateur et les journaux pour dater l'exécution.")
            }
        }
    }
    # Logged script blocks (when PowerShell logging is enabled)
    $ev = @(Get-EventData 'Microsoft-Windows-PowerShell/Operational' @(4104) $Since)
    Add-Examined $ev.Count
    # Running this tool's own self-test loads tests\Mocks.ps1, which contains literal activator
    # fixture strings (KMSpico, KMSELDI...) as test data. If script block logging is on, Windows
    # logs that file's content, and a later real scan would otherwise flag its own test run.
    $self = @($ev | Where-Object { $_.Message -match $IOC.SelfTestRegex })
    $ev = @($ev | Where-Object { $_.Message -notmatch $IOC.SelfTestRegex })
    if ($self.Count) { Add-Note (L "$($self.Count) logged script block(s) excluded: WinTriage's own test run." "$($self.Count) bloc(s) de script exclu(s) : exécution du test interne de WinTriage.") }
    foreach ($p in $IOC.HistoryPatterns) {
        $hits = @($ev | Where-Object { $_.Message -match $p.Regex })
        if (-not $hits.Count) { continue }
        $lab = Loc $p.Label
        $shown = ($hits | Select-Object -First 5 | ForEach-Object { "  $(Format-When $_.Time) : " + (Limit-Text (($_.Message -split "`n" | Where-Object { $_ -match $p.Regex } | Select-Object -First 1)) 220) }) -join "`n"
        Add-Finding $p.Severity $p.Category `
            (L "$($lab.en) $([char]0x2014) PowerShell log" "$($lab.fr) $([char]0x2014) journal PowerShell") `
            (L "$($hits.Count) logged script block(s) in the last $Days days." "$($hits.Count) bloc(s) de script journalisé(s) depuis $Days jours.") $shown
    }
}

function Check-RunKeys {
    $cat = 'Autostart'
    $sub = @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'Software\Microsoft\Windows\CurrentVersion\RunOnceEx', 'Software\Microsoft\Windows\CurrentVersion\RunServices',
             'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
             'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; Who = (L 'all users' 'tous les utilisateurs') })
    foreach ($u in $script:Users) {
        if ($u.RegRoot) { $roots += [pscustomobject]@{ Root = $u.RegRoot; Who = (L $u.Name $u.Name) } }
        else { Add-Note (L "Registry of $($u.Name) not analysed (session closed; use -LoadUserHives)." "Registre de $($u.Name) non analysé (session fermée ; utiliser -LoadUserHives).") }
    }
    foreach ($r in $roots) {
        foreach ($s in $sub) {
            $v = Get-RegValues "$($r.Root)\$s"
            if (-not $v) { continue }
            foreach ($n in $v.Keys) {
                if ($n) { Add-Autorun -Category $cat -Kind (L "Run key ($($r.Who.en))" "Clé Run ($($r.Who.fr))") -Name $n -Command "$($v[$n])" -Where "$($r.Root)\$s" }
            }
        }
        # Logon script and screen saver
        if ($r.Root -ne 'HKLM:') {
            $e = Get-RegValues "$($r.Root)\Environment"
            if ($e -and $e['UserInitMprLogonScript']) {
                Add-Finding High $cat `
                    (L "Logon script for $($r.Who.en)" "Script d'ouverture de session pour $($r.Who.fr)") `
                    (L 'Persistence mechanism that is rarely legitimate.' 'Mécanisme de persistance rarement légitime.') `
                    "$($r.Root)\Environment\UserInitMprLogonScript = $($e['UserInitMprLogonScript'])"
            }
            $d = Get-RegValues "$($r.Root)\Control Panel\Desktop"
            if ($d -and $d['SCRNSAVE.EXE'] -and "$($d['SCRNSAVE.EXE'])" -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\[^\\]+\.scr$') {
                Add-Autorun -Category $cat -Kind (L "Screen saver ($($r.Who.en))" "Économiseur d'écran ($($r.Who.fr))") -Name 'SCRNSAVE.EXE' -Command "$($d['SCRNSAVE.EXE'])" -Where "$($r.Root)\Control Panel\Desktop"
            }
        }
    }
    # Active Setup: report only what looks suspicious
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        foreach ($k in @(Get-RegSubKeys $base)) {
            $v = Get-RegValues "$base\$k"
            if ($v -and $v['StubPath']) { Add-Autorun -Category $cat -Kind (L 'Active Setup' 'Active Setup') -Name $k -Command "$($v['StubPath'])" -Where "$base\$k" -Quiet }
        }
    }
}

function Check-StartupFolders {
    $cat = 'Autostart'
    $dirs = @([pscustomobject]@{ Dir = "$PData\Microsoft\Windows\Start Menu\Programs\StartUp"; Who = (L 'all users' 'tous les utilisateurs') })
    foreach ($u in $script:Users) { $dirs += [pscustomobject]@{ Dir = (Join-Path $u.Profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); Who = (L $u.Name $u.Name) } }
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d.Dir -File -Force)) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $cmd = $f.FullName
            if ($f.Extension -eq '.lnk') { $t = Resolve-Lnk $f.FullName; if ($t) { $cmd = $t } }
            if ($f.Extension -match '(?i)^\.(bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|pif)$') {
                Add-Examined
                $sev = if ("$($f.Name)" -match $IOC.ActivatorRegex) { 'High' } else { 'Medium' }
                Add-Finding $sev $cat `
                    (L "Script in the Startup folder ($($d.Who.en)): $($f.Name)" "Script dans le dossier Démarrage ($($d.Who.fr)) : $($f.Name)") `
                    (L 'A script dropped straight into the Startup folder runs at every logon.' 'Un script posé directement dans le dossier Démarrage est exécuté à chaque ouverture de session.') `
                    (Ev @('file', $f.FullName) @('created', (Format-When $f.CreationTime)) `
                        @('head', (Limit-Text ((Get-Content -LiteralPath $f.FullName -TotalCount 3) -join " $([char]0x23CE) ") 300))) `
                    (L 'Read the script and identify who dropped it.' "Lire le script et identifier qui l'a déposé.")
            } else {
                Add-Autorun -Category $cat -Kind (L "Startup folder ($($d.Who.en))" "Dossier Démarrage ($($d.Who.fr))") -Name $f.Name -Command $cmd -Where $f.FullName
            }
        }
    }
    # Shortcuts people click every day: desktop, Start menu, pinned taskbar items.
    # A hijacked shortcut is how browser adware survives an uninstall.
    $lnkDirs = @([pscustomobject]@{ Dir = (Join-Path $PublicDir 'Desktop'); Who = (L 'all users' 'tous les utilisateurs') },
                 [pscustomobject]@{ Dir = "$PData\Microsoft\Windows\Start Menu\Programs"; Who = (L 'all users' 'tous les utilisateurs') })
    foreach ($u in $script:Users) {
        foreach ($sub in 'Desktop', 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs',
                         'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar') {
            $lnkDirs += [pscustomobject]@{ Dir = (Join-Path $u.Profile $sub); Who = (L $u.Name $u.Name) }
        }
    }
    foreach ($d in $lnkDirs) {
        if (-not $d.Dir -or -not (Test-Path -LiteralPath $d.Dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d.Dir -Recurse -Depth 2 -File -Force -Filter '*.lnk')) {
            Add-Examined
            $t = Resolve-Lnk $f.FullName
            if (-not $t) { continue }
            # Only shortcuts that start something: a .url, a document or a help file is not persistence
            if ($t -notmatch '(?i)\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|pif|dll|msi|msc)\b') { continue }
            $where = L "shortcut: $($f.FullName)" "raccourci : $($f.FullName)"
            if ($t -match $IOC.BrowserHijackArgsRegex) {
                Add-Finding High $cat `
                    (L "Browser shortcut carrying injected options ($($d.Who.en)): $($f.Name)" "Raccourci de navigateur porteur d'options injectées ($($d.Who.fr)) : $($f.Name)") `
                    (L 'The shortcut adds command-line options to the browser: loading an extension from disk, disabling web security or forcing a proxy. The browser looks untouched until it is started from this shortcut.' "Le raccourci ajoute des options en ligne de commande au navigateur : chargement d'une extension depuis le disque, désactivation des protections web ou proxy imposé. Le navigateur paraît intact jusqu'à ce qu'on le lance par ce raccourci.") `
                    (Ev @('file', $f.FullName) @('target', (Limit-Text $t 400)) @('modified', (Format-When $f.LastWriteTime))) `
                    (L 'Fix the shortcut target, then look for the folder the extension is loaded from.' "Corriger la cible du raccourci, puis chercher le dossier depuis lequel l'extension est chargée.")
                Add-Timeline $f.LastWriteTime (L "Shortcut hijacked: $($f.Name)" "Raccourci détourné : $($f.Name)") 'High'
                continue
            }
            # A shortcut launching an interpreter, an activator, or something dropped in a temp
            # folder. Ordinary per-user installs (AppData\Local\Programs) are not reported: a
            # Start-menu shortcut to an unsigned application is how most of them look.
            $strong = $false
            foreach ($r in $StrongCmd) { if ($t -match $r.R) { $strong = $true } }
            $exe = Resolve-ExePath $t
            if ($t -match $LolBinRegex -or $t -match $IOC.ActivatorRegex -or $strong) {
                Add-Autorun -Category $cat -Kind (L "Shortcut ($($d.Who.en))" "Raccourci ($($d.Who.fr))") -Name $f.Name -Command $t -Where $where
            }
            elseif ($exe -match $DropZoneRegex) {
                Add-Autorun -Category $cat -Kind (L "Shortcut ($($d.Who.en))" "Raccourci ($($d.Who.fr))") -Name $f.Name -Command $t -Where $where -Quiet
            }
        }
    }
}

function Check-Tasks {
    $cat = 'ScheduledTasks'
    foreach ($t in $script:Tasks) {
        $ms = ($t.Path -like '\Microsoft\*')
        if ((Test-NameList $t.Name $IOC.ActivatorTaskNames) -or ($IOC.ActivatorTaskFolders | Where-Object { $t.Path -like "$_*" })) { Add-Examined; continue }   # already reported by Activators
        foreach ($a in @($t.Actions)) {
            if ($a -like 'COM:*') { Add-Examined; continue }
            Add-Autorun -Category $cat -Kind (L 'Task' 'Tâche') -Name "$($t.Path)$($t.Name)" -Command $a `
                -Where (L "account: $($t.User) $([char]0x2014) created: $($t.Date) $([char]0x2014) author: $($t.Author)" "compte : $($t.User) $([char]0x2014) créée : $($t.Date) $([char]0x2014) auteur : $($t.Author)") -Quiet:$ms
        }
    }
    if (-not $script:Tasks.Count) { Add-Note (L 'No task could be read (ScheduledTasks module unavailable?).' 'Aucune tâche lue (module ScheduledTasks indisponible ?).') }
    # Hidden tasks: present in the registry but stripped of their security descriptor, or invisible to the API
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $known = @{}
    foreach ($t in $script:Tasks) { $known[("$($t.Path)$($t.Name)").ToLower()] = $true }
    $orphans = @()
    $stack = New-Object System.Collections.Stack
    $stack.Push('')
    $n = 0
    while ($stack.Count -and $n -lt 5000) {
        $rel = $stack.Pop(); $n++
        foreach ($k in @(Get-RegSubKeys "$tree$rel")) { $stack.Push("$rel\$k") }
        if (-not $rel) { continue }
        $v = Get-RegValues "$tree$rel"
        if (-not $v -or -not $v['Id']) { continue }                 # a folder, not a task
        Add-Examined
        $act = ''
        $tv = Get-RegValues "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$($v['Id'])"
        if ($tv -and $tv['Actions']) { $act = ([Text.Encoding]::Unicode.GetString([byte[]]$tv['Actions']) -replace '[^\x20-\x7E]+', ' ').Trim() }
        $ev = Ev @('key', "$tree$rel") @('id', $v['Id']) @('actions', (Limit-Text $act 400))
        if ($known[$rel.ToLower()] -and $v.ContainsKey('SD')) { continue }   # ordinary task, already analysed through the API
        if (-not $tv) { $orphans += $rel; continue }                         # name with no definition: inactive leftover
        $isAct = ("$rel $act" -match $IOC.ActivatorRegex) -or (Test-NameList (Split-Path $rel -Leaf) $IOC.ActivatorTaskNames)
        if (-not $v.ContainsKey('SD')) {
            Add-Finding High $cat `
                (L "Hidden task (security descriptor removed): $rel" "Tâche masquée (descripteur de sécurité supprimé) : $rel") `
                (L "Deleting the SD value hides a task from Task Scheduler and from schtasks while it keeps running (the 'Tarrask' technique)." "Supprimer la valeur SD rend une tâche invisible dans le Planificateur et pour schtasks, tout en la laissant active (technique « Tarrask »).") $ev `
                (L 'Export the key, analyse the action, then delete the task.' "Exporter la clé, analyser l'action, puis supprimer la tâche.")
        } elseif ($script:IsAdmin -and $script:Tasks.Count -and -not $known[$rel.ToLower()]) {
            $sev = if ($isAct) { 'High' } else { 'Medium' }
            $c2 = if ($isAct) { 'Activators' } else { $cat }
            Add-Finding $sev $c2 `
                (L "Task present in the registry but invisible to the API: $rel" "Tâche présente dans le registre mais invisible de l'API : $rel") `
                (L 'Leftover of an incompletely deleted task, or a task hidden on purpose.' "Reste d'une tâche supprimée de façon incomplète, ou tâche volontairement dissimulée.") $ev `
                (L 'Check the recorded action and whether the matching file exists under C:\Windows\System32\Tasks.' "Vérifier l'action enregistrée et la présence du fichier C:\Windows\System32\Tasks correspondant.")
        }
    }
    if ($orphans.Count) {
        $odd = @($orphans | Where-Object { $_ -notlike '\Microsoft\*' -or "$_" -match $IOC.ActivatorRegex })
        $sev = if ($odd.Count) { 'Medium' } else { 'Info' }
        Add-Finding $sev $cat `
            (L "Orphaned task entries in the registry ($($orphans.Count))" "Entrées de tâches orphelines dans le registre ($($orphans.Count))") `
            (L 'Task name with no matching definition: the task cannot run. Windows commonly leaves these behind after updates.' "Nom de tâche sans définition associée : la tâche ne peut pas s'exécuter. Windows en laisse couramment après les mises à jour.") `
            (($orphans | Sort-Object | Select-Object -First 60) -join "`n") `
            $(if ($sev -eq 'Medium') { L 'Check the entries outside \Microsoft\.' "Vérifier les entrées hors \Microsoft\." })
    }
}

function Check-Services {
    $cat = 'Services'
    foreach ($s in $script:Services) {
        if (Test-NameList $s.Name $IOC.ActivatorServices) { Add-Examined; continue }     # already reported by Activators
        $cmd = "$($s.PathName)"
        if ($cmd -match '(?i)\\svchost\.exe') {
            $p = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters"
            if ($p -and $p['ServiceDll']) {
                $dll = [Environment]::ExpandEnvironmentVariables("$($p['ServiceDll'])")
                $cmd = '"' + $dll + '"'
                # A shared-process service whose DLL lives outside the system folders is not normal
                if ($dll -notmatch '(?i)^[A-Z]:\\(Windows\\(System32|SysWOW64|WinSxS|SystemApps)|Program Files( \(x86\))?)\\') {
                    $sg = Get-Sig $dll
                    $sev = if ($dll -match $WritableRegex -or ($sg.Exists -and -not $sg.Signed)) { 'High' } else { 'Medium' }
                    Add-Finding $sev $cat `
                        (L "Service DLL outside the system folders: $($s.Name)" "DLL de service hors des dossiers système : $($s.Name)") `
                        (L 'This service runs inside a shared svchost process and loads its code from this DLL, as SYSTEM.' "Ce service s'exécute dans un processus svchost partagé et charge son code depuis cette DLL, en tant que SYSTEM.") `
                        (Ev @('service', $s.Name) @('dll', $dll) @('sig', (Format-Signer $sg)) @('state', "$($s.State) / $($s.StartMode)")) `
                        (L 'Identify the product that registered the service; treat an unknown DLL as a compromise.' "Identifier le produit qui a enregistré le service ; considérer une DLL inconnue comme une compromission.")
                }
            }
        }
        # Unquoted ImagePath with spaces: any user who can write earlier in the path gains SYSTEM
        if ($cmd -match '^[A-Za-z]:\\[^"]*\s' -and $cmd -notmatch '^"' -and $cmd -match '(?i)^([A-Z]:\\[^"]*?\.exe)(\s|$)') {
            $exe = $Matches[1]
            if ($exe -match '\s' -and $exe -notmatch '(?i)^[A-Z]:\\Windows\\') {
                Add-Finding Medium $cat `
                    (L "Unquoted service path with spaces: $($s.Name)" "Chemin de service non protégé contenant des espaces : $($s.Name)") `
                    (L 'Windows tries each truncation of the path in turn, so a file dropped earlier in the path runs as SYSTEM instead.' "Windows essaie chaque troncature du chemin, si bien qu'un fichier déposé plus tôt dans le chemin s'exécute à la place, en tant que SYSTEM.") `
                    (Ev @('service', $s.Name) @('command', $cmd)) `
                    (L 'Quote the ImagePath value, or check the parent folders are not writable by users.' "Mettre la valeur ImagePath entre guillemets, ou vérifier que les dossiers parents ne sont pas modifiables par les utilisateurs.")
            }
        }
        Add-Autorun -Category $cat -Kind (L 'Service' 'Service') -Name "$($s.Name) ($($s.DisplayName))" -Command $cmd `
            -Where (L "startup: $($s.StartMode) $([char]0x2014) state: $($s.State) $([char]0x2014) account: $($s.StartName)" "démarrage : $($s.StartMode) $([char]0x2014) état : $($s.State) $([char]0x2014) compte : $($s.StartName)")
    }
}

function Check-Wmi {
    $cat = 'WMI'
    foreach ($w in @(Get-WmiSubscriptions)) {
        Add-Examined
        if ($w.Class -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
            $sev = if ($w.Name -eq 'BVTConsumer') { 'Info' } else { 'High' }
            Add-Finding $sev $cat `
                (L "WMI subscription that runs code: $($w.Name)" "Abonnement WMI exécutant du code : $($w.Name)") `
                (L 'Permanent WMI subscriptions run a command when a system event fires. Very rare in legitimate use, common with attackers.' "Les abonnements WMI permanents lancent une commande sur un événement système. Très rares en usage légitime, courants chez les attaquants.") `
                (Ev @('type', $w.Class) @('command', (Limit-Text $w.Detail 600))) `
                (L 'Identify the matching filter, then delete filter, consumer and binding.' 'Identifier le filtre associé, puis supprimer filtre, consommateur et liaison.')
        } elseif ($w.Class -eq '__EventFilter' -and $w.Name -notmatch '^(SCM Event Log Filter|BVTFilter)$') {
            Add-Finding Medium $cat `
                (L "WMI event filter: $($w.Name)" "Filtre d'événements WMI : $($w.Name)") `
                (L 'Non-standard permanent filter.' 'Filtre permanent non standard.') (Ev @('query', $w.Detail))
        }
    }
}

function Check-RegistryPersistence {
    $cat = 'Registry'
    $nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    # Machine scope plus every user hive we can read, for the per-user hijacks below
    $scopesReg = @(Get-RegScopes)
    # Winlogon
    $w = Get-RegValues "$nt\Winlogon"
    Add-Examined 3
    if ($w) {
        if ($w['Shell'] -and "$($w['Shell'])".Trim() -notmatch '^(?i)explorer\.exe$') {
            Add-Finding High $cat (L 'Winlogon: session shell modified' 'Winlogon : interpréteur de session modifié') `
                (L 'The Shell value must be explorer.exe.' 'La valeur Shell doit être explorer.exe.') "$nt\Winlogon\Shell = $($w['Shell'])"
        }
        if ($w['Userinit'] -and "$($w['Userinit'])".Trim() -notmatch '^(?i)([A-Z]:\\Windows\\system32\\)?userinit\.exe,?$') {
            Add-Finding High $cat (L 'Winlogon: Userinit modified' 'Winlogon : Userinit modifié') `
                (L 'The value must be C:\Windows\system32\userinit.exe,' 'La valeur doit être C:\Windows\system32\userinit.exe,') "$nt\Winlogon\Userinit = $($w['Userinit'])"
        }
        if ($w['Taskman']) {
            Add-Finding Medium $cat (L 'Winlogon: Taskman value present' 'Winlogon : valeur Taskman présente') `
                (L 'This value does not exist by default.' 'Valeur absente par défaut.') "$nt\Winlogon\Taskman = $($w['Taskman'])"
        }
    }
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $uw = Get-RegValues "$($u.RegRoot)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if ($uw -and $uw['Shell']) {
            Add-Finding High $cat `
                (L "Winlogon: session shell defined for $($u.Name)" "Winlogon : interpréteur de session défini pour $($u.Name)") `
                (L 'This value does not exist at user level by default.' "Cette valeur n'existe pas par défaut au niveau utilisateur.") "Shell = $($uw['Shell'])"
        }
        foreach ($root in "$($u.RegRoot)\Software\Microsoft\Office test\Special\Perf") {
            $ot = Get-RegValues $root
            if ($ot -and $ot['']) {
                Add-Finding High $cat `
                    (L "'Office test' key for $($u.Name)" "Clé « Office test » pour $($u.Name)") `
                    (L 'DLL loaded by every Office application at startup: a known persistence technique.' 'DLL chargée par toutes les applications Office au démarrage : technique de persistance connue.') `
                    "$root = $($ot[''])"
            }
        }
    }
    # AppInit / AppCert
    foreach ($k in "$nt\Windows", 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $v = Get-RegValues $k
        Add-Examined
        if ($v -and "$($v['AppInit_DLLs'])".Trim()) {
            $sev = if ("$($v['LoadAppInit_DLLs'])" -eq '1') { 'High' } else { 'Medium' }
            Add-Finding $sev $cat (L 'AppInit_DLLs is set' 'AppInit_DLLs renseigné') `
                (L 'DLLs injected into every graphical process.' 'DLL injectées dans tous les processus graphiques.') `
                (Ev @('key', $k) @('value', "AppInit_DLLs = $($v['AppInit_DLLs'])") @('value', "LoadAppInit_DLLs = $($v['LoadAppInit_DLLs'])"))
        }
    }
    $ac = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if ($ac -and $ac.Count) {
        Add-Finding High $cat (L 'AppCertDlls is set' 'AppCertDlls renseigné') `
            (L 'DLLs injected into every process that creates another one.' 'DLL injectées dans tout processus qui en crée un autre.') `
            (($ac.Keys | ForEach-Object { "$_ = $($ac[$_])" }) -join "`n")
    }
    # Session Manager
    $sm = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if ($sm -and $sm['BootExecute']) {
        $bad = @($sm['BootExecute'] | Where-Object { $_ -and $_ -notmatch '^(?i)autocheck autochk ' })
        if ($bad.Count) {
            Add-Finding High $cat (L 'BootExecute modified' 'BootExecute modifié') `
                (L 'Program launched very early at boot, before the protections.' 'Programme lancé très tôt au démarrage, avant les protections.') `
                ('BootExecute = ' + ($sm['BootExecute'] -join ' | '))
        }
    }
    # Image File Execution Options
    $access = 'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe'
    foreach ($base in "$nt\Image File Execution Options", 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($img in @(Get-RegSubKeys $base)) {
            Add-Examined
            if ($img -match '(?i)^(SppExtComObj|osppsvc|sppsvc)\.exe$') { continue }      # handled by Activators
            $v = Get-RegValues "$base\$img"
            if ($v -and $v['Debugger']) {
                $sev = if ($access -contains $img.ToLower()) { 'Critical' } else { 'High' }
                $why = if ($sev -eq 'Critical') {
                    L 'Classic backdoor: the accessibility tool of the logon screen launches another program with SYSTEM rights.' "Porte dérobée classique : l'outil d'accessibilité de l'écran de connexion lance un autre programme avec les droits SYSTEM."
                } else {
                    L 'The program named here runs instead of (or around) the target executable.' "Le programme indiqué est lancé à la place (ou autour) de l'exécutable visé."
                }
                Add-Finding $sev $cat (L "Debugger attached to $img" "Débogueur attaché à $img") $why "$base\$img\Debugger = $($v['Debugger'])"
            }
        }
    }
    foreach ($img in @(Get-RegSubKeys "$nt\SilentProcessExit")) {
        $v = Get-RegValues "$nt\SilentProcessExit\$img"
        if ($v -and $v['MonitorProcess']) {
            Add-Finding High $cat (L "Program launched when $img exits" "Programme lancé à la fermeture de $img") `
                (L 'Persistence through SilentProcessExit.' 'Persistance via SilentProcessExit.') "MonitorProcess = $($v['MonitorProcess'])"
        }
    }
    # Replaced accessibility tools
    $shells = @{}
    foreach ($n in 'cmd.exe', 'WindowsPowerShell\v1.0\powershell.exe', 'taskmgr.exe', 'mmc.exe', 'wscript.exe') { $h = Get-Sha256 (Join-Path $SysRoot "System32\$n"); if ($h) { $shells[$h] = $n } }
    $h = Get-Sha256 (Join-Path $SysRoot 'explorer.exe'); if ($h) { $shells[$h] = 'explorer.exe' }
    foreach ($a in $access) {
        $p = Join-Path $SysRoot "System32\$a"
        $s = Get-Sig $p
        Add-Examined
        $h = Get-Sha256 $p
        if ($h -and $shells[$h]) {
            Add-Finding Critical $cat `
                (L "Accessibility tool replaced by $($shells[$h]): $a" "Outil d'accessibilité remplacé par $($shells[$h]) : $a") `
                (L 'Classic backdoor: from the logon screen this accessibility shortcut opens a shell with SYSTEM rights.' "Porte dérobée classique : depuis l'écran de connexion, ce raccourci d'accessibilité ouvre un interpréteur avec les droits SYSTEM.") `
                (Ev @('file', $p) @('sha256', (L "identical to $($shells[$h])" "identique à $($shells[$h])"))) $AdvRestore
        }
        elseif ($s.Exists -and -not $s.Signed) {
            Add-Finding Critical $cat `
                (L "Unsigned accessibility tool: $a" "Outil d'accessibilité non signé : $a") `
                (L 'System file replaced: possible backdoor on the logon screen.' 'Fichier système remplacé : porte dérobée possible sur l''écran de connexion.') `
                (Ev @('file', $p) @('sig', (Format-Signer $s))) $AdvRestore
        }
    }
    # LSA
    $lsa = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($lsa) {
        $std = @{ 'Authentication Packages' = '^(msv1_0)$'; 'Notification Packages' = '^(scecli|rassfm)$'; 'Security Packages' = '^("")?$|^(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|livessp)$' }
        foreach ($n in $std.Keys) {
            $extra = @(@($lsa[$n]) | Where-Object { $_ -and "$_".Trim() -notmatch "(?i)$($std[$n])" })
            Add-Examined
            if ($extra.Count) {
                Add-Finding Medium $cat `
                    (L "LSA: extra module in '$n'" "LSA : module supplémentaire dans « $n »") `
                    (L 'Module loaded into the authentication process (lsass). Legitimate for some security or password synchronisation products, suspicious otherwise.' "Module chargé dans le processus d'authentification (lsass). Légitime pour certains produits de sécurité ou de synchronisation de mots de passe, sinon suspect.") `
                    (Ev @('values', "$n = $(@($lsa[$n]) -join ', ')") @('nonstd', ($extra -join ', '))) `
                    (L 'Identify the publisher of the matching DLL in System32.' "Identifier l'éditeur de la DLL correspondante dans System32.")
            }
        }
    }
    # Print monitors and netsh helpers
    foreach ($m in @(Get-RegSubKeys 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors')) {
        $v = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\$m"
        if (-not $v -or -not $v['Driver']) { continue }
        Add-Examined
        $dll = "$($v['Driver'])"; if ($dll -notmatch '[\\/]') { $dll = Join-Path $SysRoot "System32\$dll" }
        $s = Get-Sig $dll
        if ($s.Exists -and -not $s.Signed) {
            Add-Finding High $cat (L "Unsigned print monitor: $m" "Moniteur d'impression non signé : $m") `
                (L 'DLL loaded by the print spooler with SYSTEM rights.' 'DLL chargée par le spouleur avec les droits SYSTEM.') `
                (Ev @('driver', $dll) @('sig', (Format-Signer $s)))
        }
    }
    $ns = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\NetSh'
    if ($ns) {
        foreach ($n in $ns.Keys) {
            $dll = "$($ns[$n])"; if ($dll -notmatch '[\\/]') { $dll = Join-Path $SysRoot "System32\$dll" }
            $s = Get-Sig $dll
            Add-Examined
            if ($s.Exists -and -not $s.Microsoft) {
                Add-Finding Medium $cat (L "Third-party netsh helper: $n" "Assistant netsh tiers : $n") `
                    (L 'DLL loaded on every netsh run.' 'DLL chargée à chaque exécution de netsh.') `
                    (Ev @('dll', $dll) @('sig', (Format-Signer $s)))
            }
        }
    }
    # Per-user COM hijack
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
                $sev = if ($dll -match $WritableRegex) { 'High' } else { 'Medium' }
                Add-Finding $sev $cat `
                    (L "Unsigned per-user COM object ($($u.Name)): $clsid" "Composant COM utilisateur non signé ($($u.Name)) : $clsid") `
                    (L 'A DLL registered at user level takes precedence over the system component: COM hijacking.' 'Une DLL enregistrée au niveau utilisateur prend le pas sur le composant système : technique de détournement COM.') `
                    (Ev @('dll', $dll) @('sig', (Format-Signer $s)))
            }
        }
    }
    # Post-mortem debugger: started as SYSTEM every time a program crashes
    foreach ($k in "$nt\AeDebug", 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug') {
        $v = Get-RegValues $k
        Add-Examined
        if ($v -and $v['Debugger'] -and "$($v['Debugger'])" -notmatch '(?i)\\(vsjitdebugger|drwtsn32|windbg|vsdebugconsole)\.exe|WerFault') {
            Add-Finding High $cat `
                (L 'Non-standard crash debugger (AeDebug)' 'Débogueur de plantage non standard (AeDebug)') `
                (L 'This command runs whenever a program crashes, which an attacker can trigger on demand.' "Cette commande est lancée à chaque plantage d'un programme, ce qu'un attaquant peut provoquer à volonté.") `
                (Ev @('key', $k) @('command', $v['Debugger'])) `
                (L 'Keep only your debugger (Visual Studio, WinDbg) or delete the value.' 'Ne garder que votre débogueur (Visual Studio, WinDbg) ou supprimer la valeur.')
        }
    }
    # cmd.exe AutoRun: prepended to every command prompt that opens
    foreach ($u in $scopesReg) {
        $v = Get-RegValues "$($u.Root)\Software\Microsoft\Command Processor"
        Add-Examined
        if ($v -and "$($v['AutoRun'])".Trim()) {
            Add-Finding High $cat `
                (L "cmd.exe AutoRun defined ($($u.Name.en))" "AutoRun de cmd.exe défini ($($u.Name.fr))") `
                (L 'This command runs first in every cmd.exe session, including those started by scripts and installers.' "Cette commande est exécutée en premier dans chaque session cmd.exe, y compris celles lancées par des scripts et des installeurs.") `
                (Ev @('key', "$($u.Root)\Software\Microsoft\Command Processor") @('command', $v['AutoRun']))
        }
    }
    # File association and protocol handler hijacks
    $assoc = @{ 'exefile\shell\open\command' = '(?i)^"?%1"? ?%\*?$'
                'txtfile\shell\open\command' = '(?i)notepad\.exe|%SystemRoot%\\system32\\NOTEPAD\.EXE'
                'lnkfile\shell\open\command' = '(?i)^$'
                'mscfile\shell\open\command'  = '(?i)\\mmc\.exe'
                'ms-settings\shell\open\command' = '(?i)^$' }
    foreach ($u in $scopesReg) {
        foreach ($a in $assoc.Keys) {
            $v = Get-RegValues "$($u.Root)\Software\Classes\$a"
            if (-not $v -or -not $v['']) { continue }
            Add-Examined
            $cmd = "$($v[''])"
            if ($cmd -match $assoc[$a]) { continue }
            Add-Finding High $cat `
                (L "File type handler hijacked ($($u.Name.en)): $a" "Gestionnaire de type de fichier détourné ($($u.Name.fr)) : $a") `
                (L 'Opening this kind of file or link runs the command below. ms-settings and mscfile are the classic UAC bypass pair.' "Ouvrir ce type de fichier ou de lien exécute la commande ci-dessous. ms-settings et mscfile sont le duo classique de contournement de l'UAC.") `
                (Ev @('key', "$($u.Root)\Software\Classes\$a") @('command', $cmd)) `
                (L 'Compare with a healthy host and restore the original command.' "Comparer avec un poste sain et rétablir la commande d'origine.")
        }
    }
    # Service recovery actions: a command run by the SCM, as SYSTEM, when a service fails.
    # Windows and several vendors (NVIDIA, iSCSI) use this legitimately, so only report a command
    # that points somewhere a user can write, runs an unsigned binary, or carries a suspicious pattern.
    foreach ($s in $script:Services) {
        $v = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
        if (-not $v -or -not $v['FailureCommand']) { continue }
        Add-Examined
        $fc = "$($v['FailureCommand'])".Trim()
        if (-not $fc -or $fc -match '^(?i)(not used|customscript\.cmd|%1 %2 %3)$') { continue }   # Windows placeholders
        $strong = $false
        foreach ($r in $StrongCmd) { if ($fc -match $r.R) { $strong = $true } }
        $exe = Resolve-ExePath $fc
        $sg = Get-Sig $exe
        $target = ($fc -match '(?i)[A-Z]:\\(Users|ProgramData|Windows\\Temp)\\[^"]*\.(exe|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta)\b')
        if (-not ($strong -or $target -or ($exe -match $WritableRegex) -or ($sg.Exists -and -not $sg.Signed))) { continue }
        Add-Finding High $cat `
            (L "Service recovery command: $($s.Name)" "Commande de récupération de service : $($s.Name)") `
            (L 'The SCM runs this command when the service fails, as SYSTEM, and a service can be made to fail on demand.' "Le gestionnaire de services exécute cette commande lorsque le service échoue, en tant que SYSTEM, et un service peut être mis en échec à volonté.") `
            (Ev @('service', $s.Name) @('command', $fc) @('binary', $exe) @('sig', (Format-Signer $sg))) `
            (L 'Check what the command does (sc qfailure <service>).' 'Vérifier ce que fait la commande (sc qfailure <service>).')
    }
    # KnownDLLs: the list of system libraries Windows loads from a fixed location. Almost never
    # changed legitimately, and an added entry hijacks that library in every process.
    $kd = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
    Add-Examined
    if ($kd) {
        foreach ($n in $kd.Keys) {
            $val = "$($kd[$n])"
            if (-not $val) { continue }
            if ($n -eq 'DllDirectory' -or $n -eq 'DllDirectory32') {
                if ($val -match '(?i)^%SystemRoot%\\(System32|SysWOW64)$') { continue }
                Add-Finding Critical $cat `
                    (L "KnownDLLs search folder changed: $n" "Dossier de recherche KnownDLLs modifié : $n") `
                    (L 'Windows would load its core libraries from this folder, in every process on the machine.' "Windows chargerait ses bibliothèques fondamentales depuis ce dossier, dans tous les processus de la machine.") `
                    (Ev @('key', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs') @('value', "$n = $val")) `
                    (L 'Restore %SystemRoot%\System32 (or SysWOW64) and treat the host as compromised.' 'Rétablir %SystemRoot%\System32 (ou SysWOW64) et considérer le poste comme compromis.')
                continue
            }
            if ($val -notmatch '(?i)^[\w.+-]+\.dll$') {
                Add-Finding Critical $cat `
                    (L "KnownDLLs entry with a path: $n" "Entrée KnownDLLs avec un chemin : $n") `
                    (L 'These entries hold a bare file name. A path here redirects a system library everywhere.' "Ces entrées ne contiennent qu'un nom de fichier. Un chemin ici détourne une bibliothèque système partout.") `
                    (Ev @('value', "$n = $val")) `
                    (L 'Compare with a healthy host of the same build and restore the value.' 'Comparer avec un poste sain de la même version et rétablir la valeur.')
                continue
            }
            $p = Join-Path $SysRoot "System32\$val"
            $s2 = Get-Sig $p
            if ($s2.Exists -and -not $s2.Signed -and -not $s2.MsClaim) {
                Add-Finding Critical $cat `
                    (L "KnownDLLs library unsigned: $val" "Bibliothèque KnownDLLs non signée : $val") `
                    (L 'A library loaded into every process on the machine carries no valid signature.' "Une bibliothèque chargée dans tous les processus de la machine ne porte aucune signature valide.") `
                    (Ev @('file', $p) @('sig', (Format-Signer $s2))) $AdvRestore
            }
        }
    }
    # Shell extension handlers: DLLs explorer.exe loads into itself
    $shellKeys = @(
        @{ K = 'Software\Classes\*\ShellEx\ContextMenuHandlers';                  N = L 'context menu handler' 'gestionnaire de menu contextuel' }
        @{ K = 'Software\Classes\Directory\ShellEx\ContextMenuHandlers';          N = L 'folder context menu handler' 'gestionnaire de menu contextuel de dossier' }
        @{ K = 'Software\Classes\Directory\Background\ShellEx\ContextMenuHandlers'; N = L 'desktop context menu handler' 'gestionnaire de menu contextuel du bureau' }
        @{ K = 'Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'; N = L 'icon overlay handler' "gestionnaire de superposition d'icônes" }
        @{ K = 'Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'; N = L 'shell service object' 'objet de service du shell' }
        @{ K = 'Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'; N = L 'shared task scheduler entry' 'entrée du planificateur partagé' }
        @{ K = 'Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'; N = L 'delay-loaded shell object' 'objet du shell à chargement différé' }
    )
    foreach ($u in $scopesReg) {
        foreach ($sk in $shellKeys) {
            $base = "$($u.Root)\$($sk.K)"
            # Some of these keys hold the CLSIDs as subkeys, others as values
            $clsids = @()
            foreach ($k in @(Get-RegSubKeys $base)) {
                $rv = Get-RegValues "$base\$k"
                if ($rv) { $clsids += "$($rv[''])" }
                if ($k -match '^\{[0-9A-Fa-f-]{36}\}$') { $clsids += $k }
            }
            $direct = Get-RegValues $base
            if ($direct) { foreach ($n in $direct.Keys) { $clsids += "$($direct[$n])" } }
            foreach ($clsid in @($clsids | Where-Object { "$_" -match '^\{[0-9A-Fa-f-]{36}\}$' } | Select-Object -Unique)) {
                Add-Examined
                $reg = $null
                foreach ($root in "$($u.Root)\Software\Classes\CLSID\$clsid\InprocServer32", "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32", "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$clsid\InprocServer32") {
                    $rv = Get-RegValues $root
                    if ($rv -and $rv['']) { $reg = $rv; break }
                }
                if (-not $reg) { continue }
                $dll = [Environment]::ExpandEnvironmentVariables(("$($reg[''])" -replace '"', ''))
                $s3 = Get-Sig $dll
                if (-not $s3.Exists -or $s3.Signed) { continue }
                $sev = if ($dll -match $WritableRegex) { 'High' } else { 'Medium' }
                Add-Finding $sev $cat `
                    (L "Unsigned $($sk.N.en) ($($u.Name.en)): $clsid" "$($sk.N.fr) non signé ($($u.Name.fr)) : $clsid") `
                    (L 'explorer.exe loads this DLL into itself, so it runs in every session as the user.' "explorer.exe charge cette DLL dans son propre processus : elle s'exécute à chaque session sous l'identité de l'utilisateur.") `
                    (Ev @('key', $base) @('dll', $dll) @('sig', (Format-Signer $s3))) `
                    (L 'Identify the software that registered it, or unregister the handler.' "Identifier le logiciel qui l'a enregistré, ou désinscrire le gestionnaire.")
            }
        }
    }
}

function Check-Office {
    $cat = 'Office'
    $scopesOffice = @(Get-RegScopes)
    foreach ($u in $script:Users) {
        if ($u.RegRoot) {
            foreach ($ver in '16.0', '15.0', '14.0') {
                foreach ($app in 'Word', 'Excel', 'PowerPoint', 'Access', 'Outlook') {
                    $sec = "$($u.RegRoot)\Software\Microsoft\Office\$ver\$app\Security"
                    $v = Get-RegValues $sec
                    Add-Examined
                    if ($v) {
                        if ("$($v['VBAWarnings'])" -eq '1') {
                            Add-Finding Medium $cat `
                                (L "$app ${ver}: all macros are enabled ($($u.Name))" "$app $ver : toutes les macros sont activées ($($u.Name))") `
                                (L 'A booby-trapped document runs without any warning.' "Un document piégé s'exécute sans avertissement.") "$sec\VBAWarnings = 1" `
                                (L "Set it back to 'Disable all macros with notification'." 'Remettre « Désactiver toutes les macros avec notification ».')
                        }
                        if ("$($v['AccessVBOM'])" -eq '1') {
                            Add-Finding Medium $cat `
                                (L "$app ${ver}: access to the VBA object model allowed ($($u.Name))" "$app $ver : accès au modèle objet VBA autorisé ($($u.Name))") `
                                (L 'Lets a macro modify other macros.' "Permet à une macro de modifier d'autres macros.") "$sec\AccessVBOM = 1"
                        }
                    }
                    foreach ($loc in @(Get-RegSubKeys "$sec\Trusted Locations")) {
                        $tl = Get-RegValues "$sec\Trusted Locations\$loc"
                        if (-not $tl -or -not $tl['Path']) { continue }
                        $path = "$($tl['Path'])"
                        if ($path -match '(?i)^\\\\|^https?:|\\(Temp|Tmp|Downloads|Desktop)(\\|$)' -or $path -match '^(?i)[A-Z]:\\?$') {
                            Add-Finding Medium $cat `
                                (L "$app ${ver}: risky trusted location ($($u.Name))" "$app $ver : emplacement approuvé risqué ($($u.Name))") `
                                (L 'Files opened from a trusted location run their macros without warning.' "Les fichiers ouverts depuis un emplacement approuvé exécutent leurs macros sans avertissement.") `
                                (Ev @('path', $path) @('subfolders', $tl['AllowSubFolders']))
                        }
                    }
                }
            }
        }
        # Office startup folders
        foreach ($d in 'AppData\Roaming\Microsoft\Word\STARTUP', 'AppData\Roaming\Microsoft\Excel\XLSTART', 'AppData\Roaming\Microsoft\AddIns') {
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $u.Profile $d) -File -Force)) {
                Add-Examined
                $sev = if ($f.CreationTime -ge $Since) { 'Medium' } else { 'Info' }
                Add-Finding $sev $cat `
                    (L "File loaded at Office startup ($($u.Name)): $($f.Name)" "Fichier chargé au démarrage d'Office ($($u.Name)) : $($f.Name)") `
                    (L 'Template or add-in opened automatically, macros included.' 'Modèle ou complément ouvert automatiquement, macros comprises.') `
                    (Ev @('file', $f.FullName) @('created', (Format-When $f.CreationTime))) `
                    (L 'Confirm this add-in is known.' 'Vérifier que ce complément est connu.') `
                    -Fix "Remove-Item -LiteralPath '$($f.FullName)'"
            }
        }
    }
    # --- COM and VSTO add-ins declared in the registry (loaded by Office itself, not a folder)
    $apps = 'Word', 'Excel', 'PowerPoint', 'Outlook', 'Access', 'Publisher', 'Visio', 'Project', 'OneNote'
    $behave = @{ '0' = L 'disconnected' 'déconnecté'; '1' = L 'loaded once' 'chargé une fois'
                 '2' = L 'load on demand' 'chargé à la demande'; '3' = L 'loaded at startup' 'chargé au démarrage'
                 '8' = L 'load on demand (connected)' 'à la demande (connecté)'; '9' = L 'load on demand' 'chargé à la demande'
                 '16' = L 'loaded at startup, first time only' 'chargé au démarrage, la première fois' }
    foreach ($u in $scopesOffice) {
        foreach ($app in $apps) {
            foreach ($base in "$($u.Root)\Software\Microsoft\Office\$app\Addins", "$($u.Root)\Software\WOW6432Node\Microsoft\Office\$app\Addins") {
                foreach ($prog in @(Get-RegSubKeys $base)) {
                    $v = Get-RegValues "$base\$prog"
                    if (-not $v) { continue }
                    Add-Examined
                    $lb = "$($v['LoadBehavior'])"
                    # Resolve the DLL or the VSTO manifest behind the ProgID
                    $file = ''
                    if ($v['Manifest']) { $file = "$($v['Manifest'])" -replace '\|vstolocal$', '' }
                    if (-not $file) {
                        foreach ($cls in "$($u.Root)\Software\Classes\$prog\CLSID", "HKLM:\SOFTWARE\Classes\$prog\CLSID") {
                            $cv = Get-RegValues $cls
                            if (-not $cv -or -not $cv['']) { continue }
                            foreach ($ips in "$($u.Root)\Software\Classes\CLSID\$($cv[''])\InprocServer32", "HKLM:\SOFTWARE\Classes\CLSID\$($cv[''])\InprocServer32", "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$($cv[''])\InprocServer32") {
                                $iv = Get-RegValues $ips
                                if ($iv -and $iv['']) { $file = "$($iv[''])" -replace '"', ''; break }
                            }
                            if ($file) { break }
                        }
                    }
                    $file = [Environment]::ExpandEnvironmentVariables($file)
                    $local = ($file -notmatch '^(?i)https?://')
                    $sg = if ($local) { Get-Sig $file } else { $null }
                    $loaded = ($lb -eq '3' -or $lb -eq '16')
                    $sev = 'Info'
                    $why = L 'Add-in declared for this Office application.' "Complément déclaré pour cette application Office."
                    if ($sg -and $sg.Exists -and -not $sg.Signed) {
                        $sev = if ($file -match $WritableRegex) { 'High' } else { 'Medium' }
                        $why = L 'The add-in library carries no valid signature: Office would run it inside the application.' "La bibliothèque du complément ne porte aucune signature valide : Office l'exécuterait dans l'application."
                    }
                    elseif ($file -match $WritableRegex -and $loaded) {
                        $sev = 'Medium'
                        $why = L 'Loaded at startup from a folder the user can write to.' "Chargé au démarrage depuis un dossier modifiable par l'utilisateur."
                    }
                    elseif (-not $local) {
                        $sev = 'Medium'
                        $why = L 'The add-in manifest is fetched over the network at startup.' 'Le manifeste du complément est récupéré sur le réseau au démarrage.'
                    }
                    elseif ($sg -and $sg.Microsoft) { continue }      # Microsoft add-in, nothing to say
                    $lbl = Loc $(if ($behave[$lb]) { $behave[$lb] } else { L "LoadBehavior $lb" "LoadBehavior $lb" })
                    Add-Finding $sev $cat `
                        (L "$app add-in ($($u.Name.en)): $prog" "Complément $app ($($u.Name.fr)) : $prog") $why `
                        (Ev @('key', "$base\$prog") @('value', "$($v['FriendlyName'])") @('dll', $file) `
                            @('state', "LoadBehavior = $lb ($($lbl.en))") @('sig', $(if ($sg) { Format-Signer $sg } else { '' }))) `
                        $(if ($sev -ne 'Info') { L 'Disable the add-in (LoadBehavior = 0) and identify the software that registered it.' 'Désactiver le complément (LoadBehavior = 0) et identifier le logiciel qui l''a enregistré.' }) `
                        -Fix $(if ($sev -ne 'Info') { "Set-ItemProperty -LiteralPath '$($base -replace '^Registry::', '')\$prog' -Name LoadBehavior -Value 0" })
                }
            }
        }
    }
    # --- Outlook: rules that run a program, custom forms, home page on a folder
    foreach ($u in $scopesOffice) {
        foreach ($ver in '16.0', '15.0') {
            $ol = "$($u.Root)\Software\Microsoft\Office\$ver\Outlook"
            $v = Get-RegValues $ol
            if ($v) {
                Add-Examined
                if ("$($v['EnableRoamingFolderHomepages'])" -eq '1' -or "$($v['EnableUnsafeClientMailRules'])" -eq '1') {
                    Add-Finding High $cat `
                        (L "Outlook: unsafe client rules allowed ($($u.Name.en))" "Outlook : règles clientes dangereuses autorisées ($($u.Name.fr))") `
                        (L 'These settings let a mailbox rule start an application or load a folder home page: remote code execution from an e-mail.' "Ces réglages permettent à une règle de boîte aux lettres de lancer une application ou de charger une page d'accueil de dossier : exécution de code à distance depuis un courriel.") `
                        (Ev @('key', $ol) @('values', "EnableUnsafeClientMailRules = $($v['EnableUnsafeClientMailRules']) ; EnableRoamingFolderHomepages = $($v['EnableRoamingFolderHomepages'])")) `
                        (L 'Remove these values and review the mailbox rules in Outlook.' 'Supprimer ces valeurs et relire les règles de la boîte aux lettres dans Outlook.')
                }
            }
            # WebView / home page set on a mail folder
            foreach ($k in @(Get-RegSubKeys "$ol\WebView")) {
                $wv = Get-RegValues "$ol\WebView\$k"
                if (-not $wv -or -not $wv['URL']) { continue }
                Add-Examined
                Add-Finding High $cat `
                    (L "Outlook: home page set on the $k folder ($($u.Name.en))" "Outlook : page d'accueil définie sur le dossier $k ($($u.Name.fr))") `
                    (L 'Outlook loads this page every time the folder is opened, inside the mail client.' "Outlook charge cette page à chaque ouverture du dossier, dans le client de messagerie.") `
                    (Ev @('key', "$ol\WebView\$k") @('value', $wv['URL'])) `
                    (L 'Remove the home page from the folder properties.' "Retirer la page d'accueil dans les propriétés du dossier.")
            }
            # Custom form servers and startup items
            foreach ($n in 'Forms', 'Addins') {
                $fk = Get-RegValues "$ol\$n"
                if ($fk -and $fk.Count) {
                    Add-Examined
                    Add-Finding Info $cat `
                        (L "Outlook $n entries ($($u.Name.en))" "Entrées Outlook $n ($($u.Name.fr))") '' `
                        (($fk.Keys | ForEach-Object { "$_ = $($fk[$_])" }) -join "`n")
                }
            }
        }
    }
    # --- Outlook macro project, per user profile
    foreach ($u in $script:Users) {
        $p = Join-Path $u.Profile 'AppData\Roaming\Microsoft\Outlook\VbaProject.OTM'
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        Add-Examined
        $i = Get-Item -LiteralPath $p -Force
        $sev = if ($i.LastWriteTime -ge $Since) { 'Medium' } else { 'Info' }
        Add-Finding $sev $cat `
            (L "Outlook macro project present ($($u.Name))" "Projet de macros Outlook présent ($($u.Name))") `
            (L 'Outlook macros run in the mail client and can act on every message. Rare outside automated setups.' "Les macros Outlook s'exécutent dans le client de messagerie et peuvent agir sur tous les messages. Rare hors automatisation voulue.") `
            (Ev @('file', $p) @('modified', (Format-When $i.LastWriteTime)) @('size', (L "$($i.Length) bytes" "$($i.Length) octets"))) `
            $(if ($sev -eq 'Medium') { L 'Open the VBA editor in Outlook and read the project.' "Ouvrir l'éditeur VBA d'Outlook et lire le projet." })
        if ($sev -eq 'Medium') { Add-Timeline $i.LastWriteTime (L "Outlook macro project modified ($($u.Name))" "Projet de macros Outlook modifié ($($u.Name))") 'Medium' }
    }
}

function Check-Accounts {
    $cat = 'Accounts'
    foreach ($a in @(Get-LocalUsersData)) {
        Add-Examined
        if ($a.Name -match '\$$') {
            Add-Finding High $cat `
                (L "Local account hidden with a trailing '`$': $($a.Name)" "Compte local masqué par un « `$ » final : $($a.Name)") `
                (L 'Convention used to hide an account from the administration tools.' "Convention utilisée pour cacher un compte dans les outils d'administration.") `
                (Ev @('sid', $a.SID) @('enabled', $a.Enabled))
        }
        elseif ($a.Enabled -and $a.SID -match '-501$') {
            Add-Finding Medium $cat (L "Guest account enabled: $($a.Name)" "Compte Invité activé : $($a.Name)") `
                (L 'Disabled by default.' 'Désactivé par défaut.') (Ev @('sid', $a.SID))
        }
        elseif ($a.Enabled) {
            Add-Finding Info $cat (L "Enabled local account: $($a.Name)" "Compte local actif : $($a.Name)") '' `
                (Ev @('lastlogon', (Format-When $a.LastLogon)) @('pwdset', (Format-When $a.PasswordLastSet)))
        }
    }
    $adm = @(Get-LocalAdmins)
    if ($adm.Count) {
        Add-Finding Info $cat (L "Members of the Administrators group ($($adm.Count))" "Membres du groupe Administrateurs ($($adm.Count))") `
            (L 'Worth re-reading: any unexpected account is a strong signal.' 'À relire : tout compte inattendu est un signal fort.') ($adm -join "`n")
    }
    $hidden = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if ($hidden) {
        foreach ($n in $hidden.Keys) {
            if ("$($hidden[$n])" -eq '0') {
                Add-Finding High $cat (L "Account hidden from the logon screen: $n" "Compte masqué de l'écran de connexion : $n") `
                    (L 'Technique used to conceal an account created by an attacker.' 'Technique utilisée pour dissimuler un compte créé par un attaquant.') `
                    'Winlogon\SpecialAccounts\UserList'
            }
        }
    }
}

function Check-RemoteAccess {
    $cat = 'RemoteAccess'
    $ts = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Add-Examined
    if ($ts -and "$($ts['fDenyTSConnections'])" -eq '0') {
        Add-Finding Info $cat (L 'Remote Desktop (RDP) enabled' 'Bureau à distance (RDP) activé') `
            (L 'Fine if intended; make sure it is not exposed to the internet.' "Normal si voulu ; vérifier qu'il n'est pas exposé sur Internet.") 'fDenyTSConnections = 0'
    }
    $sshd = $script:Services | Where-Object { $_.Name -eq 'sshd' }
    if ($sshd) {
        Add-Finding Medium $cat (L 'OpenSSH server installed' 'Serveur OpenSSH installé') `
            (L 'Rare on a workstation. Recent backdoors (the booby-trapped Claude Code extension) rely on it.' "Rare sur un poste de travail. Les portes dérobées récentes (extension Claude Code piégée) s'appuient dessus.") `
            (Ev @('state', "$($sshd.State) / $($sshd.StartMode)")) (L 'Uninstall it if it is not wanted.' "Désinstaller s'il n'est pas voulu.")
    }
    $keys = @("$PData\ssh\administrators_authorized_keys")
    foreach ($u in $script:Users) { $keys += (Join-Path $u.Profile '.ssh\authorized_keys') }
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        Add-Examined
        $i = Get-Item -LiteralPath $k -Force
        $lines = @(Get-Content -LiteralPath $k | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' })
        $sev = if ($i.LastWriteTime -ge $Since) { 'High' } else { 'Medium' }
        $list = ($lines | ForEach-Object { $p = $_ -split '\s+'; "  $($p[0]) $([char]0x2026)$("$($p[1])".PadLeft(12).Substring([math]::Max(0, "$($p[1])".Length - 12))) $($p[2])" }) -join "`n"
        Add-Finding $sev $cat `
            (L "Authorised SSH keys: $k" "Clés SSH autorisées : $k") `
            (L "$($lines.Count) key(s) allow a password-less logon$(if ($sev -eq 'High') { '; file modified recently' })." "$($lines.Count) clé(s) permettent une connexion sans mot de passe$(if ($sev -eq 'High') { ' ; fichier modifié récemment' }).") `
            (Ev @('modified', (Format-When $i.LastWriteTime)) $list) `
            (L 'Check that every key is known.' 'Vérifier que chaque clé est connue.')
        if ($sev -eq 'High') { Add-Timeline $i.LastWriteTime (L "SSH authorized_keys modified: $k" "authorized_keys SSH modifié : $k") 'High' }
    }
    $seen = @{}
    foreach ($s in $script:Services) {
        if ("$($s.Name) $($s.DisplayName) $($s.PathName)" -match $IOC.RemoteToolsRegex) {
            $seen[$Matches[0].ToLower()] = L "service $($s.Name) ($($s.State))" "service $($s.Name) ($($s.State))"
        }
    }
    foreach ($p in $script:Processes) {
        if ("$($p.Name) $($p.ExecutablePath)" -match $IOC.RemoteToolsRegex -and -not $seen[$Matches[0].ToLower()]) {
            $seen[$Matches[0].ToLower()] = L "process $($p.Name) (PID $($p.ProcessId))" "processus $($p.Name) (PID $($p.ProcessId))"
        }
    }
    foreach ($k in $seen.Keys) {
        Add-Finding Medium $cat (L "Remote access tool present: $k" "Outil d'accès à distance présent : $k") `
            (L 'A legitimate tool, but also the takeover route most used by attackers and fake tech support.' "Outil légitime, mais aussi le moyen de prise de contrôle le plus utilisé par les attaquants et les faux supports techniques.") `
            (Ev $seen[$k]) (L 'Confirm it was installed on purpose.' "Confirmer qu'il a été installé volontairement.")
    }
    # WinRM: remote PowerShell. Normal on a server, unusual on a workstation.
    $winrm = $script:Services | Where-Object { $_.Name -eq 'WinRM' -and $_.State -eq 'Running' }
    $wcli = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    Add-Examined
    if ($winrm) {
        Add-Finding Info $cat (L 'WinRM running (remote PowerShell)' 'WinRM actif (PowerShell à distance)') `
            (L 'Normal if remote administration is used; gives full command execution to anyone who can authenticate.' "Normal si l'administration à distance est utilisée ; donne l'exécution de commandes à quiconque peut s'authentifier.") `
            (Ev @('state', "$($winrm.State) / $($winrm.StartMode)"))
    }
    if ($wcli -and ("$($wcli['AllowUnencryptedTraffic'])" -eq '1' -or "$($wcli['AllowBasic'])" -eq '1')) {
        Add-Finding High $cat (L 'WinRM accepting unencrypted or Basic authentication' 'WinRM accepte le trafic non chiffré ou l''authentification Basic') `
            (L 'Credentials and commands travel in clear text and can be replayed.' "Les identifiants et les commandes circulent en clair et peuvent être rejoués.") `
            (Ev @('key', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') `
                @('values', "AllowUnencryptedTraffic = $($wcli['AllowUnencryptedTraffic']) ; AllowBasic = $($wcli['AllowBasic'])")) `
            (L 'Remove these policies and keep WinRM over HTTPS with Kerberos or certificates.' 'Supprimer ces stratégies et conserver WinRM en HTTPS avec Kerberos ou certificats.')
    }
    $pp = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
    if ($pp -and $pp.Count) {
        Add-Finding Medium $cat (L 'Port forwarding (netsh portproxy)' 'Redirection de ports (netsh portproxy)') `
            (L 'Relays connections to another machine. Used by WSL and some tools, but also to pivot.' "Relaie des connexions vers une autre machine. Utilisé par WSL et certains outils, mais aussi pour pivoter.") `
            (($pp.Keys | ForEach-Object { "$_ -> $($pp[$_])" }) -join "`n")
    }
}

function Check-Defender {
    $cat = 'Defender'
    $d = Get-DefenderData
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') {
        $v = Get-RegValues $k
        Add-Examined
        if ($v) {
            foreach ($n in 'DisableAntiSpyware', 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection') {
                if ("$($v[$n])" -eq '1') {
                    Add-Finding High $cat (L "Protection disabled by policy: $n" "Protection désactivée par stratégie : $n") `
                        (L "Value often written by malware or by a 'debloat' tool." "Valeur souvent posée par un malware ou un outil de « débridage ».") "$k\$n = 1"
                }
            }
        }
    }
    if (-not $d) { Add-Note (L 'Microsoft Defender status unreadable (module missing or another antivirus).' 'État de Microsoft Defender illisible (module absent ou autre antivirus).'); return }
    $other = @($d.OtherAV | Where-Object { $_ -and $_ -notmatch '(?i)defender' })
    if ($other.Count) {
        Add-Finding Info $cat (L "Third-party antivirus registered: $($other -join ', ')" "Antivirus tiers déclaré : $($other -join ', ')") `
            (L 'Defender then switches to passive mode: inactive real-time protection is normal.' "Defender se met alors en mode passif : une protection en temps réel inactive est normale.") ''
    }
    Add-Examined 2
    if (-not $d.Status.RealTimeProtectionEnabled -and -not $other.Count) {
        Add-Finding High $cat (L 'Real-time protection disabled' 'Protection en temps réel désactivée') `
            (L 'No other antivirus is registered.' "Aucun autre antivirus n'est déclaré.") `
            (Ev @('values', "AntivirusEnabled = $($d.Status.AntivirusEnabled) ; RealTimeProtectionEnabled = $($d.Status.RealTimeProtectionEnabled)")) `
            (L 'Turn the protection back on and find what switched it off.' "Réactiver la protection et chercher ce qui l'a coupée.")
    }
    if ($d.Status.PSObject.Properties['IsTamperProtected'] -and -not $d.Status.IsTamperProtected -and -not $other.Count) {
        Add-Finding Medium $cat (L 'Tamper protection disabled' 'Protection contre les falsifications désactivée') `
            (L 'It prevents a program from switching the antivirus off.' "Elle empêche un programme de couper l'antivirus.") ''
    }
    if ($d.Status.AntivirusSignatureLastUpdated -and $d.Status.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-14) -and -not $other.Count) {
        Add-Finding Medium $cat (L 'Antivirus signatures are old' 'Signatures antivirus anciennes') '' `
            (Ev @('modified', (Format-When $d.Status.AntivirusSignatureLastUpdated)))
    }
    # Layers switched off one by one rather than disabling the antivirus outright
    $layers = @(
        @{ P = 'DisableScriptScanning'; On = $true;  T = L 'Script scanning disabled' 'Analyse des scripts désactivée'
           W = L 'PowerShell, VBScript and JScript are no longer inspected: the favourite route of activators and droppers.' "PowerShell, VBScript et JScript ne sont plus inspectés : la voie préférée des activateurs et des droppers." }
        @{ P = 'DisableArchiveScanning'; On = $true; T = L 'Archive scanning disabled' 'Analyse des archives désactivée'
           W = L 'Content of ZIP, RAR and 7z files is no longer inspected.' "Le contenu des ZIP, RAR et 7z n'est plus inspecté." }
        @{ P = 'DisableBlockAtFirstSeen'; On = $true; T = L 'Block at first sight disabled' "Blocage à la première détection désactivé"
           W = L 'Unknown files are no longer held back for cloud analysis.' "Les fichiers inconnus ne sont plus retenus pour analyse dans le cloud." }
        @{ P = 'DisableRealtimeMonitoring'; On = $true; T = L 'Real-time monitoring disabled in the preferences' 'Analyse en temps réel désactivée dans les préférences'
           W = L 'Set through Set-MpPreference rather than the interface.' "Réglage posé via Set-MpPreference plutôt que par l'interface." }
    )
    foreach ($l in $layers) {
        if (-not $d.Prefs.PSObject.Properties[$l.P]) { continue }
        Add-Examined
        if ([bool]$d.Prefs.($l.P) -eq $l.On -and -not $other.Count) {
            Add-Finding High $cat $l.T $l.W "$($l.P) = $($d.Prefs.($l.P))" `
                (L 'Turn the layer back on (Set-MpPreference) and find what switched it off.' "Réactiver la protection (Set-MpPreference) et chercher ce qui l'a coupée.")
        }
    }
    if ($d.Prefs.PSObject.Properties['MAPSReporting'] -and "$($d.Prefs.MAPSReporting)" -eq '0' -and -not $other.Count) {
        Add-Examined
        Add-Finding Medium $cat (L 'Cloud-delivered protection disabled (MAPS)' 'Protection par le cloud désactivée (MAPS)') `
            (L 'Without it Defender only relies on local signatures and misses most recent threats.' "Sans elle, Defender ne s'appuie que sur ses signatures locales et manque la plupart des menaces récentes.") `
            'MAPSReporting = 0'
    }
    if ($d.Prefs.PSObject.Properties['PUAProtection'] -and "$($d.Prefs.PUAProtection)" -eq '0') {
        Add-Examined
        Add-Finding Info $cat (L 'Unwanted software protection (PUA) disabled' 'Protection contre les logiciels indésirables (PUA) désactivée') `
            (L 'PUA detection is what flags activators, adware and bundled toolbars.' "La détection PUA est ce qui signale les activateurs, les adwares et les barres d'outils groupées.") `
            'PUAProtection = 0' (L 'Enable it: Set-MpPreference -PUAProtection Enabled.' 'Activer : Set-MpPreference -PUAProtection Enabled.')
    }
    # Exclusions
    $broad = '(?i)^[A-Z]:\\?$|^[A-Z]:\\(Users|Windows|ProgramData)\\?$|\\AppData\\?$|\\Temp\\?$|\\Downloads\\?$|^\*|^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr)$|powershell|cmd\.exe|wscript|mshta|rundll32'
    foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
        foreach ($e in @($d.Prefs.$kind)) {
            if (-not $e) { continue }
            if ("$e" -match 'N/A:') { Add-Note (L 'Defender exclusions unreadable without administrator rights.' 'Exclusions Defender illisibles sans droits administrateur.'); break }
            Add-Examined
            if ("$e" -match $IOC.ActivatorRegex) {
                Add-Finding High 'Activators' (L "Antivirus exclusion for an activator: $e" "Exclusion antivirus pour un activateur : $e") `
                    (L 'Activators ask for their files to be excluded from scanning.' "Les activateurs demandent d'exclure leurs fichiers de l'analyse.") "$kind = $e"
            }
            elseif ("$e" -match $broad) {
                Add-Finding High $cat (L "Very broad antivirus exclusion: $e" "Exclusion antivirus très large : $e") `
                    (L 'Everything in there escapes the antivirus.' "Tout ce qui se trouve ici échappe à l'antivirus.") "$kind = $e" `
                    (L 'Remove the exclusion unless it is documented.' "Supprimer l'exclusion sauf justification documentée.")
            }
            else {
                Add-Finding Medium $cat (L "Antivirus exclusion: $e" "Exclusion antivirus : $e") `
                    (L 'To be justified: malware often adds itself to the exclusions.' "À justifier : les malwares s'ajoutent souvent eux-mêmes aux exclusions.") "$kind = $e"
            }
        }
    }
    # Detection history
    $names = @{}
    foreach ($t in $d.Threats) { $names["$($t.ThreatID)"] = "$($t.ThreatName)" }
    foreach ($x in $d.Detections) {
        Add-Examined
        $n = $names["$($x.ThreatID)"]; if (-not $n) { $n = "threat $($x.ThreatID)" }
        $isAct = ("$n $($x.Resources -join ' ')" -match $IOC.ActivatorThreatRegex) -or ("$($x.Resources -join ' ')" -match $IOC.ActivatorRegex)
        $c2 = if ($isAct) { 'Activators' } else { $cat }
        $sev = if ($isAct -or $x.InitialDetectionTime -ge $Since) { 'High' } else { 'Medium' }
        Add-Finding $sev $c2 `
            (L "Antivirus detection: $n" "Détection antivirus : $n") `
            (L "Detected on $(Format-When $x.InitialDetectionTime)$(if (-not $x.ActionSuccess) { '; remediation did NOT succeed' })." "Détectée le $(Format-When $x.InitialDetectionTime)$(if (-not $x.ActionSuccess) { ' ; action corrective NON aboutie' }).") `
            (Ev @('process', $x.ProcessName) (@($x.Resources | Select-Object -First 6) -join "`n")) `
            (L 'Confirm the file was really removed and understand how it got there.' 'Vérifier que le fichier a bien été supprimé et comprendre comment il est arrivé.')
        Add-Timeline $x.InitialDetectionTime (L "Antivirus detection: $n" "Détection antivirus : $n") $sev
    }
}

function Check-Network {
    $cat = 'Network'
    $hostsFile = "$SysRoot\System32\drivers\etc\hosts"
    $entries = @(Get-Content -LiteralPath $hostsFile | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
    Add-Examined $entries.Count
    $lic = @(); $sec = @(); $other = @()
    foreach ($e in $entries) {
        $names = @(($e -split '\s+') | Select-Object -Skip 1)
        if ($names | Where-Object { $IOC.LicensingHosts -contains $_.ToLower() }) { $lic += $e }
        elseif ($e -match $IOC.SecurityHostsRegex) { $sec += $e }
        elseif ($e -notmatch '^(127\.0\.0\.1|::1)\s+localhost$') { $other += $e }
    }
    if ($lic.Count) {
        Add-Finding High 'Activators' `
            (L "Microsoft licensing domains redirected in the hosts file ($($lic.Count))" "Domaines de licence Microsoft redirigés dans le fichier hosts ($($lic.Count))") `
            (L 'Deliberate blocking of the activation or subscription check servers, typical of activators.' "Blocage volontaire des serveurs d'activation ou de vérification d'abonnement, typique des activateurs.") `
            ($lic -join "`n") $AdvHosts
    }
    if ($sec.Count) {
        Add-Finding High $cat `
            (L "Security or update domains redirected in the hosts file ($($sec.Count))" "Domaines de sécurité ou de mise à jour redirigés dans le fichier hosts ($($sec.Count))") `
            (L 'Stops Windows Update or the antivirus from reaching its servers.' "Empêche les mises à jour ou l'antivirus de joindre ses serveurs.") `
            ($sec -join "`n") `
            (L 'Remove these lines and find what added them.' 'Retirer ces lignes et chercher ce qui les a ajoutées.')
    }
    if ($other.Count) {
        Add-Finding Info $cat (L "Other hosts file entries ($($other.Count))" "Autres entrées du fichier hosts ($($other.Count))") '' `
            (($other | Select-Object -First 40) -join "`n")
    }
    # Firewall
    foreach ($p in 'DomainProfile', 'StandardProfile', 'PublicProfile') {
        $v = Get-RegValues "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p"
        Add-Examined
        if ($v -and "$($v['EnableFirewall'])" -eq '0') {
            Add-Finding Medium $cat (L "Windows Firewall disabled ($p)" "Pare-feu Windows désactivé ($p)") `
                (L 'Normal only if a third-party firewall replaces it.' "Normal seulement si un pare-feu tiers le remplace.") 'EnableFirewall = 0'
        }
    }
    # Per-user proxy
    foreach ($u in $script:Users) {
        if (-not $u.RegRoot) { continue }
        $v = Get-RegValues "$($u.RegRoot)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Add-Examined
        if (-not $v) { continue }
        $sev = if ($script:HostInfo.PartOfDomain) { 'Info' } else { 'Medium' }
        if ($v['AutoConfigURL']) {
            Add-Finding $sev $cat `
                (L "Proxy configuration script for $($u.Name)" "Script de configuration de proxy pour $($u.Name)") `
                (L 'All web traffic can be routed through a third-party server.' 'Tout le trafic web peut être dirigé vers un serveur tiers.') `
                "AutoConfigURL = $($v['AutoConfigURL'])" `
                (L 'Check that this address is your organisation''s.' "Vérifier que cette adresse est celle de votre organisation.")
        }
        if ("$($v['ProxyEnable'])" -eq '1' -and $v['ProxyServer']) {
            Add-Finding $sev $cat (L "Proxy configured for $($u.Name)" "Proxy configuré pour $($u.Name)") '' "ProxyServer = $($v['ProxyServer'])"
        }
    }
    # Listening ports
    $byPid = @{}
    foreach ($p in $script:Processes) { $byPid["$($p.ProcessId)"] = $p }
    foreach ($g in @(Get-ListeningPorts | Group-Object OwningProcess)) {
        $p = $byPid["$($g.Name)"]
        if (-not $p -or -not $p.ExecutablePath) { continue }
        Add-Examined
        $s = Get-Sig $p.ExecutablePath
        if ($s.Microsoft) { continue }
        $ports = (@($g.Group | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) | Select-Object -Unique -First 12) -join ', '
        $sev = if (-not $s.Signed -and $p.ExecutablePath -match $WritableRegex) { 'High' } elseif (-not $s.Signed) { 'Medium' } else { 'Info' }
        Add-Finding $sev $cat `
            (L "Program listening on the network: $($p.Name)" "Programme en écoute sur le réseau : $($p.Name)") `
            $(if ($sev -ne 'Info') { L 'Unsigned program accepting inbound connections.' 'Programme non signé qui accepte des connexions entrantes.' } else { '' }) `
            (Ev @('ports', $ports) @('binary', $p.ExecutablePath) @('sig', (Format-Signer $s)))
    }
    # --- Firewall rules: the hole punched through it, not just whether it is on
    $rules = @(Get-FirewallRules)
    Add-Examined $rules.Count
    $msNames = '(?i)windows|microsoft|defender|edge|onedrive|teams|office'
    $seenRules = @{}
    foreach ($r in $rules) {
        if ("$($r.Action)" -notmatch '(?i)allow' -or "$($r.Dir)" -notmatch '(?i)^in$') { continue }
        if ("$($r.Active)" -match '(?i)false') { continue }
        $app = [Environment]::ExpandEnvironmentVariables("$($r.App)")
        if (-not $app) { continue }
        if ($app -match '^(?i)%?systemroot%?\\' -or $app -match '(?i)^[A-Z]:\\Windows\\') { continue }
        # Windows keeps one rule per protocol and per profile: report a program once
        $dedup = "$($r.Name)|$($app.ToLower())"
        if ($seenRules[$dedup]) { continue }
        $seenRules[$dedup] = $true
        $s = Get-Sig $app
        $ports = "$($r.LPort)"
        # Only rules opening something that sits in a temp-like folder. An unsigned game, or a
        # remote control tool installed under Program Files, is ordinary and reported elsewhere.
        $drop = ($app -match $DropZoneRegex)
        $remote = ($app -match $IOC.RemoteToolsRegex)
        if ($drop) {
            $sev = if ($remote -or ($s.Exists -and -not $s.Signed)) { 'High' } else { 'Medium' }
            $why = if ($remote) {
                L 'The rule opens the network to a remote control tool launched from a temporary folder.' "La règle ouvre le réseau à un outil de prise en main à distance lancé depuis un dossier temporaire."
            } else {
                L 'The rule lets the network reach a program sitting in a folder anyone can write to. Malware adds its own rule rather than fighting the firewall.' "La règle laisse le réseau joindre un programme placé dans un dossier modifiable par tous. Un malware ajoute sa propre règle plutôt que de lutter contre le pare-feu."
            }
            Add-Finding $sev $cat `
                (L "Inbound firewall rule for a program in a temporary folder: $($r.Name)" "Règle de pare-feu entrante pour un programme en dossier temporaire : $($r.Name)") `
                $why `
                (Ev @('value', $r.Name) @('binary', $app) @('sig', (Format-Signer $s)) @('ports', $ports) @('key', $r.Source)) `
                (L 'Delete the rule if the program is not meant to receive connections.' "Supprimer la règle si le programme n'a pas à recevoir de connexions.") `
                -Fix "Get-NetFirewallRule -DisplayName '$($r.Name)' | Remove-NetFirewallRule"
        }
        # A rule wearing a Microsoft name over an unsigned binary that really exists. Rules left
        # behind by an uninstalled version (file not found) are not a signal, nor are signed ones.
        elseif ("$($r.Name)" -match $msNames -and $s.Exists -and -not $s.Signed) {
            Add-Finding Medium $cat `
                (L "Firewall rule named like a Microsoft one, pointing elsewhere: $($r.Name)" "Règle de pare-feu nommée comme une règle Microsoft, pointant ailleurs : $($r.Name)") `
                (L 'Rule naming is free text: a familiar name hides what the rule actually opens.' "Le nom d'une règle est libre : un nom familier masque ce que la règle ouvre réellement.") `
                (Ev @('value', $r.Name) @('binary', $app) @('sig', (Format-Signer $s)) @('ports', $ports)) `
                (L 'Check the program; delete the rule if it is not legitimate.' 'Vérifier le programme ; supprimer la règle si elle est illégitime.')
        }
    }
    # --- Name resolution: static DNS, DNS-over-HTTPS templates and NRPT policy rules
    $known = '(?i)^(1\.1\.1\.[123]|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.(9|10|11)|149\.112\.112\.\d+|208\.67\.22[02]\.\d+|94\.140\.1[45]\.\d+|185\.228\.16[89]\.\d+|76\.76\.(2|10)\.\d+|45\.90\.(28|30)\.\d+|' +
             '10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.0\.0\.1|fe80:|::1)'
    foreach ($d in @(Get-DnsConfig)) {
        Add-Examined
        if ($d.Kind -eq 'static') {
            $odd = @(($d.Value -split '[,\s]+') | Where-Object { $_ -and $_ -notmatch $known })
            if ($odd.Count) {
                Add-Finding Medium $cat `
                    (L "DNS server set by hand to an unknown address: $($odd -join ', ')" "Serveur DNS fixé manuellement sur une adresse inconnue : $($odd -join ', ')") `
                    (L 'Whoever answers DNS decides where your traffic goes. This address belongs to neither a private network nor a well-known public resolver.' "Qui répond au DNS décide où va votre trafic. Cette adresse n'appartient ni à un réseau privé ni à un résolveur public connu.") `
                    (Ev @('value', $d.Value) @('id', $d.Interface)) `
                    (L 'Compare with what your network or ISP provides; revert to automatic if in doubt.' "Comparer avec ce que fournit votre réseau ou votre opérateur ; revenir en automatique en cas de doute.")
            } else {
                Add-Finding Info $cat (L "Static DNS server: $($d.Value)" "Serveur DNS statique : $($d.Value)") '' (Ev @('id', $d.Interface))
            }
        }
        elseif ($d.Kind -eq 'doh') {
            $sev = if ($d.Value -match '(?i)(cloudflare-dns|dns\.google|quad9|adguard|dns\.nextdns|mozilla\.cloudflare|dns10?\.quad9)') { 'Info' } else { 'Medium' }
            Add-Finding $sev $cat `
                (L "DNS-over-HTTPS resolver configured: $($d.Value)" "Résolveur DNS-over-HTTPS configuré : $($d.Value)") `
                (L 'Encrypted DNS hides resolution from the network, including from your own filtering. Fine with a known provider, worth a look otherwise.' "Le DNS chiffré soustrait la résolution au réseau, y compris à votre propre filtrage. Normal avec un fournisseur connu, à regarder sinon.") `
                (Ev @('value', $d.Value) @('id', $d.Interface))
        }
        else {
            $sev = if ($script:HostInfo.PartOfDomain) { 'Info' } else { 'Medium' }
            Add-Finding $sev $cat `
                (L "Name resolution redirected by policy (NRPT): $($d.Interface)" "Résolution de noms redirigée par stratégie (NRPT) : $($d.Interface)") `
                (L 'An NRPT rule sends the names it matches to a chosen DNS server. Normal with a VPN or a domain, unexpected otherwise.' "Une règle NRPT envoie les noms qu'elle couvre vers un serveur DNS choisi. Normal avec un VPN ou un domaine, inattendu sinon.") `
                (Ev @('value', $d.Value) @('key', "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\$($d.Interface)"))
        }
    }
}

function Check-Processes {
    $cat = 'Processes'
    # The scan's own process and the shells that launched it would otherwise report themselves
    $byId = @{}
    foreach ($p in $script:Processes) { $byId["$($p.ProcessId)"] = $p }
    $self = @{ "$PID" = $true }
    $walk = $byId["$PID"]
    for ($i = 0; $i -lt 8 -and $walk; $i++) {
        $walk = $byId["$($walk.ParentProcessId)"]
        if ($walk) { $self["$($walk.ProcessId)"] = $true }
    }
    if ($self.Count -gt 1) { Add-Note (L 'The scanning process and the shells that started it were left out.' "Le processus d'analyse et les interpréteurs qui l'ont lancé ont été exclus.") }
    foreach ($p in $script:Processes) {
        Add-Examined
        # Win32_Process sometimes reports the path in its \\?\ form, which must not look unusual
        $path = "$($p.ExecutablePath)" -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''
        $cmd = "$($p.CommandLine)"
        if ($self["$($p.ProcessId)"]) { continue }
        if ($path -and ($IOC.SystemProcessNames -contains "$($p.Name)".ToLower()) -and $path -notmatch '(?i)^[A-Z]:\\Windows\\(System32|SysWOW64|WinSxS)\\|^[A-Z]:\\Windows\\explorer\.exe$') {
            Add-Finding Critical $cat `
                (L "Process impersonating a system name: $($p.Name)" "Processus usurpant un nom système : $($p.Name)") `
                (L 'A process named after a Windows component runs from an abnormal location.' "Un processus portant le nom d'un composant Windows s'exécute depuis un emplacement anormal.") `
                (Ev @('pid', $p.ProcessId) @('binary', $path) @('command', (Limit-Text $cmd 400))) `
                (L 'Isolate the host and analyse the binary.' 'Isoler le poste et analyser le binaire.')
            continue
        }
        $reasons = @()
        foreach ($r in $StrongCmd) { if ($cmd -match $r.R) { $reasons += $r.L } }
        if ("$($p.Name) $cmd" -match $IOC.ActivatorRegex) {
            Add-Finding High 'Activators' `
                (L "Activator process running: $($p.Name)" "Processus d'activateur en cours : $($p.Name)") '' `
                (Ev @('pid', $p.ProcessId) @('command', (Limit-Text $cmd 400)))
            continue
        }
        $s = if ($path) { Get-Sig $path } else { $null }
        if ($s -and $s.Exists -and -not $s.Signed -and $path -match $WritableRegex) {
            $reasons += (L 'unsigned binary in a user-writable folder' "binaire non signé dans un dossier modifiable par l'utilisateur")
        }
        if ($reasons.Count) {
            Add-Finding High $cat `
                (L "Suspicious process: $($p.Name) (PID $($p.ProcessId))" "Processus suspect : $($p.Name) (PID $($p.ProcessId))") `
                (Join-L $reasons) `
                (Ev @('binary', $path) @('command', (Limit-Text $cmd 500)) @('parent', "PID $($p.ParentProcessId)")) `
                (L 'Identify the parent process and where the file came from.' "Identifier le processus parent et l'origine du fichier.")
        }
    }
}

function Check-RecentFiles {
    $cat = 'RecentFiles'
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
        Add-Finding Medium $cat `
            (L "Recent unsigned executable: $($f.Name)" "Exécutable non signé récent : $($f.Name)") `
            (L 'Dropped recently in a folder where malware usually installs itself. Often a legitimate installer, worth checking.' "Déposé récemment dans un dossier où les malwares s'installent habituellement. Souvent un installeur légitime, à vérifier.") `
            (Ev @('file', $f.FullName) @('created', (Format-When $f.CreationTime)) @('size', (L "$($f.Length) bytes" "$($f.Length) octets"))) `
            (L 'If in doubt, submit the SHA-256 hash to VirusTotal.' "En cas de doute, soumettre l'empreinte SHA-256 à VirusTotal.")
        Add-Timeline $f.CreationTime (L "Unsigned executable dropped: $($f.Name)" "Exécutable non signé déposé : $($f.Name)") 'Medium'
    }
    if ($pe.Count -gt 40) { Add-Note (L "$($pe.Count) recent unsigned executables, 40 listed." "$($pe.Count) exécutables non signés récents, 40 affichés.") }
    if ($scripts.Count) {
        Add-Finding Info $cat `
            (L "Recent scripts in the temporary and data folders ($($scripts.Count))" "Scripts récents dans les dossiers temporaires et de données ($($scripts.Count))") '' `
            (($scripts | Sort-Object CreationTime -Descending | Select-Object -First 40 | ForEach-Object { "$(Format-When $_.CreationTime)  $($_.FullName)" }) -join "`n")
    }
}

function Check-Events {
    $cat = 'EventLogs'
    if (-not $script:IsAdmin) { Add-Note (L 'Security log unreadable without administrator rights.' 'Journal Sécurité illisible sans droits administrateur.') }
    foreach ($e in @(Get-EventData 'Security' @(1102) $Since) + @(Get-EventData 'System' @(104) $Since)) {
        Add-Examined
        Add-Finding High $cat `
            (L "Event log cleared on $(Format-When $e.Time)" "Journal d'événements effacé le $(Format-When $e.Time)") `
            (L 'Clearing the logs is done to hide traces.' "L'effacement des journaux sert à masquer des traces.") (Limit-Text $e.Message 300)
        Add-Timeline $e.Time (L 'Event log cleared' "Journal d'événements effacé") 'High'
    }
    foreach ($e in @(Get-EventData 'System' @(7045) $Since 'Service Control Manager')) {
        Add-Autorun -Category $cat `
            -Kind (L "Service installed on $(Format-When $e.Time)" "Service installé le $(Format-When $e.Time)") `
            -Name $e.Props[0] -Command $e.Props[1] `
            -Where (L "account: $($e.Props[4]) $([char]0x2014) type: $($e.Props[2])" "compte : $($e.Props[4]) $([char]0x2014) type : $($e.Props[2])") -Quiet
        Add-Timeline $e.Time (L "Service installed: $($e.Props[0])" "Service installé : $($e.Props[0])") 'Medium'
    }
    foreach ($e in @(Get-EventData 'Security' @(4698) $Since)) {
        Add-Examined
        $m = $e.Message
        $hit = $false; foreach ($r in $StrongCmd) { if ($m -match $r.R) { $hit = $true } }
        if ($m -match $IOC.ActivatorRegex) {
            Add-Finding High 'Activators' `
                (L "Activator task created on $(Format-When $e.Time)" "Création d'une tâche d'activateur le $(Format-When $e.Time)") '' (Limit-Text $m 600)
        }
        elseif ($hit -or $m -match $WritableRegex) {
            Add-Finding Medium $cat `
                (L "Scheduled task created on $(Format-When $e.Time) with an action worth checking" "Tâche planifiée créée le $(Format-When $e.Time) avec une action à vérifier") '' (Limit-Text $m 600)
        }
    }
    foreach ($e in @(Get-EventData 'Security' @(4720) $Since)) {
        Add-Examined
        Add-Finding Medium $cat `
            (L "Local account created on $(Format-When $e.Time): $($e.Props[0])" "Compte local créé le $(Format-When $e.Time) : $($e.Props[0])") `
            (L 'Confirm this creation is known.' 'Vérifier que cette création est connue.') (Ev @('createdby', $e.Props[4]))
        Add-Timeline $e.Time (L "Local account created: $($e.Props[0])" "Compte local créé : $($e.Props[0])") 'Medium'
    }
    # Service start type changed: how a security service gets switched off for good
    foreach ($e in @(Get-EventData 'System' @(7040) $Since 'Service Control Manager')) {
        Add-Examined
        $svc = "$($e.Props[0])"
        $to = "$($e.Props[2])"
        if ($svc -notmatch '(?i)^(WinDefend|Sense|WdNisSvc|wscsvc|MpsSvc|EventLog|SecurityHealthService|Sysmon\w*|wuauserv|BITS|VSS|swprv)$') { continue }
        $sev = if ($to -match '(?i)disabl|désactiv') { 'High' } else { 'Medium' }
        Add-Finding $sev $cat `
            (L "Start type of the $svc service changed on $(Format-When $e.Time)" "Type de démarrage du service $svc modifié le $(Format-When $e.Time)") `
            (L 'Disabling a security, logging or backup service is a standard preparation step before the rest.' "Désactiver un service de sécurité, de journalisation ou de sauvegarde est une étape de préparation classique avant la suite.") `
            (Ev @('service', $svc) @('state', $to) (Limit-Text $e.Message 300)) `
            (L 'Set the service back to its normal start type and find what changed it.' 'Rétablir le type de démarrage normal du service et chercher ce qui l''a modifié.')
        Add-Timeline $e.Time (L "$svc service start type changed to $to" "Type de démarrage du service $svc changé en $to") $sev
    }
    foreach ($e in @(Get-EventData 'Security' @(4732) $Since)) {
        Add-Examined
        if ($e.Props -contains 'S-1-5-32-544') {
            Add-Finding Medium $cat `
                (L "Account added to the Administrators group on $(Format-When $e.Time)" "Compte ajouté au groupe Administrateurs le $(Format-When $e.Time)") '' `
                (Ev @('member', "$($e.Props[1]) $($e.Props[0])"))
        }
    }
    $failed = @(Get-EventData 'Security' @(4625) $Since)
    Add-Examined $failed.Count
    if ($failed.Count -ge 50) {
        $top = ($failed | Group-Object { $_.Props[5] } | Sort-Object Count -Descending | Select-Object -First 8)
        Add-Finding Medium $cat `
            (L "$($failed.Count) failed logons in $Days days" "$($failed.Count) échecs d'ouverture de session en $Days jours") `
            (L 'May indicate a brute-force password search.' 'Peut indiquer une recherche de mot de passe par force brute.') `
            (Ev (L (($top | ForEach-Object { "$($_.Count) x account '$($_.Name)'" }) -join "`n") (($top | ForEach-Object { "$($_.Count) $([char]0x00D7) compte « $($_.Name) »" }) -join "`n")))
    }
    foreach ($e in @(Get-EventData 'Microsoft-Windows-Windows Defender/Operational' @(5001, 5010, 5012) $Since)) {
        Add-Examined
        Add-Finding Medium 'Defender' `
            (L "Antivirus protection disabled on $(Format-When $e.Time)" "Protection antivirus désactivée le $(Format-When $e.Time)") '' (Limit-Text $e.Message 300)
    }
    foreach ($e in @(Get-EventData 'Microsoft-Windows-Windows Defender/Operational' @(5007) $Since | Where-Object { $_.Message -match '(?i)\\Exclusions\\' } | Select-Object -First 15)) {
        Add-Examined
        Add-Finding Medium 'Defender' `
            (L "Antivirus exclusion changed on $(Format-When $e.Time)" "Exclusion antivirus modifiée le $(Format-When $e.Time)") '' `
            (Limit-Text (($e.Message -split "`n" | Where-Object { $_ -match 'Exclusions' }) -join ' ') 400)
    }
}

function Check-Bits {
    $cat = 'BITS'
    foreach ($j in @(Get-BitsJobs)) {
        Add-Examined
        if ($j.NotifyCmd) {
            Add-Finding High $cat `
                (L "BITS job with a notification command: $($j.Name)" "Tâche BITS avec commande de notification : $($j.Name)") `
                (L 'BITS re-runs the command at the end of every transfer: quiet persistence.' "BITS relance la commande à chaque fin de transfert : persistance discrète.") `
                (Ev @('command', $j.NotifyCmd) @('urls', ($j.Urls -join ', ')))
        }
        elseif ($j.Urls.Count -and ($j.Urls -join ' ') -notmatch '(?i)microsoft\.com|windowsupdate\.com|googleapis\.com|gvt1\.com|edgedl\.me|adobe\.com|mozilla\.') {
            Add-Finding Info $cat (L "BITS transfer: $($j.Name)" "Transfert BITS : $($j.Name)") '' ($j.Urls -join "`n")
        }
    }
}

# Security settings an attacker, a "debloat" script or an activator turns off to make room.
function Check-Hardening {
    $cat = 'Hardening'
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    # --- Credentials kept in clear in memory
    $wd = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    Add-Examined
    if ($wd -and "$($wd['UseLogonCredential'])" -eq '1') {
        Add-Finding High $cat `
            (L 'Clear-text passwords kept in memory (WDigest)' 'Mots de passe conservés en clair en mémoire (WDigest)') `
            (L 'Disabled by default since Windows 8.1. Attackers switch it back on to read passwords from lsass with Mimikatz.' "Désactivé par défaut depuis Windows 8.1. Les attaquants le réactivent pour lire les mots de passe dans lsass avec Mimikatz.") `
            'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1' `
            (L 'Delete the value, reboot, then change the passwords used on this host.' 'Supprimer la valeur, redémarrer, puis changer les mots de passe utilisés sur ce poste.')
    }
    $lsa = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Add-Examined
    if ($lsa -and "$($lsa['RunAsPPL'])" -ne '1') {
        Add-Finding Info $cat `
            (L 'lsass not running as a protected process (RunAsPPL)' 'lsass non protégé (RunAsPPL)') `
            (L 'Not the default on every build. Enabling it blocks the usual credential dumping tools.' "Ce n'est pas le réglage par défaut sur toutes les versions. L'activer bloque les outils courants de vol d'identifiants.") `
            'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL' `
            (L 'Set RunAsPPL = 1 (and RunAsPPLBoot = 1) if the hardware supports it.' 'Mettre RunAsPPL = 1 (et RunAsPPLBoot = 1) si le matériel le permet.')
    }
    # --- UAC and elevation
    $sys = Get-RegValues $pol
    Add-Examined 3
    if ($sys) {
        if ("$($sys['EnableLUA'])" -eq '0') {
            Add-Finding High $cat (L 'UAC disabled (EnableLUA = 0)' 'UAC désactivé (EnableLUA = 0)') `
                (L 'Every program run by an administrator account runs elevated, with no prompt.' "Tout programme lancé par un compte administrateur s'exécute avec les droits complets, sans confirmation.") `
                "$pol\EnableLUA = 0" (L 'Set it back to 1 and reboot.' 'Remettre la valeur à 1 et redémarrer.')
        }
        elseif ("$($sys['ConsentPromptBehaviorAdmin'])" -eq '0') {
            Add-Finding Medium $cat (L 'UAC prompt switched off for administrators' "Confirmation UAC supprimée pour les administrateurs") `
                (L 'Elevation happens silently.' "L'élévation se fait sans aucune confirmation.") "$pol\ConsentPromptBehaviorAdmin = 0"
        }
        if ("$($sys['LocalAccountTokenFilterPolicy'])" -eq '1') {
            Add-Finding Medium $cat (L 'Remote administration with local accounts allowed (LocalAccountTokenFilterPolicy)' 'Administration à distance par comptes locaux autorisée (LocalAccountTokenFilterPolicy)') `
                (L 'Lets any local administrator account act with full rights over the network: a lateral movement enabler.' "Permet à tout compte administrateur local d'agir avec les droits complets à distance : facilite les déplacements latéraux.") `
                "$pol\LocalAccountTokenFilterPolicy = 1" (L 'Remove it unless a remote management tool documents the need.' "Supprimer la valeur sauf besoin documenté par un outil d'administration.")
        }
        if ("$($sys['EnableSmartScreen'])" -eq '0') {
            Add-Finding Medium $cat (L 'SmartScreen disabled' 'SmartScreen désactivé') `
                (L 'Windows no longer warns about files and sites with a bad reputation.' "Windows ne prévient plus sur les fichiers et les sites de mauvaise réputation.") "$pol\EnableSmartScreen = 0"
        }
    }
    $mi = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
    Add-Examined
    if ($mi -and "$($mi['AlwaysInstallElevated'])" -eq '1') {
        Add-Finding High $cat (L 'AlwaysInstallElevated enabled' 'AlwaysInstallElevated activé') `
            (L 'Any user can install an MSI package as SYSTEM: a direct privilege escalation.' "N'importe quel utilisateur peut installer un paquet MSI en tant que SYSTEM : élévation de privilèges immédiate.") `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1' `
            (L 'Remove this policy.' 'Supprimer cette stratégie.')
    }
    # --- Administration tools locked out (malware, ransomware, "support" scams)
    $locks = @{ DisableTaskMgr = L 'Task Manager' 'le Gestionnaire des tâches'; DisableRegistryTools = L 'Registry Editor' "l'Éditeur du registre"
                DisableCMD = L 'the command prompt' "l'invite de commandes"; DisableChangePassword = L 'password change' 'le changement de mot de passe' }
    $scopes = @(Get-RegScopes)
    foreach ($u in $scopes) {
        foreach ($k in @("$($u.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "$($u.Root)\Software\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -Unique)) {
            $v = Get-RegValues $k
            if (-not $v) { continue }
            Add-Examined
            foreach ($n in $locks.Keys) {
                if ("$($v[$n])" -ne '1') { continue }
                $sev = if ($script:HostInfo.PartOfDomain) { 'Medium' } else { 'High' }
                Add-Finding $sev $cat `
                    (L "$n`: $($locks[$n].en) blocked for $($u.Name.en)" "$n : $($locks[$n].fr) est bloqué pour $($u.Name.fr)") `
                    (L 'Malware and fake support scams lock these tools to keep the user from reacting. A corporate GPO can also set it.' "Les malwares et les faux supports techniques bloquent ces outils pour empêcher l'utilisateur de réagir. Une GPO d'entreprise peut aussi le faire.") `
                    "$k\$n = 1" (L 'Remove the value unless your organisation set it.' "Supprimer la valeur sauf si elle vient de votre organisation.")
            }
        }
    }
    # --- Updates and recovery
    $au = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wu = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    Add-Examined 2
    if ($au -and "$($au['NoAutoUpdate'])" -eq '1') {
        Add-Finding Medium $cat (L 'Automatic updates disabled by policy' 'Mises à jour automatiques désactivées par stratégie') `
            (L 'Activators and malware switch Windows Update off to keep their changes alive.' "Les activateurs et les malwares coupent Windows Update pour préserver leurs modifications.") `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate = 1'
    }
    if ($wu -and $wu['WUServer'] -and -not $script:HostInfo.PartOfDomain) {
        Add-Finding Medium $cat (L 'Updates redirected to a third-party server' 'Mises à jour redirigées vers un serveur tiers') `
            (L 'A host outside a domain normally gets its updates from Microsoft.' "Un poste hors domaine prend normalement ses mises à jour chez Microsoft.") `
            (Ev @('server', $wu['WUServer']))
    }
    $sr = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
    Add-Examined
    if ($sr -and "$($sr['DisableSR'])" -eq '1') {
        Add-Finding Info $cat (L 'System Restore disabled by policy' 'Restauration du système désactivée par stratégie') `
            (L 'No restore point will be created. Common on OEM images, also a ransomware preparation step.' "Aucun point de restauration ne sera créé. Courant sur les images constructeur, mais aussi une étape de préparation des rançongiciels.") `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore\DisableSR = 1'
    }
    # --- Legacy network protocols
    $srv = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Add-Examined
    if ($srv -and "$($srv['SMB1'])" -eq '1') {
        Add-Finding Medium $cat (L 'SMB1 file sharing enabled' 'Partage de fichiers SMB1 activé') `
            (L 'Obsolete protocol, the one WannaCry and NotPetya spread over.' 'Protocole obsolète, celui par lequel WannaCry et NotPetya se sont propagés.') `
            'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 1' `
            (L 'Disable the SMB1 feature unless an old device needs it.' "Désactiver la fonctionnalité SMB1 sauf si un équipement ancien l'exige.")
    }
    $lsaAnon = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($lsaAnon -and "$($lsaAnon['EveryoneIncludesAnonymous'])" -eq '1') {
        Add-Finding Medium $cat (L 'Anonymous access treated as Everyone' "Accès anonyme assimilé à « Tout le monde »") `
            (L 'An unauthenticated session gets the rights granted to Everyone.' "Une session non authentifiée obtient les droits accordés au groupe « Tout le monde »." ) `
            'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous = 1'
    }
    # --- PowerShell left wide open machine-wide
    $ps = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Add-Examined
    if ($ps -and "$($ps['ExecutionPolicy'])" -match '(?i)^(Bypass|Unrestricted)$' -and "$($ps['EnableScripts'])" -ne '0') {
        Add-Finding Medium $cat (L "PowerShell execution policy forced to $($ps['ExecutionPolicy'])" "Stratégie d'exécution PowerShell forcée à $($ps['ExecutionPolicy'])") `
            (L 'Any script runs without question. Often set by a tool that needed it once.' "N'importe quel script s'exécute sans question. Souvent posé par un outil qui en a eu besoin une fois.") `
            "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy = $($ps['ExecutionPolicy'])"
    }
    # --- AMSI: the interface antivirus products use to see scripts before they run
    $wsh = @{}
    foreach ($u in $scopes) {
        $v = Get-RegValues "$($u.Root)\Software\Microsoft\Windows Script\Settings"
        Add-Examined
        if ($v -and "$($v['AmsiEnable'])" -eq '0') {
            Add-Finding High $cat `
                (L "AMSI disabled for Windows Script Host ($($u.Name.en))" "AMSI désactivé pour Windows Script Host ($($u.Name.fr))") `
                (L 'VBScript and JScript then run without being shown to the antivirus. There is no legitimate reason to set this.' "VBScript et JScript s'exécutent alors sans être présentés à l'antivirus. Aucun réglage légitime ne fait cela.") `
                "$($u.Root)\Software\Microsoft\Windows Script\Settings\AmsiEnable = 0" `
                (L 'Delete the value and scan the host.' 'Supprimer la valeur et analyser le poste.') `
                -Fix "Remove-ItemProperty -LiteralPath '$($u.Root)\Software\Microsoft\Windows Script\Settings' -Name AmsiEnable"
        }
    }
    foreach ($clsid in @(Get-RegSubKeys 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers')) {
        Add-Examined
        $dll = ''
        foreach ($k in "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32", "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$clsid\InprocServer32") {
            $iv = Get-RegValues $k
            if ($iv -and $iv['']) { $dll = [Environment]::ExpandEnvironmentVariables(("$($iv[''])" -replace '"', '')); break }
        }
        if (-not $dll) { continue }
        $s = Get-Sig $dll
        if ($s.Exists -and -not $s.Signed) {
            Add-Finding High $cat `
                (L "Unsigned AMSI provider: $clsid" "Fournisseur AMSI non signé : $clsid") `
                (L 'This DLL is loaded by every process that submits a script to AMSI. An unsigned one can neutralise the scanning instead of doing it.' "Cette DLL est chargée par tout processus qui soumet un script à AMSI. Non signée, elle peut neutraliser l'analyse au lieu de la faire.") `
                (Ev @('key', "HKLM\SOFTWARE\Microsoft\AMSI\Providers\$clsid") @('dll', $dll) @('sig', (Format-Signer $s))) `
                (L 'Identify the product that registered it; remove the provider if unknown.' "Identifier le produit qui l'a enregistré ; supprimer le fournisseur s'il est inconnu.")
        }
    }
    # amsi.dll dropped next to an executable: loaded instead of the real one (DLL search order)
    foreach ($d in @($PData, $PublicDir) + @($script:Users | ForEach-Object { Join-Path $_.Profile 'AppData\Local\Temp'; Join-Path $_.Profile 'Downloads' })) {
        if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -File -Force -Filter 'amsi.dll')) {
            Add-Examined
            Add-Finding High $cat `
                (L 'amsi.dll placed outside the system folder' "amsi.dll placée hors du dossier système") `
                (L 'A program started from this folder loads this copy instead of the real AMSI library: the usual way to blind the antivirus for that process.' "Un programme lancé depuis ce dossier charge cette copie au lieu de la vraie bibliothèque AMSI : la façon habituelle d'aveugler l'antivirus pour ce processus.") `
                (Ev @('file', $f.FullName) @('created', (Format-When $f.CreationTime)) @('sig', (Format-Signer (Get-Sig $f.FullName)))) `
                (L 'Remove the file and look for what dropped it.' 'Supprimer le fichier et chercher ce qui l''a déposé.') `
                -Fix "Remove-Item -LiteralPath '$($f.FullName)'"
            Add-Timeline $f.CreationTime (L "amsi.dll dropped in $($f.DirectoryName)" "amsi.dll déposée dans $($f.DirectoryName)") 'High'
        }
    }
    # PowerShell 2.0 engine: no AMSI, no script block logging
    $v2 = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
    Add-Examined
    if ($v2 -and "$($v2['PowerShellVersion'])" -match '^2\.' -and (Test-Path -LiteralPath (Join-Path $SysRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))) {
        Add-Finding Medium $cat `
            (L 'PowerShell 2.0 engine still available' 'Moteur PowerShell 2.0 encore disponible') `
            (L 'Started with -Version 2, PowerShell runs without AMSI and without script block logging. Attackers use it to bypass both.' "Lancé avec -Version 2, PowerShell s'exécute sans AMSI et sans journalisation des blocs de script. Les attaquants s'en servent pour contourner les deux.") `
            (Ev @('key', 'HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine') @('value', "PowerShellVersion = $($v2['PowerShellVersion'])")) `
            (L 'Remove the optional feature: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root.' 'Supprimer la fonctionnalité : Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root.')
    }
    # --- Trusted root certificates: a rogue one makes any HTTPS site forgeable
    $roots = @(Get-RootCertificates)
    Add-Examined $roots.Count
    foreach ($c in $roots) {
        $cn = ($c.Subject -replace '^CN=([^,]+).*$', '$1')
        if ($c.Subject -match $IOC.TlsInterceptionCertRegex) {
            $sev = if ($script:HostInfo.PartOfDomain) { 'Info' } else { 'Medium' }
            Add-Finding $sev $cat `
                (L "TLS interception certificate trusted: $cn" "Certificat d'interception TLS approuvé : $cn") `
                (L 'This authority belongs to a traffic inspection product. Expected if your organisation inspects HTTPS, otherwise it means someone can read every secure page.' "Cette autorité appartient à un produit d'inspection du trafic. Normal si votre organisation inspecte le HTTPS, sinon cela signifie que quelqu'un peut lire toutes les pages sécurisées.") `
                (Ev @('value', $c.Subject) @('created', (Format-When $c.NotBefore)) @('sha256', $c.Thumbprint)) `
                (L 'Confirm it was installed by your organisation; remove it otherwise.' "Confirmer qu'il vient de votre organisation ; le supprimer sinon.")
            continue
        }
        if ($c.Subject -ne $c.Issuer) { continue }           # cross-signed: part of a normal chain
        if ($c.NotBefore -lt $Since) { continue }
        Add-Finding Medium $cat `
            (L "Root certificate authority added recently: $cn" "Autorité de certification racine ajoutée récemment : $cn") `
            (L 'A self-signed authority trusted by the whole machine, issued inside the analysis window. Any HTTPS site can be impersonated with its key.' "Une autorité auto-signée approuvée par toute la machine, émise pendant la période analysée. N'importe quel site HTTPS peut être usurpé avec sa clé.") `
            (Ev @('value', $c.Subject) @('created', (Format-When $c.NotBefore)) @('time', (Format-When $c.NotAfter)) @('sha256', $c.Thumbprint)) `
            (L 'Identify what installed it (software, proxy, GPO) and remove it if unknown.' "Identifier ce qui l'a installé (logiciel, proxy, GPO) et le supprimer s'il est inconnu.")
        Add-Timeline $c.NotBefore (L "Root certificate added: $cn" "Certificat racine ajouté : $cn") 'Medium'
    }
}

# Kernel drivers: unsigned, known-abused (BYOVD) or freshly installed, and the boot options
# that would let any of them load.
function Check-Drivers {
    $cat = 'Drivers'
    $thirdParty = @()
    foreach ($d in @(Get-DriversData)) {
        Add-Examined
        $path = Resolve-ExePath "$($d.PathName)"
        if (-not $path) { continue }
        $sig = Get-Sig $path
        $file = Split-Path $path -Leaf
        $known = ($file -match $IOC.VulnerableDriverRegex)
        $writable = ($path -match $WritableRegex)
        $ev = Ev @('service', $d.Name) @('file', $path) @('sig', (Format-Signer $sig)) @('state', "$($d.State) / $($d.StartMode)")
        if ($known) {
            $sev = if (-not $sig.Signed -or $writable) { 'High' } else { 'Medium' }
            Add-Finding $sev $cat `
                (L "Driver known to be abused: $file" "Pilote connu pour être détourné : $file") `
                (L 'This driver is on the lists used for BYOVD attacks: it gives kernel access to whoever loads it. Expected if it comes from a monitoring, overclocking or RGB tool you installed.' "Ce pilote figure sur les listes utilisées pour les attaques BYOVD : il donne un accès noyau à qui le charge. Normal s'il vient d'un outil de supervision, d'overclocking ou RGB que vous avez installé.") `
                $ev (L 'Match it against the software you installed; remove it otherwise and check Defender''s vulnerable driver blocklist is on.' "Rapprocher du logiciel installé ; sinon le supprimer et vérifier que la liste de blocage des pilotes vulnérables est active.")
        }
        elseif ($sig.Exists -and -not $sig.Signed -and $sig.MsClaim -and $path -match '(?i)^[A-Z]:\\Windows\\') {
            # Old inbox drivers sometimes lose their catalogue entry: worth a look, not an alarm
            Add-Finding Medium $cat `
                (L "Kernel driver without a verifiable signature: $file" "Pilote noyau sans signature vérifiable : $file") `
                (L 'The file names Microsoft as its publisher but no signature could be verified, usually a missing catalogue entry for an old inbox driver. A replaced system file would look the same, so confirm it.' "Le fichier indique Microsoft comme éditeur mais aucune signature n'a pu être vérifiée, en général une entrée de catalogue manquante pour un vieux pilote intégré. Un fichier système remplacé donnerait la même image : à confirmer.") `
                $ev (L 'Run sfc /verifyonly, or compare the SHA-256 with the same file on a healthy host.' 'Lancer sfc /verifyonly, ou comparer le SHA-256 avec le même fichier sur un poste sain.')
        }
        elseif ($sig.Exists -and -not $sig.Signed) {
            Add-Finding High $cat `
                (L "Unsigned kernel driver: $file" "Pilote noyau non signé : $file") `
                (L 'Windows normally refuses unsigned drivers: either signing enforcement is off, or the file was replaced after installation.' "Windows refuse normalement les pilotes non signés : soit le contrôle de signature est désactivé, soit le fichier a été remplacé après installation.") `
                $ev (L 'Identify the publisher, submit the hash to VirusTotal, and check the boot options below.' "Identifier l'éditeur, soumettre l'empreinte à VirusTotal et vérifier les options de démarrage ci-dessous.")
        }
        elseif (-not $sig.Microsoft) {
            $thirdParty += $d.Name
            $i = Get-Item -LiteralPath $path -Force
            if ($i -and $i.CreationTime -ge $Since) {
                Add-Finding Medium $cat `
                    (L "Third-party driver installed recently: $file" "Pilote tiers installé récemment : $file") `
                    (L 'A kernel driver added in the analysis window. Normal after installing software or an update, worth confirming otherwise.' "Pilote noyau ajouté pendant la période analysée. Normal après l'installation d'un logiciel ou d'une mise à jour, à confirmer sinon.") `
                    (Ev @('service', $d.Name) @('file', $path) @('sig', (Format-Signer $sig)) @('created', (Format-When $i.CreationTime))) `
                    (L 'Match it against what was installed on that date.' "Rapprocher de ce qui a été installé à cette date.")
                Add-Timeline $i.CreationTime (L "Kernel driver installed: $file" "Pilote noyau installé : $file") 'Medium'
            }
        }
    }
    if ($thirdParty.Count) {
        Add-Finding Info $cat (L "Third-party kernel drivers ($($thirdParty.Count))" "Pilotes noyau tiers ($($thirdParty.Count))") `
            (L 'Signed by someone other than Microsoft: normal for hardware, antivirus and virtualisation software.' "Signés par un autre éditeur que Microsoft : normal pour le matériel, les antivirus et la virtualisation.") `
            (($thirdParty | Sort-Object | Select-Object -First 40) -join ', ')
    }
    # Driver signing and kernel integrity switched off at boot
    if (-not $script:IsAdmin) { Add-Note (L 'Boot options unreadable without administrator rights (bcdedit).' 'Options de démarrage illisibles sans droits administrateur (bcdedit).') }
    else {
        $b = Get-BootConfig
        Add-Examined 3
        if ("$($b['testsigning'])" -match '(?i)yes|oui') {
            Add-Finding High $cat (L 'Test signing enabled at boot (testsigning)' 'Signature de test activée au démarrage (testsigning)') `
                (L 'Windows then loads drivers signed by anyone. Used to load a rootkit or a cracked driver.' "Windows charge alors des pilotes signés par n'importe qui. Utilisé pour charger un rootkit ou un pilote craqué.") `
                'bcdedit: testsigning = Yes' (L 'bcdedit /set testsigning off, then reboot and look for what needed it.' "bcdedit /set testsigning off, puis redémarrer et chercher ce qui l'exigeait.")
        }
        if ("$($b['nointegritychecks'])" -match '(?i)yes|oui' -or "$($b['integrityservices'])" -match '(?i)disable') {
            Add-Finding High $cat (L 'Kernel integrity checks disabled' 'Contrôles d''intégrité du noyau désactivés') `
                (L 'Any driver can be loaded, signed or not.' "N'importe quel pilote peut être chargé, signé ou non.") `
                "bcdedit: nointegritychecks = $($b['nointegritychecks']) ; integrityservices = $($b['integrityservices'])" `
                (L 'bcdedit /deletevalue nointegritychecks, then reboot.' 'bcdedit /deletevalue nointegritychecks, puis redémarrer.')
        }
        if ($b['safeboot']) {
            Add-Finding Medium $cat (L "Host set to boot in safe mode ($($b['safeboot']))" "Poste réglé pour démarrer en mode sans échec ($($b['safeboot']))") `
                (L 'Ransomware uses safe mode to run with the security products unloaded.' "Les rançongiciels utilisent le mode sans échec pour agir avec les protections déchargées.") `
                "bcdedit: safeboot = $($b['safeboot'])"
        }
        if ("$($b['debug'])" -match '(?i)yes|oui') {
            Add-Finding Medium $cat (L 'Kernel debugging enabled' 'Débogage du noyau activé') `
                (L 'Gives full control over the kernel to whoever attaches a debugger.' "Donne le contrôle complet du noyau à qui attache un débogueur.") 'bcdedit: debug = Yes'
        }
    }
    $ci = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    Add-Examined
    if ($ci -and "$($ci['VulnerableDriverBlocklistEnable'])" -eq '0') {
        Add-Finding Medium $cat (L 'Microsoft vulnerable driver blocklist disabled' 'Liste de blocage des pilotes vulnérables désactivée') `
            (L 'This list is what stops the drivers used in BYOVD attacks from loading.' "Cette liste est ce qui empêche le chargement des pilotes utilisés dans les attaques BYOVD.") `
            'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable = 0' `
            (L 'Set it back to 1.' 'Remettre la valeur à 1.')
    }
}

# Artefacts left behind by credential dumping: the memory dump or hive copy, not the tool.
function Check-Credentials {
    $cat = 'Credentials'
    $dirs = @("$SysRoot\Temp", $PData, $PublicDir, "$SysRoot\System32\config\RegBack")
    foreach ($u in $script:Users) {
        foreach ($sub in 'AppData\Local\Temp', 'Downloads', 'Desktop', 'Documents') { $dirs += (Join-Path $u.Profile $sub) }
    }
    $hiveNames = '(?i)^(sam|system|security|ntds\.dit|sam\.(sav|bak|old|dmp)|system\.(sav|bak|old)|ntuser\.dat\.copy)$'
    foreach ($d in ($dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -File -Force |
                         Where-Object { $_.Extension -match '(?i)^\.(dmp|hive|kirbi|ccache|ntds|save)$' -or $_.Name -match $hiveNames })) {
            Add-Examined
            $name = $f.Name
            $isWer = ($f.FullName -match '(?i)\\(CrashDumps|WER|ReportQueue|ReportArchive|LocalLow\\Microsoft\\CryptnetUrlCache)\\')
            $magic = ''
            if ($f.Extension -match '(?i)^\.(dmp|save|hive)$' -or $name -match $hiveNames) { $magic = Get-FileMagic $f.FullName 4 }
            $isDump = ($magic -match '^MDMP')
            $isHive = ($magic -match '^regf')
            $named = ($name -match '(?i)lsass|procdump|nanodump|dumpert|minidump|mimi|sekurlsa|comsvcs|ntds|sam')
            if (-not $isDump -and -not $isHive -and -not $named) { continue }
            if ($isWer -and -not $named) { continue }                      # ordinary Windows crash dumps
            if ($isDump) {
                # Size alone proves nothing: a developer's crash dump is big too. The name is what
                # says this dump was taken of a credential process.
                $sev = if ($named) { 'High' } else { 'Medium' }
                Add-Finding $sev $cat `
                    (L "Process memory dump on disk: $name" "Vidage mémoire de processus sur le disque : $name") `
                    (L 'A memory dump of a process can be opened offline to extract passwords, tokens and keys. A large dump, or one named after lsass, is how credentials leave a machine.' "Le vidage mémoire d'un processus peut être ouvert hors ligne pour en extraire mots de passe, jetons et clés. Un vidage volumineux, ou nommé d'après lsass, est la façon dont les identifiants quittent une machine.") `
                    (Ev @('file', $f.FullName) @('size', (L "$([math]::Round($f.Length / 1MB, 1)) MB" "$([math]::Round($f.Length / 1MB, 1)) Mo")) `
                        @('created', (Format-When $f.CreationTime)) @('type', $magic.Trim())) `
                    (L 'Collect the file, then delete it and change the passwords used on this host.' "Collecter le fichier, puis le supprimer et changer les mots de passe utilisés sur ce poste.") `
                    -Fix "Remove-Item -LiteralPath '$($f.FullName)'"
                Add-Timeline $f.CreationTime (L "Memory dump written: $name" "Vidage mémoire écrit : $name") $sev
                continue
            }
            if ($isHive -or $named) {
                Add-Finding High $cat `
                    (L "Copy of a registry hive or credential store: $name" "Copie d'une ruche de registre ou d'un magasin d'identifiants : $name") `
                    (L 'SAM, SECURITY, SYSTEM and ntds.dit hold password hashes. A copy outside the system folders is a collection step, not a backup Windows makes here.' "SAM, SECURITY, SYSTEM et ntds.dit contiennent les empreintes de mots de passe. Une copie hors des dossiers système est une étape de collecte, pas une sauvegarde que Windows fait ici.") `
                    (Ev @('file', $f.FullName) @('size', (L "$($f.Length) bytes" "$($f.Length) octets")) `
                        @('created', (Format-When $f.CreationTime)) @('type', $magic.Trim())) `
                    (L 'Treat the host as compromised: collect the file, reset the passwords, then look for how it was made.' "Considérer le poste comme compromis : collecter le fichier, réinitialiser les mots de passe, puis chercher comment il a été produit.")
                Add-Timeline $f.CreationTime (L "Hive copy written: $name" "Copie de ruche écrite : $name") 'High'
            }
        }
    }
    # Shadow copy and backup deletion, plus hive export, read from the command lines we can still see
    foreach ($p in $script:Processes) {
        $cmd = "$($p.CommandLine)"
        if (-not $cmd) { continue }
        Add-Examined
        if ($cmd -match '(?i)\b(reg(\.exe)?\s+save\s+hk|vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete|comsvcs\.dll.{0,20}minidump|procdump(64)?(\.exe)?\s+.*lsass|esentutl.{0,40}ntds\.dit)') {
            Add-Finding Critical $cat `
                (L "Credential or backup tampering command running: $($p.Name)" "Commande de vol d'identifiants ou de destruction de sauvegardes en cours : $($p.Name)") `
                (L 'This command is running right now. Exporting a hive, dumping lsass or deleting shadow copies has no routine use.' "Cette commande s'exécute en ce moment. Exporter une ruche, vider lsass ou supprimer les copies d'ombre n'a aucun usage courant.") `
                (Ev @('pid', $p.ProcessId) @('binary', $p.ExecutablePath) @('command', (Limit-Text $cmd 500)) @('parent', "PID $($p.ParentProcessId)")) `
                (L 'Isolate the host now and identify the parent process.' 'Isoler le poste immédiatement et identifier le processus parent.')
        }
    }
}

# Browser extensions: the quiet way to read every page, every password and every session.
function Check-Browsers {
    $cat = 'Browsers'
    $browsers = @(
        @{ Name = 'Chrome'; Pol = 'Google\Chrome';    Store = '(?i)clients2\.google\.com/service/update2/crx' }
        @{ Name = 'Edge';   Pol = 'Microsoft\Edge';   Store = '(?i)edge\.microsoft\.com/extensionwebstorebase/v1/crx' }
        @{ Name = 'Brave';  Pol = 'BraveSoftware\Brave'; Store = '(?i)clients2\.google\.com/service/update2/crx' }
    )
    # --- Extensions imposed by policy
    foreach ($b in $browsers) {
        foreach ($k in "HKLM:\SOFTWARE\Policies\$($b.Pol)\ExtensionInstallForcelist", "HKCU:\SOFTWARE\Policies\$($b.Pol)\ExtensionInstallForcelist") {
            $v = Get-RegValues $k
            if (-not $v) { continue }
            foreach ($n in $v.Keys) {
                $entry = "$($v[$n])"
                if (-not $entry) { continue }
                Add-Examined
                $id = ($entry -split ';')[0]
                if ($entry -match ';' -and $entry -notmatch $b.Store) {
                    Add-Finding High $cat `
                        (L "$($b.Name): extension force-installed from a third-party server" "$($b.Name) : extension imposée depuis un serveur tiers") `
                        (L 'A policy installs this extension and the user cannot remove it. The update URL is not the official store.' "Une stratégie installe cette extension et l'utilisateur ne peut pas la retirer. L'adresse de mise à jour n'est pas celle du magasin officiel.") `
                        (Ev @('key', $k) @('id', $id) @('value', $entry)) `
                        (L 'Remove the policy and inspect the extension.' "Supprimer la stratégie et examiner l'extension.")
                } else {
                    Add-Finding Info $cat `
                        (L "$($b.Name): extension installed by policy" "$($b.Name) : extension installée par stratégie") `
                        (L 'Comes from the official store; usual in a managed fleet.' "Vient du magasin officiel ; courant sur un parc géré.") `
                        (Ev @('key', $k) @('id', $id))
                }
            }
        }
    }
    # --- Extensions registered through the registry (sideloading, no store involved)
    foreach ($b in $browsers) {
        foreach ($root in 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node', 'HKCU:\SOFTWARE') {
            $base = "$root\$($b.Pol -replace '\\Brave$', '\Brave-Browser')\Extensions"
            foreach ($id in @(Get-RegSubKeys $base)) {
                $v = Get-RegValues "$base\$id"
                if (-not $v) { continue }
                Add-Examined
                $p = "$($v['path'])"
                if (-not $p) { continue }
                $sev = if ($p -match $WritableRegex) { 'High' } else { 'Medium' }
                Add-Finding $sev $cat `
                    (L "$($b.Name): extension sideloaded through the registry" "$($b.Name) : extension installée hors magasin via le registre") `
                    (L 'An extension declared this way is installed from a local file at the next start, bypassing the store. Software bundles and adware use it.' "Une extension déclarée ainsi est installée depuis un fichier local au prochain démarrage, sans passer par le magasin. Utilisé par les logiciels groupés et les adwares.") `
                    (Ev @('key', "$base\$id") @('id', $id) @('path', $p) @('value', "version = $($v['version'])")) `
                    (L 'Identify the software that registered it; remove both if it is unknown.' "Identifier le logiciel qui l'a déclarée ; supprimer les deux si elle est inconnue.")
            }
        }
    }
    # --- Installed extensions, per user profile
    foreach ($u in $script:Users) {
        $exts = @(Get-BrowserExtensions $u.Profile)
        Add-Examined $exts.Count
        if (-not $exts.Count) { continue }
        foreach ($e in $exts) {
            $risky = @($e.Permissions | Where-Object { $_ -match $IOC.BrowserRiskyPermissions })
            if (-not $risky.Count) { continue }
            Add-Finding Medium $cat `
                (L "$($e.Browser) extension with powerful permissions ($($u.Name)): $($e.Name)" "Extension $($e.Browser) aux permissions étendues ($($u.Name)) : $($e.Name)") `
                (L "Requests $($risky -join ', '): enough to drive the browser, read traffic or talk to a local program." "Demande $($risky -join ', ') : de quoi piloter le navigateur, lire le trafic ou dialoguer avec un programme local.") `
                (Ev @('id', $e.Id) @('value', "$($e.Name) $($e.Version)") @('path', $e.Path) @('modified', (Format-When $e.Installed)) `
                    @('values', (($e.Permissions | Select-Object -First 20) -join ', '))) `
                (L 'Open the extension page in the browser and confirm the user installed it on purpose.' "Ouvrir la page des extensions du navigateur et confirmer que l'utilisateur l'a installée volontairement.")
        }
        foreach ($g in @($exts | Group-Object Browser)) {
            Add-Finding Info $cat `
                (L "$($g.Name) extensions installed for $($u.Name) ($($g.Count))" "Extensions $($g.Name) installées pour $($u.Name) ($($g.Count))") '' `
                (($g.Group | Sort-Object Name | ForEach-Object { "$($_.Name) $($_.Version)  [$($_.Id)]" }) -join "`n")
        }
    }
}

# =====================================================================================
#  Orchestration
# =====================================================================================
$AllChecks = [ordered]@{
    Activators        = { Check-Activators }
    PowerShellHistory = { Check-PSHistory }
    Autostart         = { Check-RunKeys; Check-StartupFolders }
    ScheduledTasks    = { Check-Tasks }
    Services          = { Check-Services }
    WMI               = { Check-Wmi }
    Registry          = { Check-RegistryPersistence }
    Office            = { Check-Office }
    Accounts          = { Check-Accounts }
    Credentials       = { Check-Credentials }
    Hardening         = { Check-Hardening }
    RemoteAccess      = { Check-RemoteAccess }
    Defender          = { Check-Defender }
    Network           = { Check-Network }
    Drivers           = { Check-Drivers }
    Browsers          = { Check-Browsers }
    Processes         = { Check-Processes }
    RecentFiles       = { Check-RecentFiles }
    EventLogs         = { Check-Events }
    BITS              = { Check-Bits }
}
if ($ListChecks) { foreach ($k in $AllChecks.Keys) { '{0,-18} {1}' -f $k, $CatLabel[$k].en }; exit 0 }
if ($TestHooks) { . $TestHooks }

$script:IsAdmin  = [bool](Test-IsAdmin)
$script:HostInfo = Get-HostInfo
$started = Get-Date
Write-Host "WinTriage $($script:Version) $([char]0x2014) $($script:HostInfo.Computer) $([char]0x2014) $(Format-When $started)" -ForegroundColor White
if (-not $script:IsAdmin) { Write-Host '[WARNING] Running without administrator rights: analysis limited to the current profile, Security log and antivirus exclusions unreadable.' -ForegroundColor Yellow }

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
        try { & $AllChecks[$name] } catch { $script:Cur.Error = "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
        $script:Cur.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        $script:Checks.Add($script:Cur)
        $mine = @($script:Findings | Where-Object { $_.Check -eq $name -and $_.Severity -ne 'Info' })
        $color = if ($script:Cur.Error) { 'Magenta' } elseif ($mine | Where-Object { $_.Severity -in 'Critical', 'High' }) { 'Red' } elseif ($mine.Count) { 'Yellow' } else { 'Green' }
        Write-Host ('  {0,-20} {1,5} items   {2,3} to review   {3,5}s {4}' -f $name, $script:Cur.Examined, $mine.Count, $script:Cur.Seconds, $(if ($script:Cur.Error) { "ERROR: $($script:Cur.Error)" })) -ForegroundColor $color
    }
} finally {
    $script:Cur = $null
    if ($script:LoadedHives.Count) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        foreach ($h in $script:LoadedHives) { $null = reg.exe unload "HKU\$h" 2>$null }
    }
}

# =====================================================================================
#  Report
# =====================================================================================
$all = @($script:Findings | Sort-Object @{ Expression = { $SevRank[$_.Severity] } }, Category, @{ Expression = { $_.Title.en } })

# --- Suppression rules: accepted findings leave the results but stay visible and accountable
$allowRules = $null
if (-not $NoAllowlist -and (Test-Path -LiteralPath $AllowlistFile)) {
    $allowRules = Import-PowerShellDataFile -LiteralPath $AllowlistFile
    if ($allowRules -and -not $allowRules.Suppress) { $allowRules = $null }
}
$expiredRules = @()
foreach ($f in $all) {
    if (-not $allowRules) { break }
    foreach ($r in @($allowRules.Suppress)) {
        if ($r.Key -and $r.Key -ne $f.Key) { continue }
        if ($r.Category -and $r.Category -ne $f.Category) { continue }
        if ($r.Title -and $f.Title.en -notmatch $r.Title) { continue }
        if ($r.Evidence -and $f.Evidence.en -notmatch $r.Evidence) { continue }
        if (-not ($r.Key -or $r.Title -or $r.Evidence)) { continue }     # a category alone is too broad
        if ($r.Expires) {
            $exp = $null
            try { $exp = [datetime]::ParseExact("$($r.Expires)", 'yyyy-MM-dd', $null) } catch { }
            if (-not $exp -or $exp -lt (Get-Date).Date) {
                $expiredRules += [ordered]@{ Title = "$($r.Title)$($r.Key)"; Expires = "$($r.Expires)"; Reason = "$($r.Reason)"; Author = "$($r.Author)" }
                continue
            }
        }
        $f.Suppressed = [ordered]@{ Reason = "$($r.Reason)"; Author = "$($r.Author)"; Expires = "$($r.Expires)"; Key = $f.Key }
        break
    }
}
$suppressed = @($all | Where-Object { $_.Suppressed })
$live = @($all | Where-Object { -not $_.Suppressed })

# --- Baseline: what was already there in a previous run is marked as known
$baselineFile = ''
$knownKeys = @{}
if ($Baseline) {
    $bf = $null
    if (Test-Path -LiteralPath $Baseline -PathType Container) {
        $bf = Get-ChildItem -LiteralPath $Baseline -Filter 'WinTriage_*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    } elseif (Test-Path -LiteralPath $Baseline -PathType Leaf) {
        $bf = Get-Item -LiteralPath $Baseline
    }
    if (-not $bf) { Write-Host "Baseline not found: $Baseline" -ForegroundColor Yellow }
    else {
        $bj = $null
        try { $bj = Get-Content -LiteralPath $bf.FullName -Raw | ConvertFrom-Json } catch { }
        if (-not $bj -or -not $bj.Findings) { Write-Host "Baseline unreadable or empty: $($bf.FullName)" -ForegroundColor Yellow }
        else {
            $baselineFile = $bf.FullName
            foreach ($b in @($bj.Findings)) {
                $k = "$($b.Key)"
                if (-not $k) { $k = Get-FindingKey "$($b.Category)" "$($b.Title.en)" "$($b.Evidence.en)" }   # report from an older version
                $knownKeys[$k] = $true
            }
            foreach ($f in $all) { if ($knownKeys[$f.Key]) { $f.New = $false } }
        }
    }
}
$newCount = @($live | Where-Object { $_.New -and $_.Severity -ne 'Info' }).Count
$sorted = if ($NewOnly -and $baselineFile) { @($live | Where-Object { $_.New }) } else { $live }
$hiddenKnown = $live.Count - $sorted.Count

$count = [ordered]@{}
foreach ($s in 'Critical', 'High', 'Medium', 'Info') { $count[$s] = @($sorted | Where-Object { $_.Severity -eq $s }).Count }
$verdictKey = if ($count['Critical']) { 'critical' } elseif ($count['High']) { 'high' } elseif ($count['Medium']) { 'medium' } else { 'clean' }
$verdictText = @{
    critical = L 'Signs of compromise: deal with this immediately' 'Signes de compromission : à traiter immédiatement'
    high     = L 'Items to deal with' 'Éléments à traiter'
    medium   = L 'Nothing alarming, some points to verify' "Rien d'alarmant, des points à vérifier"
    clean    = L 'These checks found nothing suspicious' 'Aucun élément suspect relevé par ces contrôles'
}

$null = New-Item -ItemType Directory -Path $OutputDir -Force
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$base = Join-Path $OutputDir ('WinTriage_{0}_{1}' -f $script:HostInfo.Computer, $stamp)
$duration = [math]::Round(((Get-Date) - $started).TotalSeconds)
$domain = if ($script:HostInfo.PartOfDomain) { L $script:HostInfo.Domain $script:HostInfo.Domain } else { L 'not domain-joined' 'hors domaine' }
$profiles = @($script:Users | ForEach-Object { [ordered]@{ path = $_.Profile; loaded = [bool]$_.RegRoot } })

$timeline = @($script:Timeline | Sort-Object When -Descending | Select-Object -First 250 | ForEach-Object {
    [ordered]@{ When = $_.When.ToString('yyyy-MM-dd HH:mm'); Category = $_.Category; CategoryLabel = $CatLabel[$_.Category]
                Severity = $_.Severity; What = $_.What }
})
$meta = [ordered]@{
    Tool = "WinTriage $($script:Version)"; Started = $started.ToString('s'); DurationSeconds = $duration
    Computer = $script:HostInfo.Computer; User = $script:HostInfo.User; Admin = $script:IsAdmin; OS = $script:HostInfo.OS
    Domain = $domain; Days = $Days; Profiles = $profiles
    Verdict = $verdictText[$verdictKey]; Counts = $count
    BaselineFile = $baselineFile; NewSinceBaseline = $newCount; KnownHidden = $hiddenKnown
    AllowlistFile = $(if ($allowRules) { $AllowlistFile } else { '' }); SuppressedCount = $suppressed.Count
    ExpiredSuppressions = $expiredRules
}
$checksOut = @($script:Checks | ForEach-Object {
    $seen = @{}; $notes = @()
    foreach ($n in @($_.Notes)) { if (-not $seen["$($n.en)"]) { $seen["$($n.en)"] = $true; $notes += $n } }
    [ordered]@{ Name = $_.Name; Label = $CatLabel[$_.Name]; Examined = $_.Examined; Results = $_.Results; Seconds = $_.Seconds; Error = $_.Error; Notes = $notes }
})
$outFinding = {
    param($f)
    [ordered]@{ Severity = $f.Severity; Category = $f.Category; CategoryLabel = $CatLabel[$f.Category]
                Title = $f.Title; Detail = $f.Detail; Evidence = $f.Evidence; Advice = $f.Advice
                Key = $f.Key; New = [bool]$f.New; Fix = $f.Fix; Suppressed = $f.Suppressed; Check = $f.Check }
}
$findingsOut   = @($sorted     | ForEach-Object { & $outFinding $_ })
$suppressedOut = @($suppressed | ForEach-Object { & $outFinding $_ })
[ordered]@{ Meta = $meta; Checks = $checksOut; Findings = $findingsOut; Suppressed = $suppressedOut; Timeline = $timeline } |
    ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$base.json" -Encoding UTF8

# --- Remediation script: everything commented out, meant to be read and edited
if ($FixScript) {
    $fx = New-Object System.Text.StringBuilder
    # Every line stays a comment: the file is a worksheet, not a script to run
    $null = $fx.AppendLine("# Suggested remediation for WinTriage $($script:Version) - $($script:HostInfo.Computer) - $(Format-When $started)")
    $null = $fx.AppendLine('#')
    $null = $fx.AppendLine('# NOTHING in this file runs as is: every command is commented out on purpose.')
    $null = $fx.AppendLine('# Read each block, confirm the finding is really unwanted, then uncomment what you accept.')
    $null = $fx.AppendLine('# Collect evidence before deleting anything, and keep this file with the report.')
    $null = $fx.AppendLine('# Most of these commands need an administrator PowerShell.')
    $null = $fx.AppendLine('')
    foreach ($f in @($sorted | Where-Object { $_.Severity -ne 'Info' })) {
        $null = $fx.AppendLine('# ' + ('=' * 86))
        $null = $fx.AppendLine("# [$($f.Severity)] $($CatLabel[$f.Category].en) - $($f.Title.en)")
        if ($f.Detail.en) { $null = $fx.AppendLine("#   $($f.Detail.en)") }
        foreach ($l in @("$($f.Evidence.en)" -split "`n")) { if ($l.Trim()) { $null = $fx.AppendLine("#   | $l") } }
        if ($f.Advice.en) { $null = $fx.AppendLine("#   -> $($f.Advice.en)") }
        $null = $fx.AppendLine("#   key: $($f.Key)")
        $cmds = @()
        if ($f.Fix) { $cmds += $f.Fix }
        else {
            # Derive a candidate command from the evidence block when the finding carries no fix
            $ev = "$($f.Evidence.en)"
            foreach ($line in ($ev -split "`n")) {
                if ($line -match '^(Key|Clé)\s*:\s*(\S.*)$') {
                    $k = $Matches[2].Trim() -replace '^HKLM:?\\', 'HKLM:\' -replace '^Registry::', ''
                    if ($ev -match '(?m)^(Value|Valeur)\s*:\s*([^=\r\n]+?)\s*=') { $cmds += "Remove-ItemProperty -LiteralPath '$k' -Name '$($Matches[2].Trim())'   # check the value first" }
                    else { $cmds += "Get-Item -LiteralPath '$k' | Format-List *   # inspect, then Remove-Item if unwanted" }
                }
                elseif ($line -match '^(File|Fichier|Path|Chemin|Binary|Binaire|DLL)\s*:\s*([A-Za-z]:\\\S.*)$') {
                    $p = $Matches[2].Trim()
                    $cmds += "Get-FileHash -LiteralPath '$p' -Algorithm SHA256   # submit to VirusTotal before deleting"
                    $cmds += "# Remove-Item -LiteralPath '$p'"
                }
                elseif ($line -match '^(Service)\s*:\s*(\S+)') { $cmds += "Get-Service -Name '$($Matches[2])' | Format-List *   # then: sc.exe delete $($Matches[2])" }
                elseif ($line -match '^(Task|Tâche)\s*:\s*(\S.*)$') { $cmds += "Get-ScheduledTask | Where-Object TaskName -eq '$(Split-Path $Matches[2].Trim() -Leaf)' | Format-List *" }
            }
        }
        if (-not $cmds.Count) { $null = $fx.AppendLine('#   (no command suggested: handle it by hand)') }
        foreach ($c in ($cmds | Select-Object -Unique -First 4)) { $null = $fx.AppendLine('# ' + ($c -replace '^#\s*', '')) }
        $null = $fx.AppendLine('')
    }
    [IO.File]::WriteAllText("$base.fix.ps1", $fx.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

if (-not $NoHtml) {
    $data = [ordered]@{
        lang = $Language; version = $script:Version; computer = $script:HostInfo.Computer; os = $script:HostInfo.OS
        user = $script:HostInfo.User; admin = [bool]$script:IsAdmin; domain = $domain; days = $Days; duration = $duration
        started = @{ en = $started.ToString('yyyy-MM-dd HH:mm'); fr = $started.ToString('dd/MM/yyyy HH:mm') }
        verdict = $verdictKey; verdicts = $verdictText; counts = $count; sevs = $SevLabel; cats = $CatLabel
        profiles = $profiles
        findings = @($sorted | ForEach-Object { [ordered]@{ s = $_.Severity; c = $_.Category; t = $_.Title; d = $_.Detail; e = $_.Evidence; a = $_.Advice; k = $_.Key; n = [bool]$_.New } })
        checks = @($checksOut | ForEach-Object { [ordered]@{ n = $_.Name; x = $_.Examined; r = $_.Results; d = $_.Seconds; err = $_.Error; notes = @($_.Notes) } })
        timeline = @($timeline | ForEach-Object { [ordered]@{ w = $_.When; c = $_.Category; s = $_.Severity; t = $_.What } })
        suppressed = @($suppressed | ForEach-Object { [ordered]@{ s = $_.Severity; c = $_.Category; t = $_.Title; k = $_.Key
                                                                  reason = "$($_.Suppressed.Reason)"; author = "$($_.Suppressed.Author)"; expires = "$($_.Suppressed.Expires)" } })
        expired = @($expiredRules | ForEach-Object { [ordered]@{ title = "$($_.Title)"; expires = "$($_.Expires)"; reason = "$($_.Reason)"; author = "$($_.Author)" } })
        baseline = [ordered]@{ file = $(if ($baselineFile) { Split-Path $baselineFile -Leaf } else { '' })
                               newCount = $newCount; hiddenKnown = $hiddenKnown; newOnly = [bool]($NewOnly -and $baselineFile) }
    }
    $json = ($data | ConvertTo-Json -Depth 8 -Compress) -replace '<', '<' -replace '>', '>' -replace '&', '&'
    $tpl = @'
<!doctype html>
<html lang="__LANG__"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinTriage</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--mut:#5c6b7a;--line:#dde2e8;--crit:#b00020;--high:#c2410c;--med:#a16207;--info:#51627a;--ok:#15803d}
@media(prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b222b;--fg:#e6eaf0;--mut:#9aa8b8;--line:#2c3644;--crit:#ff6b81;--high:#fb923c;--med:#facc15;--info:#93a4ba;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0;overflow-wrap:anywhere}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
.lang{display:flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--card);flex:none}
.lang button{border:0;background:transparent;color:var(--mut);font:inherit;font-weight:600;padding:7px 14px;cursor:pointer}
.lang button+button{border-left:1px solid var(--line)}.lang button.on{background:var(--info);color:var(--card)}
.verdict{font-size:18px;font-weight:600;border-left:6px solid var(--ok)}
.verdict.critical{border-left-color:var(--crit)}.verdict.high{border-left-color:var(--high)}.verdict.medium{border-left-color:var(--med)}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.tile{text-align:center;cursor:pointer;user-select:none}.tile b{display:block;font-size:28px}
.tile.off{opacity:.4}.Critical b,.sev.Critical{color:var(--crit)}.High b,.sev.High{color:var(--high)}.Medium b,.sev.Medium{color:var(--med)}.Info b,.sev.Info{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.f{border-left:5px solid var(--info)}.f.Critical{border-left-color:var(--crit)}.f.High{border-left-color:var(--high)}.f.Medium{border-left-color:var(--med)}.scroll{overflow-x:auto}
.f h3{font-size:15px;margin:0 0 4px;overflow-wrap:anywhere}.sev{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-right:8px}
.cat{font-size:12px;color:var(--mut)}pre{margin:8px 0 0;padding:10px;background:var(--bg);border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.45 Consolas,monospace}
.adv{margin-top:8px;font-size:14px}.adv b{color:var(--mut)}input[type=search]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit;margin:10px 0}
.err{color:var(--crit)}@media(max-width:600px){.tiles{grid-template-columns:repeat(2,1fr)}}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0 0}
.btn{border:1px solid var(--line);background:var(--card);color:var(--fg);font:inherit;font-size:13px;padding:6px 11px;border-radius:7px;cursor:pointer}
.btn.on{background:var(--info);color:var(--card);border-color:var(--info)}.btn:hover{border-color:var(--info)}
.new{font-size:11px;font-weight:700;letter-spacing:.04em;color:var(--card);background:var(--high);border-radius:4px;padding:1px 6px;margin-left:6px;vertical-align:1px}
.tri{float:right;display:flex;gap:6px}.tri .btn{font-size:12px;padding:3px 8px}
.key{font:11px/1 Consolas,monospace;color:var(--mut);margin-left:8px}
.tl{margin:0;padding:0;list-style:none;font-size:14px}
.tl li{display:flex;gap:10px;padding:5px 0;border-bottom:1px solid var(--line)}
.tl time{flex:none;width:118px;color:var(--mut);font-variant-numeric:tabular-nums}
.tl .sev{flex:none;width:68px;margin:0}
.sup{border-left:5px solid var(--ok);font-size:14px}.sup b{font-weight:600}
textarea{width:100%;min-height:120px;font:12px/1.45 Consolas,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px}
@media print{.tile,input,.lang,.bar,.tri{display:none}}
</style></head><body><main id="app"></main>
<script>
/* Report renderer. Plain ES5 on purpose: the page must open anywhere, offline. */
var D = __DATA__;
var SEVS = ['Critical', 'High', 'Medium', 'Info'];
var S = {
  en: {
    title: 'WinTriage report', ranOn: 'run on', by: 'by', admin: '(administrator)',
    noAdmin: '(WITHOUT administrator rights: partial analysis)',
    tilesHint: 'Click a tile to show or hide a level. "Info" items (inventory) are hidden by default.',
    search: 'Filter: file name, category, keyword...', results: 'Findings', none: 'Nothing found.',
    todo: 'What to do:', checksTitle: 'Checks performed', thCheck: 'Check', thItems: 'Items examined',
    thFindings: 'Findings', thTime: 'Duration', thNotes: 'Notes', interrupted: 'Check interrupted:',
    scope: 'Scope', profiles: 'Profiles analysed:', notLoaded: '(registry not loaded)',
    period: 'Period:', periodText: 'last {d} days for event logs and recent files.',
    limitsTitle: 'Limitations',
    limits: 'This tool complements an antivirus, it does not replace it. It examines the most used persistence locations and known traces: a report without alerts does not prove the machine is clean (rootkits, in-memory implants, techniques not covered). A "Medium" item calls for a check, not necessarily for action. HWID and TSforge activations leave almost no distinctive trace.',
    newBadge: 'NEW', newSince: '{n} new since {f}', newOnly: 'New only', hideAccepted: 'Hide accepted',
    reviewed: 'Reviewed', accept: 'Accept', accepted: 'Accepted', clearTriage: 'Clear my marks',
    exportTriage: 'Export my decisions', exportHint: 'Paste the block below into allowlist.psd1 so the accepted findings stop coming back. The JSON above keeps the full decision list.',
    timelineTitle: 'Timeline', timelineEmpty: 'No dated event was collected.',
    suppressedTitle: 'Suppressed by the allowlist ({n})', suppressedHint: 'Accepted on purpose, listed here so nothing is hidden silently.',
    expiredTitle: 'Expired suppression rules ({n})', expiredHint: 'These rules no longer apply, so their findings are back in the list above.',
    knownHidden: '{n} known finding(s) hidden', reason: 'Reason', by: 'Accepted by', until: 'Until',
    footer: 'WinTriage {v} - report generated in {s} s - no change made to the system.'
  },
  fr: {
    title: 'Rapport WinTriage', ranOn: 'lancé le', by: 'par', admin: '(administrateur)',
    noAdmin: '(SANS droits administrateur : analyse partielle)',
    tilesHint: 'Cliquer sur une tuile pour afficher ou masquer un niveau. Les éléments « Info » (inventaire) sont masqués par défaut.',
    search: 'Filtrer : nom de fichier, catégorie, mot-clé...', results: 'Résultats', none: 'Aucun résultat.',
    todo: 'Que faire :', checksTitle: 'Contrôles effectués', thCheck: 'Contrôle', thItems: 'Éléments examinés',
    thFindings: 'Résultats', thTime: 'Durée', thNotes: 'Remarques', interrupted: 'Contrôle interrompu :',
    scope: 'Périmètre', profiles: 'Profils analysés :', notLoaded: '(registre non chargé)',
    period: 'Période :', periodText: '{d} derniers jours pour les journaux et les fichiers récents.',
    limitsTitle: 'Limites',
    limits: 'Cet outil complète un antivirus, il ne le remplace pas. Il examine les emplacements de persistance les plus utilisés et des traces connues : un rapport sans alerte ne prouve pas que la machine est saine (rootkits, implants en mémoire, techniques non couvertes). Un élément « Moyen » demande une vérification, pas forcément une action. Les activations HWID et TSforge ne laissent presque aucune trace distinctive.',
    newBadge: 'NOUVEAU', newSince: '{n} nouveau(x) depuis {f}', newOnly: 'Nouveaux seulement', hideAccepted: 'Masquer les acceptés',
    reviewed: 'Vu', accept: 'Accepter', accepted: 'Accepté', clearTriage: 'Effacer mes marques',
    exportTriage: 'Exporter mes décisions', exportHint: "Coller le bloc ci-dessous dans allowlist.psd1 pour que les résultats acceptés ne reviennent plus. Le JSON au-dessus conserve la liste complète des décisions.",
    timelineTitle: 'Chronologie', timelineEmpty: "Aucun événement daté n'a été collecté.",
    suppressedTitle: "Supprimés par l'allowlist ({n})", suppressedHint: "Acceptés volontairement, listés ici pour que rien ne soit masqué en silence.",
    expiredTitle: 'Règles de suppression expirées ({n})', expiredHint: "Ces règles ne s'appliquent plus : leurs résultats sont revenus dans la liste ci-dessus.",
    knownHidden: '{n} résultat(s) connu(s) masqué(s)', reason: 'Motif', by: 'Accepté par', until: "Jusqu'au",
    footer: 'WinTriage {v} - rapport généré en {s} s - aucune modification apportée au système.'
  }
};
var lang = D.lang === 'fr' ? 'fr' : 'en';
try { var saved = localStorage.getItem('wintriage.lang'); if (saved === 'en' || saved === 'fr') { lang = saved; } } catch (e) {}
var off = { Info: true };     /* severities hidden right now */
var filter = '';
var newOnly = !!(D.baseline && D.baseline.newOnly);
var hideOk = false;
/* Triage marks, per host, kept in this browser: 'seen' or 'ok' per finding key */
var TKEY = 'wintriage.triage.' + D.computer;
var marks = {};
try { marks = JSON.parse(localStorage.getItem(TKEY) || '{}') || {}; } catch (e) { marks = {}; }
function saveMarks() { try { localStorage.setItem(TKEY, JSON.stringify(marks)); } catch (e) {} }

function arr(v) { if (Object.prototype.toString.call(v) === '[object Array]') { return v; } return v ? [v] : []; }
function tx(o) { return o ? (o[lang] || o.en || '') : ''; }
function t(k) { return S[lang][k]; }
function sev(k) { return tx(D.sevs[k]); }
function cat(k) { return D.cats[k] ? tx(D.cats[k]) : k; }
function esc(s) {
  return String(s === null || s === undefined ? '' : s).replace(/[&<>"]/g, function (c) {
    return c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&quot;';
  });
}

function header() {
  var who = D.admin ? esc(t('admin')) : '<b class="err">' + esc(t('noAdmin')) + '</b>';
  var h = '<div class="top"><div><h1>' + esc(t('title')) + '</h1>';
  h += '<div class="mut">' + esc(D.computer) + ' · ' + esc(D.os) + ' · ' + esc(tx(D.domain)) + ' · ';
  h += esc(t('ranOn')) + ' ' + esc(tx(D.started)) + ' ' + esc(t('by')) + ' ' + esc(D.user) + ' ' + who + '</div></div>';
  h += '<div class="lang">';
  h += '<button type="button" data-lang="en"' + (lang === 'en' ? ' class="on"' : '') + '>EN</button>';
  h += '<button type="button" data-lang="fr"' + (lang === 'fr' ? ' class="on"' : '') + '>FR</button>';
  h += '</div></div>';
  h += '<div class="card verdict ' + D.verdict + '">' + esc(tx(D.verdicts[D.verdict])) + '</div><div class="tiles">';
  for (var i = 0; i < SEVS.length; i++) {
    var s = SEVS[i];
    h += '<div class="card tile ' + s + (off[s] ? ' off' : '') + '" data-sev="' + s + '"><b>' + (D.counts[s] || 0) + '</b>' + esc(sev(s)) + '</div>';
  }
  h += '</div><div class="mut">' + esc(t('tilesHint')) + '</div>';
  /* Baseline line and the filters that go with it */
  if (D.baseline && D.baseline.file) {
    h += '<div class="mut">' + esc(t('newSince').replace('{n}', D.baseline.newCount).replace('{f}', D.baseline.file));
    if (D.baseline.hiddenKnown) { h += ' · ' + esc(t('knownHidden').replace('{n}', D.baseline.hiddenKnown)); }
    h += '</div>';
  }
  h += '<div class="bar">';
  if (D.baseline && D.baseline.file) { h += '<button type="button" class="btn' + (newOnly ? ' on' : '') + '" id="bNew">' + esc(t('newOnly')) + '</button>'; }
  h += '<button type="button" class="btn' + (hideOk ? ' on' : '') + '" id="bOk">' + esc(t('hideAccepted')) + '</button>';
  h += '<button type="button" class="btn" id="bExp">' + esc(t('exportTriage')) + '</button>';
  h += '<button type="button" class="btn" id="bClr">' + esc(t('clearTriage')) + '</button>';
  h += '</div><div id="exp"></div>';
  return h + '<input type="search" id="q" placeholder="' + esc(t('search')) + '" value="' + esc(filter) + '">';
}

function findings() {
  var list = arr(D.findings), h = '<h2>' + esc(t('results')) + '</h2><div id="list">';
  for (var i = 0; i < list.length; i++) {
    var f = list[i], m = marks[f.k] || '';
    h += '<div data-key="' + esc(f.k) + '" data-new="' + (f.n ? '1' : '0') + '" data-mark="' + m + '" class="card f ' + f.s + '" data-sev="' + f.s + '">';
    h += '<div class="tri"><button type="button" class="btn tbtn' + (m === 'seen' ? ' on' : '') + '" data-set="seen" data-k="' + esc(f.k) + '">' + esc(t('reviewed')) + '</button>';
    h += '<button type="button" class="btn tbtn' + (m === 'ok' ? ' on' : '') + '" data-set="ok" data-k="' + esc(f.k) + '">' + esc(m === 'ok' ? t('accepted') : t('accept')) + '</button></div>';
    h += '<span class="sev ' + f.s + '">' + esc(sev(f.s)) + '</span><span class="cat">' + esc(cat(f.c)) + '</span>';
    if (f.n && D.baseline && D.baseline.file) { h += '<span class="new">' + esc(t('newBadge')) + '</span>'; }
    h += '<h3>' + esc(tx(f.t)) + '</h3>';
    if (tx(f.d)) { h += '<div>' + esc(tx(f.d)) + '</div>'; }
    if (tx(f.e)) { h += '<pre>' + esc(tx(f.e)) + '</pre>'; }
    if (tx(f.a)) { h += '<div class="adv"><b>' + esc(t('todo')) + '</b> ' + esc(tx(f.a)) + '</div>'; }
    h += '<span class="key">' + esc(f.k) + '</span>';
    h += '</div>';
  }
  if (!list.length) { h += '<div class="card">' + esc(t('none')) + '</div>'; }
  return h + '</div>';
}

function timeline() {
  var list = arr(D.timeline);
  var h = '<h2>' + esc(t('timelineTitle')) + '</h2><div class="card">';
  if (!list.length) { return h + esc(t('timelineEmpty')) + '</div>'; }
  h += '<ul class="tl">';
  for (var i = 0; i < list.length; i++) {
    var e = list[i];
    h += '<li><time>' + esc(e.w) + '</time><span class="sev ' + e.s + '">' + esc(sev(e.s)) + '</span>';
    h += '<span>' + esc(tx(e.t)) + ' <span class="cat">' + esc(cat(e.c)) + '</span></span></li>';
  }
  return h + '</ul></div>';
}

function suppressed() {
  var list = arr(D.suppressed), exp = arr(D.expired), h = '';
  if (list.length) {
    h += '<h2>' + esc(t('suppressedTitle').replace('{n}', list.length)) + '</h2>';
    h += '<div class="mut">' + esc(t('suppressedHint')) + '</div>';
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      h += '<div class="card sup"><span class="sev ' + f.s + '">' + esc(sev(f.s)) + '</span><span class="cat">' + esc(cat(f.c)) + '</span>';
      h += '<br><b>' + esc(tx(f.t)) + '</b><br><span class="mut">' + esc(t('reason')) + ': ' + esc(f.reason || '-');
      h += ' · ' + esc(t('by')) + ': ' + esc(f.author || '-');
      if (f.expires) { h += ' · ' + esc(t('until')) + ': ' + esc(f.expires); }
      h += '</span><span class="key">' + esc(f.k) + '</span></div>';
    }
  }
  if (exp.length) {
    h += '<h2 class="err">' + esc(t('expiredTitle').replace('{n}', exp.length)) + '</h2>';
    h += '<div class="mut">' + esc(t('expiredHint')) + '</div><div class="card">';
    for (var j = 0; j < exp.length; j++) {
      h += '<div>' + esc(exp[j].title) + ' <span class="mut">(' + esc(t('until')) + ' ' + esc(exp[j].expires || '-') + ', ' + esc(exp[j].author || '-') + ')</span></div>';
    }
    h += '</div>';
  }
  return h;
}

function checks() {
  var list = arr(D.checks);
  var h = '<h2>' + esc(t('checksTitle')) + '</h2><div class="card scroll"><table><tr><th>' + esc(t('thCheck'));
  h += '</th><th class="n">' + esc(t('thItems')) + '</th><th class="n">' + esc(t('thFindings'));
  h += '</th><th class="n">' + esc(t('thTime')) + '</th><th>' + esc(t('thNotes')) + '</th></tr>';
  for (var i = 0; i < list.length; i++) {
    var c = list[i], notes = [], n = arr(c.notes);
    if (c.err) { notes.push('<span class="err">' + esc(t('interrupted')) + ' ' + esc(c.err) + '</span>'); }
    for (var j = 0; j < n.length; j++) { notes.push(esc(tx(n[j]))); }
    h += '<tr><td>' + esc(cat(c.n)) + '</td><td class="n">' + c.x + '</td><td class="n">' + c.r;
    h += '</td><td class="n">' + c.d + ' s</td><td>' + notes.join('<br>') + '</td></tr>';
  }
  return h + '</table></div>';
}

function scope() {
  var p = arr(D.profiles), lines = [];
  for (var i = 0; i < p.length; i++) { lines.push(esc(p[i].path) + (p[i].loaded ? '' : ' ' + esc(t('notLoaded')))); }
  var h = '<h2>' + esc(t('scope')) + '</h2><div class="card"><b>' + esc(t('profiles')) + '</b><br>' + lines.join('<br>');
  h += '<br><br><b>' + esc(t('period')) + '</b> ' + esc(t('periodText').replace('{d}', D.days)) + '</div>';
  h += '<h2>' + esc(t('limitsTitle')) + '</h2><div class="card mut">' + esc(t('limits')) + '<br><br>';
  return h + esc(t('footer').replace('{v}', D.version).replace('{s}', D.duration)) + '</div>';
}

function applyFilter() {
  var q = filter.toLowerCase(), nodes = document.querySelectorAll('#list .f');
  for (var i = 0; i < nodes.length; i++) {
    var e = nodes[i], txt = (e.textContent || e.innerText || '').toLowerCase();
    var k = e.getAttribute('data-key'), m = marks[k] || '';
    var hidden = off[e.getAttribute('data-sev')] || (q && txt.indexOf(q) < 0);
    if (newOnly && e.getAttribute('data-new') !== '1') { hidden = true; }
    if (hideOk && m === 'ok') { hidden = true; }
    e.style.display = hidden ? 'none' : '';
    e.style.opacity = m === 'ok' ? '0.5' : '';
  }
}

function onLang() {
  lang = this.getAttribute('data-lang');
  try { localStorage.setItem('wintriage.lang', lang); } catch (e) {}
  render();
}

function onTile() {
  var s = this.getAttribute('data-sev');
  if (off[s]) { delete off[s]; } else { off[s] = true; }
  this.className = 'card tile ' + s + (off[s] ? ' off' : '');
  applyFilter();
}

function onMark() {
  var k = this.getAttribute('data-k'), want = this.getAttribute('data-set');
  marks[k] = (marks[k] === want) ? '' : want;
  if (!marks[k]) { delete marks[k]; }
  saveMarks();
  render();
}

/* My decisions, as JSON plus a block ready for allowlist.psd1 */
function exportTriage() {
  var list = arr(D.findings), out = [], snip = [], i, f, m;
  for (i = 0; i < list.length; i++) {
    f = list[i]; m = marks[f.k];
    if (!m) { continue; }
    out.push({ key: f.k, state: m, severity: f.s, category: f.c, title: f.t.en });
    if (m === 'ok') {
      snip.push("        @{ Key = '" + f.k + "'; Reason = 'TODO: why this is accepted'; Author = '" + (D.user || '') +
                "'; Expires = 'YYYY-MM-DD' }   # " + f.t.en.replace(/[\r\n]+/g, ' '));
    }
  }
  var doc = { tool: 'WinTriage ' + D.version, computer: D.computer, exported: new Date().toISOString(), decisions: out };
  var text = JSON.stringify(doc, null, 2);
  var box = document.getElementById('exp');
  var h = '<div class="card"><textarea readonly>' + esc(text) + '</textarea>';
  if (snip.length) {
    h += '<div class="mut" style="margin:8px 0">' + esc(t('exportHint')) + '</div>';
    h += '<textarea readonly>@{\n    Suppress = @(\n' + esc(snip.join('\n')) + '\n    )\n}</textarea>';
  }
  box.innerHTML = h + '</div>';
  /* Offer the JSON as a file too, when the browser allows it from a local page */
  try {
    var blob = new Blob([text], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'wintriage-triage-' + D.computer + '.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  } catch (e) {}
}

function render() {
  document.documentElement.lang = lang;
  document.title = t('title') + ' - ' + D.computer;
  document.getElementById('app').innerHTML = header() + findings() + timeline() + checks() + scope() + suppressed();
  var i, b = document.querySelectorAll('.lang button');
  for (i = 0; i < b.length; i++) { b[i].onclick = onLang; }
  var tiles = document.querySelectorAll('.tile');
  for (i = 0; i < tiles.length; i++) { tiles[i].onclick = onTile; }
  var tb = document.querySelectorAll('.tbtn');
  for (i = 0; i < tb.length; i++) { tb[i].onclick = onMark; }
  var bn = document.getElementById('bNew');
  if (bn) { bn.onclick = function () { newOnly = !newOnly; render(); }; }
  document.getElementById('bOk').onclick = function () { hideOk = !hideOk; render(); };
  document.getElementById('bExp').onclick = exportTriage;
  document.getElementById('bClr').onclick = function () { marks = {}; saveMarks(); render(); };
  var q = document.getElementById('q');
  q.oninput = function () { filter = q.value; applyFilter(); };
  applyFilter();
}

render();
</script></body></html>
'@
    $html = $tpl.Replace('__LANG__', $Language).Replace('__DATA__', $json)
    [IO.File]::WriteAllText("$base.html", $html, (New-Object System.Text.UTF8Encoding($true)))
}

# =====================================================================================
#  Console summary
# =====================================================================================
Write-Host ''
Write-Host "== $($verdictText[$verdictKey].en) ==" -ForegroundColor $(if ($count['Critical'] -or $count['High']) { 'Red' } elseif ($count['Medium']) { 'Yellow' } else { 'Green' })
Write-Host ('Critical: {0}   High: {1}   Medium: {2}   Info: {3}' -f $count['Critical'], $count['High'], $count['Medium'], $count['Info'])
if ($baselineFile) {
    Write-Host ("New since $(Split-Path $baselineFile -Leaf): {0}{1}" -f $newCount, $(if ($hiddenKnown) { " (and $hiddenKnown known finding(s) hidden)" })) -ForegroundColor $(if ($newCount) { 'Yellow' } else { 'Green' })
}
if ($suppressed.Count) { Write-Host "Suppressed by the allowlist: $($suppressed.Count)" -ForegroundColor DarkGray }
if ($expiredRules.Count) { Write-Host "$($expiredRules.Count) suppression rule(s) expired: their findings are back in the list." -ForegroundColor Yellow }
foreach ($f in @($sorted | Where-Object { $_.Severity -in 'Critical', 'High' } | Select-Object -First 25)) {
    Write-Host ('  [{0}] {1} {2} {3}' -f $SevLabel[$f.Severity].en.ToUpper(), $CatLabel[$f.Category].en, [char]0x2014, $f.Title.en) -ForegroundColor $(if ($f.Severity -eq 'Critical') { 'Magenta' } else { 'Red' })
}
$errs = @($script:Checks | Where-Object { $_.Error })
if ($errs.Count) { Write-Host "$($errs.Count) check(s) interrupted by an error: see the report." -ForegroundColor Magenta }
Write-Host ''
if (-not $NoHtml) { Write-Host "HTML report: $base.html" }
Write-Host "JSON data:   $base.json"
if ($FixScript) { Write-Host "Fix script:  $base.fix.ps1 (every command commented out: read before use)" }

if ($PassThru) { $sorted }
if ($count['Critical'] -or $count['High']) { exit 2 } elseif ($count['Medium']) { exit 1 } else { exit 0 }
