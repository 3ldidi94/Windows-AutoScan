@{
    # =====================================================================
    #  Indicators used by Invoke-WinTriage.ps1
    #  Data file only: extend it as incidents come in.
    #  The MAS indicators were taken from MAS_AIO.cmd (commit 6cfd6f45).
    #  Report text is bilingual: labels carry an 'en' and a 'fr' variant.
    # =====================================================================

    # Activator keyword: matched against the names and commands of tasks, services, Run keys and processes
    ActivatorRegex = '(?i)kms[-_ ]?pico|autopico|kmsauto|autokms|kms[-_]vl[-_]all|kmseldi|secoh-qad|vlmcsd|sppextcomobj(hook|patcher)|activation-renewal|activation_task\.cmd|online_kms_activation|mas_aio|massgrave|activated\.win|kmsnano|kms360|re-loader|microsoft toolkit|ohook|tsforge|hwid_activation'

    # Marks a logged PowerShell script block as coming from WinTriage's own test suite rather than
    # from a real session, so a scan never flags the self-test it (or a previous run) just executed.
    SelfTestRegex = '(?i)\\tests\\(Mocks\.ps1|Run-SelfTest\.ps1|Test-ReportRender\.js)\b|\bWINTRIAGE_SCENARIO\b|\$script:MockReg\b|function\s+Invoke-(Scenario|FeatureTests)\b'

    # Scheduled tasks (name, wildcards accepted)
    ActivatorTaskNames = @(
        'Activation-Renewal', 'Activation-Run_Once',                  # MAS Online KMS
        'Online_KMS_Activation_Script-Renewal', 'Online_KMS_Activation_Script-Run_Once',
        'AutoKMS*', 'AutoPico*', 'KMSAuto*', 'KMSpico*', 'KMS_VL_ALL*', 'SppExtComObjPatcher*', 'KMSELDI*'
    )
    ActivatorTaskFolders = @('\R@1n-KMS\')

    # Files and folders (environment variables and wildcards accepted)
    ActivatorPaths = @(
        '%ProgramFiles%\Activation-Renewal',                          # MAS Online KMS
        '%ProgramData%\Online_KMS_Activation.cmd',
        '%ProgramData%\Online_KMS_Activation',
        '%SystemRoot%\Temp\MAS_*.cmd',                                # temporary copy of the MAS launcher
        '%ProgramFiles%\KMSpico', '%ProgramFiles(x86)%\KMSpico', '%ProgramData%\KMSpico',
        '%ProgramData%\KMSAuto*', '%SystemRoot%\KMSAuto*', '%SystemRoot%\AutoKMS',
        '%ProgramFiles%\KMSnano', '%ProgramFiles%\Microsoft Toolkit',
        '%SystemRoot%\SECOH-QAD.exe', '%SystemRoot%\SECOH-QAD.dll',
        '%SystemRoot%\System32\SECOH-QAD.exe', '%SystemRoot%\System32\SECOH-QAD.dll',
        '%SystemRoot%\System32\SppExtComObjHook.dll', '%SystemRoot%\System32\SppExtComObjPatcher.exe',
        '%SystemRoot%\System32\SppExtComObjPatcher.dll',
        '%SystemRoot%\vlmcsd.exe', '%SystemRoot%\System32\vlmcsd.exe'
    )

    # Services (name, wildcards accepted)
    ActivatorServices = @('KMSELDI', 'Service KMSELDI', 'KMSAuto*', 'AutoKMS', 'vlmcsd', 'KMSEmulator', 'KMSServerService', 'SppExtComObjPatcher', 'KMS-R@1n')

    # Dummy KMS addresses written by activators
    #   10.0.0.10: MAS (Ohook / Online KMS, "non-existent address")    127.0.0.2: MAS (KMS38 lock)
    KmsPlaceholderHosts = @('10.0.0.10', '127.0.0.2', '127.0.0.1', '0.0.0.0', 'localhost', '1.2.3.4', '10.3.0.20', '172.16.0.2')

    # Public pirate KMS servers (regex). Explicit list: a generic 'kms.' pattern would wrongly flag a corporate KMS.
    PublicKmsRegex = '(?i)msguides\.com|digiboy\.ir|03k\.org|loli\.(beer|best)|chinancce\.com|cangshui\.net|moeclub\.org|lotro\.cc|ghpym\.com|mogeko\.me|luody\.info|sixyin\.com|wxlost\.com|library\.hk|shuax\.com|crsoo\.com|zhuxiaole\.org|zhang\.yt|^222\.184\.9\.98$'

    # Microsoft licensing domains: finding them in the hosts file means they were blocked on purpose
    LicensingHosts = @('ols.officeapps.live.com', 'activation.sls.microsoft.com', 'activation-v2.sls.microsoft.com',
                       'validation.sls.microsoft.com', 'validation-v2.sls.microsoft.com', 'licensing.mp.microsoft.com',
                       'purchase.mp.microsoft.com', 'displaycatalog.mp.microsoft.com', 'officeclient.microsoft.com',
                       'genuine.microsoft.com', 'go.microsoft.com', 'mpa.one.microsoft.com')

    # Domains whose redirection in hosts cuts off updates or the antivirus (regex)
    SecurityHostsRegex = '(?i)windowsupdate|update\.microsoft|defender|smartscreen|virustotal|kaspersky|eset\.|avast|avg\.|bitdefender|malwarebytes|sophos|symantec|norton|mcafee|trendmicro|crowdstrike|sentinelone'

    # Antivirus detections tied to activators (regex on the threat name)
    ActivatorThreatRegex = '(?i)autokms|kmspico|kmsauto|hacktool.*(kms|activator|patcher)|keygen|crack|activator|wpakill'

    # PowerShell history and logged script blocks.
    # Severity: Critical | High | Medium      Category: a check key (Activators, PowerShellHistory, ...)
    HistoryPatterns = @(
        @{ Label = @{ en = 'Fake MAS domain (typosquat that spread Cosmali Loader / XWorm)'
                      fr = 'Faux domaine MAS (typosquat qui a diffusé Cosmali Loader / XWorm)' }
           Regex = '(?i)get\.activate\.win|activated?\.(wim|vin|w1n)\b|massgrave\.(com|net|org|co)\b'
           Severity = 'Critical'; Category = 'Activators' }
        @{ Label = @{ en = 'Microsoft Activation Scripts (MAS) launched'
                      fr = 'Lancement de Microsoft Activation Scripts (MAS)' }
           Regex = '(?i)activated\.win|massgrave\.dev|MAS_AIO|massgravel'
           Severity = 'High'; Category = 'Activators' }
        @{ Label = @{ en = 'Other activator or KMS tampering'
                      fr = 'Autre activateur ou manipulation KMS' }
           Regex = '(?i)kms[-_ ]?pico|kmsauto|kms_vl_all|slmgr(\.vbs)?\s+[/-](skms|ipk)|ospp\.vbs.+[/-](sethst|inpkey)'
           Severity = 'High'; Category = 'Activators' }
        @{ Label = @{ en = 'Download executed straight in memory'
                      fr = 'Téléchargement exécuté directement en mémoire' }
           Regex = '(?i)\b(irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\b[^|]{0,300}\|\s*(iex|invoke-expression)\b|iex\s*\(?\s*\(?\s*(new-object\s+net\.webclient|irm|iwr)|downloadstring\s*\('
           Severity = 'High'; Category = 'PowerShellHistory' }
        @{ Label = @{ en = 'Encoded command'; fr = 'Commande encodée' }
           Regex = '(?i)\s-(e|ec|enc|enco[a-z]*)\s+[A-Za-z0-9+/=]{40,}|frombase64string\s*\('
           Severity = 'Medium'; Category = 'PowerShellHistory' }
        @{ Label = @{ en = 'Antivirus switched off'; fr = "Désactivation de l'antivirus" }
           Regex = '(?i)set-mppreference\s+.*-disable\w+\s+(\$true|1)\b|reg(\.exe)?\s+add\s+.*windows defender.*/v\s+disable\w+.*/d\s+1\b|set-itemproperty\s+.*windows defender.*disable\w+.*-value\s+1\b|sc(\.exe)?\s+(stop|config|delete)\s+(windefend|sense|wscsvc)'
           Severity = 'High'; Category = 'PowerShellHistory' }
        @{ Label = @{ en = 'Antivirus exclusion added'; fr = "Ajout d'exclusion antivirus" }
           Regex = '(?i)add-mppreference\s+.*-exclusion'
           Severity = 'Medium'; Category = 'PowerShellHistory' }
        @{ Label = @{ en = 'Traces wiped'; fr = 'Effacement de traces' }
           Regex = '(?i)wevtutil(\.exe)?\s+cl\b|clear-eventlog|remove-item.+consolehost_history|vssadmin(\.exe)?\s+delete\s+shadows'
           Severity = 'High'; Category = 'PowerShellHistory' }
    )

    # Legitimate history lines: official installers launched through 'irm ... | iex'. A detection whose
    # matching lines all appear here is downgraded to Info.
    HistoryAllowRegex = '(?i)https://(claude\.ai/install\.ps1|get\.scoop\.sh|community\.chocolatey\.org/install\.ps1|astral\.sh/uv/install\.ps1|bun\.sh/install\.ps1|deno\.land/install\.ps1|aka\.ms/install-powershell\.ps1|win\.rustup\.rs|ohmyposh\.dev/install\.ps1|dot\.net/v1/dotnet-install\.ps1)\b'

    # Kernel drivers known to be abused for BYOVD ("bring your own vulnerable driver"): they hand kernel
    # access to whoever loads them. Several ship with legitimate monitoring, overclocking or RGB tools,
    # so a match is a question, not a verdict. Matched on the file name of the driver.
    VulnerableDriverRegex = '(?i)^(rtcore64|gdrv|dbutil_2_3|dbutildrv2|winio\d*|winring0x?\d*|asrdrv\d*|asupio|atillk64|iqvw64e|nvoclock|speedfan|mhyprot\d*|kprocesshacker|truesight|viragt64|amifldrv64|glckio2|segwindrvx64|pcdsrvc(_x64)?|hwrwdrv|rwdrv|monitor_win10_x64|atszio64|elrawdsk|nicm|physmem|wincore64|lv56|cpuz\d*|gmer\d*)\.sys$'

    # Browser extension permissions that are enough to drive the browser, read all traffic or reach a
    # local program. Common in legitimate extensions too, hence Medium: the point is to review them.
    BrowserRiskyPermissions = '(?i)^(debugger|proxy|nativeMessaging|management|desktopCapture|tabCapture|privacy|contentSettings|certificateProvider|enterprise\.\w+)$'

    # Command-line options injected into a browser shortcut by adware: they load an extension from
    # disk, switch off web security or route the traffic elsewhere.
    BrowserHijackArgsRegex = '(?i)--load-extension=|--disable-web-security|--allow-running-insecure-content|--proxy-server=|--proxy-pac-url=|--host-rules=|--host-resolver-rules=|--remote-debugging-(port|pipe)|--user-data-dir=[^ ]*\\(Temp|Public|AppData\\Local\\Temp)|--disable-features=[^ ]*(SafeBrowsing|Isolate)'

    # Trusted root authorities that belong to a TLS inspection product. Legitimate in a company that
    # inspects HTTPS, a serious problem on a machine that should not have one.
    TlsInterceptionCertRegex = '(?i)CN=(fiddler|mitmproxy|charles proxy|burp|portswigger|telerik|netskope|zscaler|blue ?coat|forcepoint|websense|sophos ssl|kaspersky anti-virus personal root|eset ssl filter|avast|avg web|bitdefender personal|dr\.?web|proxyman|squid|sslsplit|packetfence|do_not_trust)'

    # Remote access tools: legitimate, but each one needs validating (regex on services and processes)
    RemoteToolsRegex = '(?i)anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|rustdesk|netsupport|meshagent|ngrok|tailscale|zerotier|ammyy|dwservice|dwagent|remoteutilities|rutserv|logmein|supremo|tightvnc|ultravnc|realvnc|vncserver|radmin|chrome remote desktop|chromoting|quickassist|simplehelp|pdq connect|level\.io|action1|fleetdeck|tacticalrmm'

    # System process names: running from outside System32 / SysWOW64 / Windows means impersonation
    SystemProcessNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'winlogon.exe', 'smss.exe', 'wininit.exe',
                           'spoolsv.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'runtimebroker.exe', 'sihost.exe',
                           'explorer.exe', 'dwm.exe', 'ctfmon.exe', 'fontdrvhost.exe', 'lsm.exe', 'userinit.exe')
}
