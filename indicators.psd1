@{
    # =====================================================================
    #  Indicateurs utilisés par Invoke-WinTriage.ps1
    #  Fichier de données uniquement : à enrichir au fil des incidents.
    #  Les indicateurs MAS ont été relevés dans MAS_AIO.cmd (commit 6cfd6f45).
    # =====================================================================

    # Mot-clé d'activateur : appliqué aux noms et commandes des tâches, services, clés Run, processus
    ActivatorRegex = '(?i)kms[-_ ]?pico|autopico|kmsauto|autokms|kms[-_]vl[-_]all|kmseldi|secoh-qad|vlmcsd|sppextcomobj(hook|patcher)|activation-renewal|activation_task\.cmd|online_kms_activation|mas_aio|massgrave|activated\.win|kmsnano|kms360|re-loader|microsoft toolkit|ohook|tsforge|hwid_activation'

    # Tâches planifiées (nom, jokers acceptés)
    ActivatorTaskNames = @(
        'Activation-Renewal', 'Activation-Run_Once',                  # MAS Online KMS
        'Online_KMS_Activation_Script-Renewal', 'Online_KMS_Activation_Script-Run_Once',
        'AutoKMS*', 'AutoPico*', 'KMSAuto*', 'KMSpico*', 'KMS_VL_ALL*', 'SppExtComObjPatcher*', 'KMSELDI*'
    )
    ActivatorTaskFolders = @('\R@1n-KMS\')

    # Fichiers et dossiers (variables d'environnement et jokers acceptés)
    ActivatorPaths = @(
        '%ProgramFiles%\Activation-Renewal',                          # MAS Online KMS
        '%ProgramData%\Online_KMS_Activation.cmd',
        '%ProgramData%\Online_KMS_Activation',
        '%SystemRoot%\Temp\MAS_*.cmd',                                # copie temporaire du lanceur MAS
        '%ProgramFiles%\KMSpico', '%ProgramFiles(x86)%\KMSpico', '%ProgramData%\KMSpico',
        '%ProgramData%\KMSAuto*', '%SystemRoot%\KMSAuto*', '%SystemRoot%\AutoKMS',
        '%ProgramFiles%\KMSnano', '%ProgramFiles%\Microsoft Toolkit',
        '%SystemRoot%\SECOH-QAD.exe', '%SystemRoot%\SECOH-QAD.dll',
        '%SystemRoot%\System32\SECOH-QAD.exe', '%SystemRoot%\System32\SECOH-QAD.dll',
        '%SystemRoot%\System32\SppExtComObjHook.dll', '%SystemRoot%\System32\SppExtComObjPatcher.exe',
        '%SystemRoot%\System32\SppExtComObjPatcher.dll',
        '%SystemRoot%\vlmcsd.exe', '%SystemRoot%\System32\vlmcsd.exe'
    )

    # Services (nom, jokers acceptés)
    ActivatorServices = @('KMSELDI', 'Service KMSELDI', 'KMSAuto*', 'AutoKMS', 'vlmcsd', 'KMSEmulator', 'KMSServerService', 'SppExtComObjPatcher', 'KMS-R@1n')

    # Adresses KMS factices posées par les activateurs
    #   10.0.0.10 : MAS (Ohook / Online KMS, « adresse inexistante »)    127.0.0.2 : MAS (verrou KMS38)
    KmsPlaceholderHosts = @('10.0.0.10', '127.0.0.2', '127.0.0.1', '0.0.0.0', 'localhost', '1.2.3.4', '10.3.0.20', '172.16.0.2')

    # Serveurs KMS publics pirates (regex). Liste explicite : un motif générique « kms. » signalerait à tort un KMS d'entreprise.
    PublicKmsRegex = '(?i)msguides\.com|digiboy\.ir|03k\.org|loli\.(beer|best)|chinancce\.com|cangshui\.net|moeclub\.org|lotro\.cc|ghpym\.com|mogeko\.me|luody\.info|sixyin\.com|wxlost\.com|library\.hk|shuax\.com|crsoo\.com|zhuxiaole\.org|zhang\.yt|^222\.184\.9\.98$'

    # Domaines de licence Microsoft : leur présence dans le fichier hosts trahit un blocage volontaire
    LicensingHosts = @('ols.officeapps.live.com', 'activation.sls.microsoft.com', 'activation-v2.sls.microsoft.com',
                       'validation.sls.microsoft.com', 'validation-v2.sls.microsoft.com', 'licensing.mp.microsoft.com',
                       'purchase.mp.microsoft.com', 'displaycatalog.mp.microsoft.com', 'officeclient.microsoft.com',
                       'genuine.microsoft.com', 'go.microsoft.com', 'mpa.one.microsoft.com')

    # Domaines dont la redirection dans hosts sert à couper les mises à jour ou l'antivirus (regex)
    SecurityHostsRegex = '(?i)windowsupdate|update\.microsoft|defender|smartscreen|virustotal|kaspersky|eset\.|avast|avg\.|bitdefender|malwarebytes|sophos|symantec|norton|mcafee|trendmicro|crowdstrike|sentinelone'

    # Détections antivirus liées aux activateurs (regex sur le nom de la menace)
    ActivatorThreatRegex = '(?i)autokms|kmspico|kmsauto|hacktool.*(kms|activator|patcher)|keygen|crack|activator|wpakill'

    # Historique PowerShell et blocs de script journalisés.
    # Severity : Critique | Eleve | Moyen      Category : libellé de la catégorie du rapport
    HistoryPatterns = @(
        @{ Label = 'Faux domaine MAS (typosquat qui a diffusé Cosmali Loader / XWorm)'
           Regex = '(?i)get\.activate\.win|activated?\.(wim|vin|w1n)\b|massgrave\.(com|net|org|co)\b'
           Severity = 'Critique'; Category = 'Activateurs et licences' }
        @{ Label = 'Lancement de Microsoft Activation Scripts (MAS)'
           Regex = '(?i)activated\.win|massgrave\.dev|MAS_AIO|massgravel'
           Severity = 'Eleve'; Category = 'Activateurs et licences' }
        @{ Label = 'Autre activateur ou manipulation KMS'
           Regex = '(?i)kms[-_ ]?pico|kmsauto|kms_vl_all|slmgr(\.vbs)?\s+[/-](skms|ipk)|ospp\.vbs.+[/-](sethst|inpkey)'
           Severity = 'Eleve'; Category = 'Activateurs et licences' }
        @{ Label = 'Téléchargement exécuté directement en mémoire'
           Regex = '(?i)\b(irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\b[^|]{0,300}\|\s*(iex|invoke-expression)\b|iex\s*\(?\s*\(?\s*(new-object\s+net\.webclient|irm|iwr)|downloadstring\s*\('
           Severity = 'Eleve'; Category = 'Historique PowerShell' }
        @{ Label = 'Commande encodée'
           Regex = '(?i)\s-(e|ec|enc|enco[a-z]*)\s+[A-Za-z0-9+/=]{40,}|frombase64string\s*\('
           Severity = 'Moyen'; Category = 'Historique PowerShell' }
        @{ Label = 'Affaiblissement de l''antivirus'
           Regex = '(?i)add-mppreference\s+.*-exclusion|set-mppreference\s+.*-disable|disableantispyware|sc(\.exe)?\s+(stop|config|delete)\s+(windefend|sense|wscsvc)'
           Severity = 'Eleve'; Category = 'Historique PowerShell' }
        @{ Label = 'Effacement de traces'
           Regex = '(?i)wevtutil(\.exe)?\s+cl\b|clear-eventlog|remove-item.+consolehost_history|vssadmin(\.exe)?\s+delete\s+shadows'
           Severity = 'Eleve'; Category = 'Historique PowerShell' }
    )

    # Outils d'accès à distance : légitimes, mais à valider un par un (regex sur services et processus)
    RemoteToolsRegex = '(?i)anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|rustdesk|netsupport|meshagent|ngrok|tailscale|zerotier|ammyy|dwservice|dwagent|remoteutilities|rutserv|logmein|supremo|tightvnc|ultravnc|realvnc|vncserver|radmin|chrome remote desktop|chromoting|quickassist|simplehelp|pdq connect|level\.io|action1|fleetdeck|tacticalrmm'

    # Noms de processus système : leur présence hors de System32 / SysWOW64 / Windows est une usurpation
    SystemProcessNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'winlogon.exe', 'smss.exe', 'wininit.exe',
                           'spoolsv.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'runtimebroker.exe', 'sihost.exe',
                           'explorer.exe', 'dwm.exe', 'ctfmon.exe', 'fontdrvhost.exe', 'lsm.exe', 'userinit.exe')
}
