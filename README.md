# WinTriage

Audit en lecture seule d'un poste Windows : mécanismes de persistance, traces d'activateurs
Office et Windows, signes courants de compromission. Le script produit un rapport HTML lisible
et un fichier JSON exploitable par d'autres outils.

C'est un complément à un antivirus, pas un remplaçant.

## Utilisation

Dans un PowerShell **administrateur** (Windows PowerShell 5.1 ou PowerShell 7) :

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-WinTriage.ps1
```

Le rapport est écrit dans `.\reports\WinTriage_<poste>_<date>.html` (et `.json`).
Sans droits administrateur, le script fonctionne mais se limite au profil courant et ne lit ni
le journal Sécurité ni les exclusions de l'antivirus.

| Option | Effet |
|---|---|
| `-Days 90` | Profondeur des journaux et des fichiers récents (30 jours par défaut) |
| `-LoadUserHives` | Analyse aussi le registre des utilisateurs déconnectés (monte puis démonte leur `NTUSER.DAT`) |
| `-OutputDir <dossier>` | Dossier des rapports, par exemple un partage réseau |
| `-Only 'Activateurs*','Tâches*'` | Ne lance que certains contrôles |
| `-Skip 'Fichiers récents'` | Exclut certains contrôles |
| `-ListChecks` | Affiche la liste des contrôles |
| `-PassThru` | Renvoie les résultats sous forme d'objets |
| `-NoHtml` | JSON seulement |

Codes de sortie : `0` rien au-dessus d'Info, `1` au moins un Moyen, `2` au moins un Élevé ou
Critique, `3` fichier d'indicateurs manquant.

## Lire le rapport

| Niveau | Signification |
|---|---|
| **Critique** | Compromission probable : à traiter tout de suite |
| **Élevé** | Anomalie nette (activateur, persistance suspecte, antivirus affaibli) : à traiter |
| **Moyen** | À vérifier : souvent légitime, mais mérite une confirmation |
| **Info** | Inventaire (logiciels tiers au démarrage, comptes, licences) ; masqué par défaut |

Chaque résultat donne l'emplacement exact, la preuve relevée et une action conseillée.
Le tableau « Contrôles effectués » indique ce qui a été examiné et ce qui n'a pas pu l'être.

## Ce qui est vérifié

| Contrôle | Contenu |
|---|---|
| Activateurs et licences | Ohook (`sppc.dll` / `sppcs.dll` dans Office, valeur `TimeOfLastHeartbeatFailure`), tâches et dossiers de MAS, KMSpico, KMSAuto, KMS_VL_ALL ; adresse KMS factice ou serveur KMS public ; durée d'activation anormale (KMS38, KMS4k) ; domaines de licence bloqués dans `hosts` ; détournement du service de licences |
| Historique PowerShell | Commandes d'activateurs, **faux domaines MAS** (typosquat), téléchargements exécutés en mémoire, affaiblissement de l'antivirus, effacement de traces |
| Démarrage automatique | Clés Run et RunOnce (machine et chaque utilisateur), dossiers Démarrage, Active Setup, script d'ouverture de session |
| Tâches planifiées | Actions suspectes, binaires non signés, **tâches masquées** (sans descripteur de sécurité, ou présentes dans le registre mais invisibles de l'API) |
| Services | Binaires non signés ou dans un dossier modifiable, DLL des services hébergés par svchost |
| WMI | Abonnements permanents qui exécutent une commande ou un script |
| Registre (persistance avancée) | Winlogon, AppInit_DLLs, AppCertDlls, BootExecute, Image File Execution Options, SilentProcessExit, outils d'accessibilité remplacés, modules LSA, moniteurs d'impression, assistants netsh, détournement COM, clé « Office test » |
| Office | Macros toutes activées, accès au modèle objet VBA, emplacements approuvés risqués, fichiers des dossiers de démarrage de Word et Excel |
| Comptes | Comptes masqués, Invité actif, membres du groupe Administrateurs |
| Accès à distance | Serveur OpenSSH, clés `authorized_keys`, outils de prise en main à distance, redirections de ports |
| Antivirus (Defender) | Protection désactivée, exclusions, historique des détections |
| Réseau | Fichier `hosts`, pare-feu désactivé, proxy imposé, programmes non signés en écoute |
| Processus | Usurpation d'un nom système, commandes encodées, binaires non signés en dossier modifiable |
| Fichiers récents | Exécutables non signés déposés récemment dans les dossiers temporaires et de données |
| Journaux d'événements | Journaux effacés, services installés, tâches et comptes créés, échecs d'authentification en masse |
| BITS | Transferts avec commande de notification |

## Adapter les indicateurs

Tous les noms, chemins et motifs connus sont dans [`indicators.psd1`](indicators.psd1), séparé du
code : ajouter un activateur, un serveur KMS ou un motif d'historique ne demande pas de toucher au
script. Les indicateurs MAS ont été relevés directement dans son code source.

## Déploiement sur plusieurs postes

Le script n'a aucune dépendance. Pour un parc : le lancer via votre outil de gestion (GPO, Intune,
tâche planifiée SYSTEM) avec `-OutputDir` vers un partage, puis exploiter les fichiers JSON.

```powershell
Get-ChildItem \\serveur\triage\*.json | ForEach-Object {
    $r = Get-Content $_ -Raw | ConvertFrom-Json
    $r.Findings | Where-Object Severity -in 'Critique', 'Eleve' |
        Select-Object @{ n = 'Poste'; e = { $r.Meta.Computer } }, Severity, Category, Title
}
```

## Tests

`tests/Run-SelfTest.ps1` exécute le script sur des données factices (poste sain, poste compromis)
sans toucher au système réel, et vérifie que chaque détection attendue sort et qu'un poste sain ne
déclenche rien. Il demande PowerShell 7 et fonctionne aussi sous Linux et macOS.

```powershell
pwsh ./tests/Run-SelfTest.ps1
pwsh ./tests/Run-SelfTest.ps1 -KeepReports ./exemples     # conserve les rapports générés
```

## Limites

- Un rapport sans alerte ne prouve pas qu'un poste est sain : rootkits, implants en mémoire et
  techniques non couvertes échappent à ce type d'outil.
- Les activations HWID et TSforge (ZeroCID) ne laissent presque aucune trace distinctive une fois
  posées. Seules leurs traces annexes sont détectables (historique, tickets, détections antivirus).
- L'historique PowerShell n'est pas daté et un utilisateur peut l'effacer.
- Les pilotes noyau, les extensions de navigateur et le contenu des boîtes aux lettres ne sont pas
  examinés.
- Un résultat « Moyen » est une question à poser, pas un verdict.

## Confidentialité

Les rapports contiennent des noms de comptes, des chemins, des extraits de lignes de commande et
d'historique PowerShell. Le dossier `reports/` est exclu du dépôt par `.gitignore` : ne le publiez pas.
