<p align="center">
  <img src="assets/banner.svg" alt="WinTriage" width="600">
</p>

<p align="center">
  <b>Read-only triage of a Windows host.</b><br>
  Persistence mechanisms, Office and Windows activator traces, common signs of compromise —<br>
  in one HTML report you can read, and one JSON file your tools can read.
</p>

<p align="center">
  <img alt="PowerShell 5.1 and 7" src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207-5391FE?logo=powershell&logoColor=white">
  <img alt="Windows 10 and 11" src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows&logoColor=white">
  <img alt="Read only" src="https://img.shields.io/badge/system-read--only-2ea043">
  <img alt="No dependency" src="https://img.shields.io/badge/dependencies-none-2ea043">
  <img alt="Report in English and French" src="https://img.shields.io/badge/report-EN%20%7C%20FR-8957e5">
  <img alt="20 checks" src="https://img.shields.io/badge/checks-20-555">
</p>

---

One script, no installation, nothing written to the system. It looks where persistence actually
lives — Run keys, scheduled tasks, services, WMI, the registry corners attackers like, kernel
drivers, browser extensions, shortcuts — plus credential-theft leftovers, weakened security
settings, and the specific traces left by Office and Windows activators. Every finding says what
was found, where, and *what to do* about it.

It complements an antivirus. It does not replace one.

## Quick start

```powershell
# from an administrator PowerShell
powershell -ExecutionPolicy Bypass -File .\Invoke-WinTriage.ps1
```

```text
WinTriage 1.2.0 — WORKSTATION-07 — 2026-11-22 09:12
  Activators             565 items     0 to review     2.1s
  PowerShellHistory      449 items     1 to review     3.3s
  Autostart              357 items     2 to review     3.7s
  ScheduledTasks         218 items     0 to review     1.2s
  ...
  Credentials            313 items     1 to review     1.9s
  Hardening               85 items     1 to review     1.5s
  Drivers                475 items     4 to review     4.2s
  Browsers                17 items     2 to review     0.3s
  RecentFiles           3188 items     0 to review    30.7s

== Items to deal with ==
Critical: 0   High: 3   Medium: 26   Info: 102
  [HIGH] Activators and licensing — Ohook: sppc.dll replaced in the Office folder (Ohook 1.2)
  [HIGH] Credential theft traces — Process memory dump on disk: lsass.dmp
  [HIGH] Network — Inbound firewall rule for a program in a temporary folder: AnyDesk

HTML report: .\reports\WinTriage_WORKSTATION-07_20261122-091204.html
JSON data:   .\reports\WinTriage_WORKSTATION-07_20261122-091204.json
```

A full scan takes about a minute and a half on a normal workstation, 20 checks over roughly
10 000 items. Without administrator rights the script still runs, but it is limited to the current
profile and reads neither the Security log, the antivirus exclusions, nor the boot options.

| Option | Effect |
|---|---|
| `-Language fr` | Language the report **opens** in: `en` (default) or `fr`. Both are always embedded |
| `-Days 90` | How far back event logs and recent files are examined (30 days by default) |
| `-Baseline <file\|folder>` | Compare with a previous JSON report and mark what appeared since |
| `-NewOnly` | With `-Baseline`, list only the new findings (the exit code then follows the list) |
| `-AllowlistFile <file>` | Suppression rules (default: `allowlist.psd1`, used when present) |
| `-NoAllowlist` | Ignore the suppression rules for this run |
| `-FixScript` | Also write `<report>.fix.ps1`: suggested remediation, every line commented out |
| `-LoadUserHives` | Also analyse logged-off users (mounts, then unmounts, their `NTUSER.DAT`) |
| `-OutputDir <folder>` | Where reports go — a network share, for instance |
| `-Only Activators,Drivers` | Run only these checks (wildcards accepted) |
| `-Skip RecentFiles` | Run everything except these |
| `-ListChecks` | Print the check names and exit |
| `-PassThru` | Also return the findings as objects |
| `-NoHtml` | JSON only |

Exit codes: `0` nothing above Info · `1` at least one Medium · `2` at least one High or Critical ·
`3` indicator file missing. Handy in a scheduled task or a pipeline.

### The second run is the one that matters

A triage tool earns its keep when you run it again next week. Three things keep that run short:

```powershell
# only what appeared since the last report in .\reports
.\Invoke-WinTriage.ps1 -Baseline .\reports -NewOnly
```

- **Baseline** — every finding carries a stable 12-character key derived from what it says, not
  from when it was seen. `-Baseline` marks the findings already present in a previous report, the
  page badges the others **NEW**, and `-NewOnly` drops the known ones entirely.
- **Allowlist** — `allowlist.psd1` holds the findings you have already decided about, each with a
  reason, an author and an expiry date. They move into a *suppressed* section of the report, so
  nothing is hidden silently, and they come back by themselves when the rule expires.
- **Triage marks** — in the report, mark each finding *reviewed* or *accepted*. The marks are kept
  in your browser, per host. **Export my decisions** hands you the JSON and a ready-to-paste
  `allowlist.psd1` block for everything you accepted.

And when something has to be cleaned up, `-FixScript` writes a worksheet next to the report: one
block per finding with its evidence, the advice, and candidate commands — all commented out, for
you to read, edit and run yourself.

## The report, in two languages

Every finding carries its text in **English and French**. The `EN | FR` switch at the top right of
the report changes the whole page — titles, explanations, advice, evidence labels, the checks
table — and the browser remembers the choice for the next report you open. `-Language` only picks
which one it opens in; nothing is lost either way.

```text
┌──────────────────────────────────────────────────────────────── EN │ FR ──┐
│ HIGH   Activators and licensing                                          │
│ Ohook: sppc.dll replaced in the Office folder (Ohook 1.2)                │
│ This DLL intercepts the Office licence check and answers 'licensed'.     │
│ ┌──────────────────────────────────────────────────────────────────────┐ │
│ │ File        : C:\Program Files\Microsoft Office\root\vfs\...\sppc.dll│ │
│ │ Size        : 184320 bytes                                          │ │
│ │ Description : Office licensing helper / —                           │ │
│ │ Signature   : Unsigned                                              │ │
│ │ Modified    : 2026-10-02 23:41                                      │ │
│ └──────────────────────────────────────────────────────────────────────┘ │
│ What to do: uninstall the activator, repair Office, then activate with   │
│ a valid licence.                                                         │
└──────────────────────────────────────────────────────────────────────────┘
```

Tiles at the top filter by severity (Info is hidden until you click it), and the search box
filters on anything — a file name, a category, a keyword. Each finding also shows its key and two
triage buttons, and the page holds three more sections:

- **Timeline** — every dated artefact the checks collected, newest first: services installed,
  tasks and accounts created, files dropped, antivirus detections, logs cleared, certificates
  added. It usually tells the story faster than the findings list.
- **Suppressed** — what your `allowlist.psd1` accepted, with the reason, the author and the
  expiry date. Expired rules get their own section, in red.
- **Checks performed** and **Scope** — what was examined, how long it took, and what could not
  be read.

| Level | Meaning |
|---|---|
| **Critical** | Probable compromise — deal with it now |
| **High** | Clear anomaly (activator, suspicious persistence, antivirus weakened) — deal with it |
| **Medium** | Worth verifying — often legitimate, but confirm it |
| **Info** | Inventory (third-party autostart entries, accounts, licences, drivers) — hidden by default |

A **Medium** is a question to ask, not a verdict. The "Checks performed" table says what was
examined, how long it took, and what could not be read.

## What it checks

| Check | Looks for |
|---|---|
| **Activators and licensing** | Ohook (`sppc.dll` / `sppcs.dll` in Office, `TimeOfLastHeartbeatFailure`), MAS / KMSpico / KMSAuto / KMS_VL_ALL tasks, services and folders, dummy KMS addresses, public pirate KMS servers, abnormal activation duration (KMS38, KMS4k/TSforge), licensing domains blocked in `hosts`, licensing-service hijack, antivirus exclusions for activators |
| **PowerShell history** | Activator commands, **fake MAS domains** (typosquats that spread Cosmali Loader / XWorm), downloads piped straight into memory, antivirus switched off, traces wiped. Known official installers are downgraded to Info |
| **Autostart** | Run / RunOnce / RunServices (machine and every user), Startup folders, Active Setup, logon scripts, screen savers, and **shortcuts** on the desktop, Start menu and taskbar whose target is an interpreter, an activator or something in a temporary folder — including browser shortcuts carrying injected options (`--load-extension`, `--proxy-server`, …) |
| **Scheduled tasks** | Suspicious actions, unsigned binaries, **hidden tasks** (security descriptor removed — "Tarrask" — or present in the registry yet invisible to the API), orphaned registry entries |
| **Services** | Unsigned binaries, binaries in user-writable folders, the DLL behind each svchost-hosted service — flagged when it sits **outside the system folders** — and unquoted service paths with spaces |
| **WMI** | Permanent subscriptions that run a command or a script on a system event |
| **Registry (advanced persistence)** | Winlogon Shell/Userinit/Taskman, AppInit_DLLs, AppCertDlls, BootExecute, Image File Execution Options, SilentProcessExit, replaced accessibility tools (sticky-keys backdoor), LSA modules, print monitors, netsh helpers, COM hijacking, "Office test", AeDebug, `cmd.exe` AutoRun, file-type and `ms-settings` handler hijacks, service recovery commands, **KnownDLLs** tampering, **shell extension handlers** loaded into explorer.exe |
| **Office (macros and startup)** | All macros enabled, VBA object model access, risky trusted locations, files auto-loaded from the Word/Excel startup folders, **COM and VSTO add-ins** declared in the registry (`LoadBehavior`, manifests fetched over the network), **Outlook** unsafe client rules, folder home pages and macro project |
| **Accounts** | Accounts hidden with a trailing `$`, hidden from the logon screen, enabled Guest, Administrators group membership |
| **Credential theft traces** | Process memory dumps on disk, recognised by their `MDMP` header rather than their extension and raised to High when the name points at a credential process (lsass, SAM, ntds, procdump…), copies of the SAM / SECURITY / SYSTEM hives or `ntds.dit`, Kerberos ticket files, and hive-export or shadow-copy-deletion commands caught running |
| **Security settings** | WDigest clear-text credentials, `RunAsPPL`, UAC disabled, `LocalAccountTokenFilterPolicy`, `AlwaysInstallElevated`, Task Manager / regedit / cmd blocked by policy, updates disabled or redirected, System Restore off, SMB1, anonymous access, machine-wide PowerShell `Bypass`, **AMSI** switched off for scripts or hijacked (unsigned provider, `amsi.dll` dropped next to an executable), **PowerShell 2.0** engine still available, **trusted root certificates** added recently or belonging to a TLS interception product |
| **Remote access** | RDP, OpenSSH server, `authorized_keys`, WinRM (and Basic / unencrypted WinRM), remote-control tools (AnyDesk, TeamViewer, RustDesk, ngrok…), `netsh portproxy` forwarding |
| **Antivirus (Defender)** | Protection disabled by policy or preference, script / archive / first-sight scanning off, cloud protection and PUA protection off, tamper protection, exclusions (broad ones and activator ones), detection history |
| **Network** | `hosts` file redirections (licensing, security, update domains), firewall disabled per profile, **inbound firewall rules** opening a program that sits in a temporary folder or wearing a Microsoft name over an unsigned binary, enforced proxy or PAC script, **static DNS servers, DNS-over-HTTPS resolvers and NRPT policy rules**, unsigned programs listening on the network |
| **Kernel drivers** | Unsigned drivers, drivers **known to be abused for BYOVD**, third-party drivers installed recently, `testsigning` / `nointegritychecks` / safe-mode boot options, Microsoft's vulnerable-driver blocklist turned off |
| **Browser extensions** | Extensions force-installed by policy from a third-party server, extensions sideloaded through the registry, extensions holding powerful permissions (`debugger`, `nativeMessaging`, `proxy`, `management`…), plus a per-browser inventory |
| **Processes** | System-name impersonation (`svchost.exe` outside System32…), encoded commands, unsigned binaries in writable folders |
| **Recent files** | Unsigned executables dropped in temp and data folders inside the analysis window |
| **Event logs** | Cleared logs, services installed, tasks and accounts created, administrators added, bursts of failed logons, Defender exclusions changed, **start type of a security, logging or backup service changed** |
| **BITS** | Transfer jobs carrying a notification command (quiet persistence) |

## JSON for a fleet

The script has no dependency: run it from your management tool (GPO, Intune, a SYSTEM scheduled
task) with `-OutputDir` on a share, then read the JSON. Text fields are `{ en, fr }` objects, so
a fleet-wide summary can be built in either language.

```powershell
Get-ChildItem \\server\triage\*.json | ForEach-Object {
    $r = Get-Content $_ -Raw | ConvertFrom-Json
    $r.Findings | Where-Object Severity -in 'Critical', 'High' |
        Select-Object @{ n = 'Host';  e = { $r.Meta.Computer } },
                      Severity, Category,
                      @{ n = 'Title'; e = { $_.Title.en } }
} | Sort-Object Severity, Host | Format-Table -AutoSize
```

Or let [`Merge-Reports.ps1`](Merge-Reports.ps1) do it: it reads every JSON under a folder, keeps
the newest report per host, and writes one bilingual dashboard — a sortable host table (verdict,
counts, suppressed, new, link to each report) and the findings seen across the fleet with the
hosts affected by each.

```powershell
.\Merge-Reports.ps1 -Path \\server\triage -MaxAgeDays 30 -Json
```

It exits `2` if any host has a Critical or High finding, `1` for a Medium, `0` otherwise — so it
works as a scheduled fleet check on its own.

## Tuning the indicators

Every name, path and pattern lives in [`indicators.psd1`](indicators.psd1), away from the code:
adding an activator, a KMS server, a vulnerable driver, a history pattern or a risky browser
permission needs no change to the script. Labels there carry an `en` and an `fr` variant, so a new
pattern shows up in both languages. The MAS indicators were read straight from its source.

## Repository layout

```text
Invoke-WinTriage.ps1          the scanner — single file, no dependency
indicators.psd1               what it looks for: names, paths, patterns
allowlist.psd1                findings you have accepted, with reason and expiry
Merge-Reports.ps1             turns many JSON reports into one fleet dashboard
TODO.md                       what is planned next, and why
reports/                      generated reports (git-ignored)
tests/Run-SelfTest.ps1        end-to-end self-test on a fake host
tests/Mocks.ps1               the fake host it runs against
tests/Expected-Infected.txt   reference list of findings: a missing one fails the build
tests/Test-ReportRender.js    renders the report to prove both languages work
```

## Tests

`tests/Run-SelfTest.ps1` runs the whole script against fake data — one clean host, one compromised
host — without touching the real system, and checks that:

- every expected detection fires, and the clean host fires nothing above Info;
- **no detection was lost**: the titles found are compared with `tests/Expected-Infected.txt`, and
  a missing one fails the run. New ones are listed, to be recorded with `-UpdateExpected`;
- each finding carries both languages, and the report opens in the requested one;
- the timeline is populated on a compromised host;
- `-Baseline` against an identical run reports nothing new (which proves the finding keys are
  stable), `-NewOnly` then yields an empty report and exit code `0`;
- the allowlist suppresses an active rule, ignores an expired one and says so;
- `-FixScript` writes a file in which **not a single line is executable**.

On Windows it also renders the HTML report through `tests/Test-ReportRender.js`: the page's own
script runs against a small DOM shim (`cscript`), proving the report displays in English and in
French, that the language switch works, and that the triage marks persist and filter. Elsewhere
that step is skipped.

```powershell
pwsh ./tests/Run-SelfTest.ps1
pwsh ./tests/Run-SelfTest.ps1 -KeepReports ./examples    # keep the generated reports
pwsh ./tests/Run-SelfTest.ps1 -UpdateExpected            # record newly added detections
```

## Limitations

- A report without alerts does not prove a host is clean. Rootkits, in-memory implants and
  techniques not covered here escape this kind of tool.
- HWID and TSforge (ZeroCID) activations leave almost no distinctive trace once applied. Only
  their side traces are detectable — history, leftover tickets, antivirus detections.
- The PowerShell history carries no timestamp, and a user can delete it.
- Firefox extensions, mailbox contents and anything living only in memory are out of scope.
  [`TODO.md`](TODO.md) lists what is planned next and why.
- Signature checks rely on Windows: a system file whose catalogue entry is missing looks unsigned,
  which is why those cases are reported as Medium with the nuance spelled out.
- The remediation script is a worksheet. Its commands are derived from the evidence, commented
  out, and meant to be read before anything is run.
- Some things are left out on purpose, because flagging them buries the rest: unsigned games with
  an inbound firewall rule, per-user application installs under `AppData\Local\Programs`, firewall
  rules left behind by an uninstalled version, and Microsoft-signed autostart entries. The
  thresholds were set against real machines, not only against the test fixtures.

## Privacy

Reports contain account names, paths, and excerpts of command lines and PowerShell history. The
`reports/` folder and the generated `*.fix.ps1` worksheets are kept out of the repository by
`.gitignore` — do not publish them as is.