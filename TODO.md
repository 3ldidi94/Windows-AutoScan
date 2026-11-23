# TODO

What is left to do on WinTriage, ordered by what it buys you. Effort is S (hours), M (a day),
L (several days). Items marked **deferred** were proposed and consciously postponed.

Done in 1.2.0, for reference: baseline comparison, allowlist, triage marks in the report,
timeline, remediation script, fleet dashboard, and 11 new detection areas.

---

## Next, highest value first

### Performance and run profiles — M — deferred
A full scan takes about 60 s on a normal workstation, and `RecentFiles` alone takes 26 s of it
(2 700 files hashed and signature-checked). Worth doing:
- prune `RecentFiles`: skip package caches (`AppData\Local\Packages\*\LocalCache`, npm/pip/nuget
  caches, `node_modules`), and stop at the first 2 000 candidates per folder;
- cache `Get-Sig` results by file hash as well as by path, so copies cost nothing;
- `-Quick` (no hashing, no recent files, no driver enumeration) and `-Deep` (everything plus
  hashes of every autostart binary);
- optionally run the independent checks in runspaces; keep the sequential path for `-TestHooks`
  so the self-test stays deterministic.

### Continuous integration — S — deferred
GitHub Actions: run `tests/Run-SelfTest.ps1` on `windows-latest` (PowerShell 5.1 and 7) and on
`ubuntu-latest` (pwsh, renderer test skipped), plus `PSScriptAnalyzer`. Add the badge to the
README. This repo has already been hit once by two editors writing the same file; CI is the net.

### ATT&CK technique ids — S — deferred
Carry `T1547.001`, `T1546.012`, `T1003.001`… in `indicators.psd1` and on each finding, show them
in the report and in the JSON. Helps write up an incident, and makes coverage gaps visible.

### Surface failures instead of swallowing them — S — found while building 1.2.0
`$ErrorActionPreference = 'SilentlyContinue'` is set globally. It hid a real bug for a while: a
`Split-Path ''` on a missing baseline silently emptied the whole HTML data blob. Proposal: keep
the quiet default, add `-Strict` that turns errors into check errors (already reported per check),
and assert in the self-test that the embedded data blob parses (partly done: the language default
is asserted today).

### Firefox extensions — M
The browser check only covers the Chromium family. Firefox persistence lives in
`extensions.json`, `user.js`, `policies.json` and `distribution/` — none of it is read today.

### Scheduled task triggers — S
Only task *actions* are analysed. A task that runs at logon or boot, as SYSTEM, with
`RunLevel = Highest`, is worth a look even when its action looks ordinary.

### More hardening checks — M
Not covered yet: ASR rules (`Get-MpPreference -AttackSurfaceReductionRules_Ids`), Credential
Guard / LSA protection state, SMB signing, LAPS, accounts with "password never expires" or no
password at all, and a renamed RID-500 administrator.

---

## Output and integration

### `-ToEventLog` / `-Webhook` — S — deferred
Write the verdict and the findings above Info into the Windows Application log (one event per
finding, a stable event id per severity) or POST the JSON to an endpoint, so a SIEM picks it up
without a file share.

### `-Collect <folder>` — M — deferred
Copy the flagged artefacts with their hashes into a zip next to the report, for offline analysis.
Read-only on the system; must refuse to collect anything over a size limit, and must never
collect user documents.

### VirusTotal lookup — S — deferred
`-VirusTotalKey`: look up the hashes already computed, add the verdict to the finding. Only
hashes leave the machine, and the option must be explicit, never a default.

### Merge-Reports: CSV and drill-down — S
`-Csv` for the host table (people want it in Excel), and a per-finding view listing which hosts
have it with their scan dates.

### `-PassThru` shape — S
It returns objects whose text fields are `@{ en; fr }` hashtables, which is awkward in a pipeline.
Add flattening driven by `-Language`, keeping the bilingual form behind `-PassThru -Raw`.

### Report size cap — S
A host with thousands of findings produces one very large HTML file. Cap the embedded evidence,
paginate the Info level, and say in the report what was truncated.

---

## Accuracy and depth

### Definitive signature verdict on catalogue-signed files — M
`Get-Sig` reports "no verifiable signature" for inbox files whose catalogue entry is missing
(`bthmodem.sys` on the dev machine). Today that is softened with a metadata heuristic (`MsClaim`).
A `WinVerifyTrust` P/Invoke with catalogue lookup would give a real answer.

### Boot options without bcdedit text parsing — S
`Get-BootConfig` parses localised `bcdedit` output and only recognises `Yes`/`Oui`. Read the BCD
store or the `HKLM\SYSTEM\CurrentControlSet\Control\CI` values instead.

### Richer timeline sources — L
The timeline only shows artefacts the checks already date. Prefetch, Amcache, SRUM and
`$MFT`-free sources would turn it into a real execution timeline; all need administrator rights
and a parser, hence the size.

### First-seen dates — M
Keep a small state file per host (or derive it from the baseline chain) so each finding can say
how long it has been there. "New" is useful; "there since 3 weeks" is better.

### Baseline over several runs — S
Compare against the last N reports rather than one, to spot findings that come and go.

### Allowlist scoping — S
Rules apply to every host. Add an optional `Computer` field (and wildcards) so a fleet can share
one allowlist file.

### Explicit remediation metadata — M
The fix script derives commands from the evidence block with regexes; about 15 findings carry an
explicit `-Fix`. Filling that in for the rest makes the generated script precise rather than
indicative.

### Per-check timeout — S
One slow check (a huge `AppData\Roaming`) dominates a scan. A `-Timeout <seconds>` per check,
recorded as a check error, keeps a fleet run predictable.

### WSL and containers — M
A WSL distribution with a custom rootfs, or a container with `restart: always`, is persistence
that nothing here looks at.

---

## Repository hygiene — S — deferred

- No `LICENSE` file: the README cannot state terms until there is one.
- No `CHANGELOG.md`; versions move (1.0.0 → 1.2.0) with nothing recording why.
- `#Requires -Version 5.1` is missing from both scripts.
- Sign the scripts (Authenticode) so they run under `AllSigned`, and publish a release zip.
- `indicators.psd1` has no provenance per indicator (added when, by whom, from which source);
  a `Meta` block per group would make the file auditable.
- `tests/Test-ReportRender.js` needs `cscript`, so the rendering test is Windows-only. A Node
  variant would let CI check the report on Linux too.
- A third report language would mean touching every `L ...` call. If that ever comes up, move the
  catalogue to `lang/<code>.psd1` files keyed by message id.
