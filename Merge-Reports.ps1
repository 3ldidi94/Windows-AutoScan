<#
.SYNOPSIS
    Merges the JSON reports produced by Invoke-WinTriage.ps1 into one fleet dashboard.

.DESCRIPTION
    Reads every WinTriage_*.json under -Path, keeps the most recent report per host (unless -All),
    and writes a single HTML page: one row per host, plus the findings seen across the fleet with
    the hosts affected by each. The page carries English and French text, like the host reports.

    Nothing is collected here: the script only reads the JSON files you point it at.

.PARAMETER Path
    Folder (searched recursively) or list of JSON files. Default: .\reports next to this script.
.PARAMETER OutputFile
    HTML file to write. Default: <Path>\WinTriage_Fleet_<date>.html
.PARAMETER Language
    Language the dashboard opens in: en (default) or fr. Both are embedded.
.PARAMETER MaxAgeDays
    Ignore reports older than this many days.
.PARAMETER All
    Keep every report instead of only the newest one per host.
.PARAMETER Json
    Also write a <OutputFile>.json summary for other tools.

.EXAMPLE
    .\Merge-Reports.ps1 -Path \\server\triage -OutputFile \\server\triage\fleet.html
.EXAMPLE
    .\Merge-Reports.ps1 -Path .\reports -MaxAgeDays 30 -Language fr -Json
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$OutputFile,
    [ValidateSet('en', 'fr')][string]$Language = 'en',
    [int]$MaxAgeDays = 0,
    [switch]$All,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Path) { $Path = @(Join-Path $ScriptDir 'reports') }

# --- Collect the report files
$files = @()
foreach ($p in $Path) {
    if (Test-Path -LiteralPath $p -PathType Container) { $files += @(Get-ChildItem -LiteralPath $p -Recurse -Filter 'WinTriage_*.json' -File) }
    elseif (Test-Path -LiteralPath $p -PathType Leaf)  { $files += @(Get-Item -LiteralPath $p) }
    else { $files += @(Get-ChildItem -Path $p -File) }
}
$files = @($files | Sort-Object FullName -Unique | Where-Object { $_.Extension -eq '.json' })
if (-not $files.Count) { Write-Host "No WinTriage JSON report found under: $($Path -join ', ')" -ForegroundColor Red; exit 3 }

$reports = @()
foreach ($f in $files) {
    $j = $null
    try { $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { }
    if (-not $j -or -not $j.Meta -or -not $j.Meta.Computer) { Write-Host "Skipped (not a WinTriage report): $($f.Name)" -ForegroundColor DarkGray; continue }
    $when = $null
    try { $when = [datetime]$j.Meta.Started } catch { $when = $f.LastWriteTime }
    if ($MaxAgeDays -gt 0 -and $when -lt (Get-Date).AddDays(-$MaxAgeDays)) { continue }
    $reports += [pscustomobject]@{ File = $f; When = $when; Data = $j; Computer = "$($j.Meta.Computer)" }
}
if (-not $reports.Count) { Write-Host 'No report left after filtering.' -ForegroundColor Red; exit 3 }
if (-not $All) { $reports = @($reports | Group-Object Computer | ForEach-Object { $_.Group | Sort-Object When -Descending | Select-Object -First 1 }) }
$reports = @($reports | Sort-Object Computer, When)

# --- Per host summary, and findings grouped across the fleet
function Sev-Rank([string]$s) { switch ($s) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } } }
# Findings are grouped by what they say, not by their per-host key: the same problem on two hosts
# carries different paths and user names, so the key differs while the title is the same.
function Get-GroupTitle([string]$s) {
    $s = $s -replace '\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?', '<date>'
    $s = $s -replace '\d{1,2}/\d{1,2}/\d{2,4}([ ,]+\d{1,2}:\d{2}(:\d{2})?( ?[AaPp]\.?[Mm]\.?)?)?', '<date>'
    $s = $s -replace '(?i)[A-Z]:\\Users\\[^\\]+\\', '<profile>\'
    $s -replace '\b\d{3,}\b', '<n>'
}
$hosts = @()
$groups = @{}
foreach ($r in $reports) {
    $c = $r.Data.Meta.Counts
    $hosts += [ordered]@{
        host = $r.Computer; os = "$($r.Data.Meta.OS)"; domain = $r.Data.Meta.Domain
        when = $r.When.ToString('yyyy-MM-dd HH:mm'); admin = [bool]$r.Data.Meta.Admin
        tool = "$($r.Data.Meta.Tool)"; verdict = $r.Data.Meta.Verdict
        counts = [ordered]@{ Critical = [int]$c.Critical; High = [int]$c.High; Medium = [int]$c.Medium; Info = [int]$c.Info }
        suppressed = [int]$r.Data.Meta.SuppressedCount; new = [int]$r.Data.Meta.NewSinceBaseline
        file = $r.File.Name
        errors = @($r.Data.Checks | Where-Object { $_.Error } | ForEach-Object { "$($_.Name)" })
    }
    foreach ($f in @($r.Data.Findings)) {
        if ("$($f.Severity)" -eq 'Info') { continue }
        $k = "$($f.Severity)|$($f.Category)|$(Get-GroupTitle "$($f.Title.en)")"
        if (-not $groups.ContainsKey($k)) {
            $groups[$k] = [pscustomobject]@{ Severity = "$($f.Severity)"; Category = "$($f.Category)"
                                             CategoryLabel = $f.CategoryLabel; Title = $f.Title; Hosts = @() }
        }
        if ($groups[$k].Hosts -notcontains $r.Computer) { $groups[$k].Hosts += $r.Computer }
    }
}
$findings = @($groups.Values |
    Sort-Object @{ Expression = { Sev-Rank $_.Severity } }, @{ Expression = { -$_.Hosts.Count } }, @{ Expression = { $_.Title.en } } |
    ForEach-Object { [ordered]@{ s = $_.Severity; c = $_.Category; cl = $_.CategoryLabel; t = $_.Title; h = @($_.Hosts | Sort-Object) } })

$totals = [ordered]@{ hosts = $hosts.Count; critical = 0; high = 0; medium = 0; clean = 0; errors = 0 }
foreach ($h in $hosts) {
    if ($h.counts.Critical) { $totals.critical++ }
    elseif ($h.counts.High) { $totals.high++ }
    elseif ($h.counts.Medium) { $totals.medium++ }
    else { $totals.clean++ }
    if ($h.errors.Count) { $totals.errors++ }
}

if (-not $OutputFile) {
    $dir = if (Test-Path -LiteralPath $Path[0] -PathType Container) { $Path[0] } else { Split-Path -Parent $files[0].FullName }
    $OutputFile = Join-Path $dir ("WinTriage_Fleet_{0}.html" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
}

$data = [ordered]@{
    lang = $Language; generated = (Get-Date).ToString('yyyy-MM-dd HH:mm'); totals = $totals
    hosts = $hosts; findings = $findings
}
$blob = ($data | ConvertTo-Json -Depth 8 -Compress) -replace '<', '\u003c' -replace '>', '\u003e' -replace '&', '\u0026'

$tpl = @'
<!doctype html>
<html lang="__LANG__"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinTriage fleet</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--mut:#5c6b7a;--line:#dde2e8;--crit:#b00020;--high:#c2410c;--med:#a16207;--info:#51627a;--ok:#15803d}
@media(prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b222b;--fg:#e6eaf0;--mut:#9aa8b8;--line:#2c3644;--crit:#ff6b81;--high:#fb923c;--med:#facc15;--info:#93a4ba;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0;overflow-wrap:anywhere}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
.lang{display:flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--card);flex:none}
.lang button{border:0;background:transparent;color:var(--mut);font:inherit;font-weight:600;padding:7px 14px;cursor:pointer}
.lang button+button{border-left:1px solid var(--line)}.lang button.on{background:var(--info);color:var(--card)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.tile{text-align:center}.tile b{display:block;font-size:28px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;cursor:pointer;user-select:none}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto}.sev{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.Critical,.sev.Critical{color:var(--crit)}.High,.sev.High{color:var(--high)}.Medium,.sev.Medium{color:var(--med)}.Info,.sev.Info{color:var(--info)}
.ok{color:var(--ok)}.err{color:var(--crit)}.cat{font-size:12px;color:var(--mut)}
.hosts{font:12px/1.5 Consolas,monospace;color:var(--mut)}
input[type=search]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit;margin:10px 0}
@media(max-width:700px){.tiles{grid-template-columns:repeat(2,1fr)}}
@media print{.lang,input{display:none}}
</style></head><body><main id="app"></main>
<script>
var D = __DATA__;
var S = {
  en: { title: 'WinTriage fleet', generated: 'generated', hosts: 'hosts', critical: 'with a critical finding',
        high: 'to deal with', medium: 'to verify', clean: 'nothing above Info', errors: 'with an interrupted check',
        hostsTitle: 'Hosts', thHost: 'Host', thWhen: 'Scanned', thOs: 'OS', thVerdict: 'Verdict', thSup: 'Suppressed', thNew: 'New', thFile: 'Report',
        findingsTitle: 'Findings across the fleet', thCount: 'Hosts', search: 'Filter: host, finding, category...',
        affected: 'affected hosts', noFindings: 'No finding above Info on any host.', adminNo: 'partial scan (no admin rights)' },
  fr: { title: 'Parc WinTriage', generated: 'généré le', hosts: 'postes', critical: 'avec un résultat critique',
        high: 'à traiter', medium: 'à vérifier', clean: 'rien au-dessus d\'Info', errors: 'avec un contrôle interrompu',
        hostsTitle: 'Postes', thHost: 'Poste', thWhen: 'Analysé', thOs: 'OS', thVerdict: 'Verdict', thSup: 'Supprimés', thNew: 'Nouveaux', thFile: 'Rapport',
        findingsTitle: 'Résultats sur le parc', thCount: 'Postes', search: 'Filtrer : poste, résultat, catégorie...',
        affected: 'postes concernés', noFindings: 'Aucun résultat au-dessus d\'Info sur les postes analysés.', adminNo: 'analyse partielle (sans droits admin)' }
};
var lang = D.lang === 'fr' ? 'fr' : 'en';
try { var sv = localStorage.getItem('wintriage.lang'); if (sv === 'en' || sv === 'fr') { lang = sv; } } catch (e) {}
var filter = '', sortKey = 'sev', sortDir = 1;

function arr(v) { if (Object.prototype.toString.call(v) === '[object Array]') { return v; } return v ? [v] : []; }
function tx(o) { return o ? (o[lang] || o.en || '') : ''; }
function t(k) { return S[lang][k]; }
function esc(s) {
  return String(s === null || s === undefined ? '' : s).replace(/[&<>"]/g, function (c) {
    return c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&quot;';
  });
}
function worst(h) {
  if (h.counts.Critical) { return 'Critical'; }
  if (h.counts.High) { return 'High'; }
  if (h.counts.Medium) { return 'Medium'; }
  return 'Info';
}
function rank(s) { return s === 'Critical' ? 0 : s === 'High' ? 1 : s === 'Medium' ? 2 : 3; }

function header() {
  var h = '<div class="top"><div><h1>' + esc(t('title')) + '</h1><div class="mut">' + esc(t('generated')) + ' ' + esc(D.generated) + '</div></div>';
  h += '<div class="lang"><button type="button" data-lang="en"' + (lang === 'en' ? ' class="on"' : '') + '>EN</button>';
  h += '<button type="button" data-lang="fr"' + (lang === 'fr' ? ' class="on"' : '') + '>FR</button></div></div>';
  var k = ['hosts', 'critical', 'high', 'medium', 'clean'];
  var cls = ['', 'Critical', 'High', 'Medium', 'ok'];
  h += '<div class="tiles">';
  for (var i = 0; i < k.length; i++) {
    h += '<div class="card tile"><b class="' + cls[i] + '">' + (D.totals[k[i]] || 0) + '</b>' + esc(t(k[i])) + '</div>';
  }
  h += '</div>';
  if (D.totals.errors) { h += '<div class="mut">' + D.totals.errors + ' ' + esc(t('errors')) + '</div>'; }
  return h + '<input type="search" id="q" placeholder="' + esc(t('search')) + '" value="' + esc(filter) + '">';
}

function hostsTable() {
  var list = arr(D.hosts).slice(0), q = filter.toLowerCase();
  list.sort(function (a, b) {
    var r = 0;
    if (sortKey === 'host') { r = a.host < b.host ? -1 : a.host > b.host ? 1 : 0; }
    else if (sortKey === 'when') { r = a.when < b.when ? -1 : a.when > b.when ? 1 : 0; }
    else { r = rank(worst(a)) - rank(worst(b)) || (b.counts.High - a.counts.High); }
    return r * sortDir;
  });
  var h = '<h2>' + esc(t('hostsTitle')) + '</h2><div class="card scroll"><table><tr>';
  h += '<th data-sort="host">' + esc(t('thHost')) + '</th><th data-sort="when">' + esc(t('thWhen')) + '</th>';
  h += '<th>' + esc(t('thOs')) + '</th><th data-sort="sev">' + esc(t('thVerdict')) + '</th>';
  h += '<th class="n">C</th><th class="n">H</th><th class="n">M</th><th class="n">i</th>';
  h += '<th class="n">' + esc(t('thSup')) + '</th><th class="n">' + esc(t('thNew')) + '</th><th>' + esc(t('thFile')) + '</th></tr>';
  for (var i = 0; i < list.length; i++) {
    var x = list[i], w = worst(x);
    var line = (x.host + ' ' + x.os + ' ' + tx(x.verdict) + ' ' + x.file).toLowerCase();
    if (q && line.indexOf(q) < 0) { continue; }
    h += '<tr><td><b>' + esc(x.host) + '</b>' + (x.admin ? '' : '<br><span class="mut">' + esc(t('adminNo')) + '</span>') + '</td>';
    h += '<td>' + esc(x.when) + '</td><td class="mut">' + esc(x.os) + ' · ' + esc(tx(x.domain)) + '</td>';
    h += '<td class="' + w + '">' + esc(tx(x.verdict)) + (x.errors && x.errors.length ? ' <span class="err">!</span>' : '') + '</td>';
    h += '<td class="n Critical">' + x.counts.Critical + '</td><td class="n High">' + x.counts.High + '</td>';
    h += '<td class="n Medium">' + x.counts.Medium + '</td><td class="n mut">' + x.counts.Info + '</td>';
    h += '<td class="n mut">' + (x.suppressed || 0) + '</td><td class="n">' + (x.new || 0) + '</td>';
    h += '<td><a href="' + esc(x.file) + '">' + esc(x.file) + '</a></td></tr>';
  }
  return h + '</table></div>';
}

function findingsTable() {
  var list = arr(D.findings), q = filter.toLowerCase();
  var h = '<h2>' + esc(t('findingsTitle')) + '</h2>';
  if (!list.length) { return h + '<div class="card">' + esc(t('noFindings')) + '</div>'; }
  h += '<div class="card scroll"><table><tr><th>' + esc(t('thVerdict')) + '</th><th>' + esc(t('findingsTitle'));
  h += '</th><th class="n">' + esc(t('thCount')) + '</th><th>' + esc(t('affected')) + '</th></tr>';
  for (var i = 0; i < list.length; i++) {
    var f = list[i];
    var line = (f.t.en + ' ' + f.t.fr + ' ' + f.c + ' ' + f.h.join(' ')).toLowerCase();
    if (q && line.indexOf(q) < 0) { continue; }
    h += '<tr><td><span class="sev ' + f.s + '">' + esc(f.s) + '</span></td>';
    h += '<td>' + esc(tx(f.t)) + '<br><span class="cat">' + esc(tx(f.cl) || f.c) + '</span></td>';
    h += '<td class="n">' + f.h.length + '</td><td class="hosts">' + esc(f.h.join(', ')) + '</td></tr>';
  }
  return h + '</table></div>';
}

function render() {
  document.documentElement.lang = lang;
  document.title = t('title');
  document.getElementById('app').innerHTML = header() + hostsTable() + findingsTable();
  var i, b = document.querySelectorAll('.lang button');
  for (i = 0; i < b.length; i++) {
    b[i].onclick = function () {
      lang = this.getAttribute('data-lang');
      try { localStorage.setItem('wintriage.lang', lang); } catch (e) {}
      render();
    };
  }
  var th = document.querySelectorAll('th[data-sort]');
  for (i = 0; i < th.length; i++) {
    th[i].onclick = function () {
      var k = this.getAttribute('data-sort');
      if (k === sortKey) { sortDir = -sortDir; } else { sortKey = k; sortDir = 1; }
      render();
    };
  }
  var q = document.getElementById('q');
  q.oninput = function () { filter = q.value; render(); q.focus(); };
}
render();
</script></body></html>
'@

$html = $tpl.Replace('__LANG__', $Language).Replace('__DATA__', $blob)
[IO.File]::WriteAllText($OutputFile, $html, (New-Object System.Text.UTF8Encoding($true)))
if ($Json) { $data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$OutputFile.json" -Encoding UTF8 }

Write-Host ("{0} report(s) merged, {1} host(s)" -f $reports.Count, $hosts.Count) -ForegroundColor White
Write-Host ("Critical: {0}   High: {1}   Medium: {2}   Clean: {3}" -f $totals.critical, $totals.high, $totals.medium, $totals.clean)
foreach ($h in @($hosts | Where-Object { $_.counts.Critical -or $_.counts.High })) {
    Write-Host ("  {0,-18} C:{1} H:{2} M:{3}  {4}" -f $h.host, $h.counts.Critical, $h.counts.High, $h.counts.Medium, $h.verdict.en) -ForegroundColor Red
}
Write-Host ''
Write-Host "Fleet dashboard: $OutputFile"
if ($Json) { Write-Host "Summary JSON:    $OutputFile.json" }
if ($totals.critical -or $totals.high) { exit 2 } elseif ($totals.medium) { exit 1 } else { exit 0 }
