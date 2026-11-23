// Checks that an HTML report really renders, in English and in French, and that the
// language switch embedded in the page works. Runs the page's own script against a
// minimal DOM shim, so it needs no browser:
//
//     cscript //nologo tests\Test-ReportRender.js <report.html>
//
// Run-SelfTest.ps1 calls it automatically when cscript is available.
// Keep this file ASCII only: cscript reads it as ANSI, so accented literals would
// not survive. Expected text is taken from the report's own data instead.

var path = WScript.Arguments(0);

// cscript runs JScript 5.8: no JSON, no Date.toISOString. The page uses both and browsers have
// them, so the shim provides them here rather than the page doing without.
if (typeof JSON === 'undefined') {
    JSON = {
        parse: function (s) { return eval('(' + (s === '' || s === null || s === undefined ? 'null' : s) + ')'); },
        stringify: function (v, r, sp) {
            function q(s) {
                return '"' + String(s).replace(/[\\"\u0000-\u001f]/g, function (c) {
                    if (c === '\\') { return '\\\\'; }
                    if (c === '"') { return '\\"'; }
                    if (c === '\n') { return '\\n'; }
                    if (c === '\r') { return '\\r'; }
                    if (c === '\t') { return '\\t'; }
                    var h = c.charCodeAt(0).toString(16);
                    return '\\u' + '0000'.substring(h.length) + h;
                }) + '"';
            }
            function walk(x) {
                if (x === null || x === undefined) { return 'null'; }
                var tn = Object.prototype.toString.call(x), i, out;
                if (tn === '[object Array]') {
                    out = [];
                    for (i = 0; i < x.length; i++) { out.push(walk(x[i])); }
                    return '[' + out.join(',') + ']';
                }
                if (tn === '[object Number]' || typeof x === 'number') { return isFinite(x) ? String(x) : 'null'; }
                if (tn === '[object Boolean]' || typeof x === 'boolean') { return x ? 'true' : 'false'; }
                if (tn === '[object String]' || typeof x === 'string') { return q(x); }
                out = [];
                for (i in x) { if (x.hasOwnProperty(i) && typeof x[i] !== 'function') { out.push(q(i) + ':' + walk(x[i])); } }
                return '{' + out.join(',') + '}';
            }
            return walk(v);
        }
    };
}
if (!Date.prototype.toISOString) {
    Date.prototype.toISOString = function () {
        function p(n, w) { var s = String(n); while (s.length < (w || 2)) { s = '0' + s; } return s; }
        return this.getUTCFullYear() + '-' + p(this.getUTCMonth() + 1) + '-' + p(this.getUTCDate()) + 'T' +
               p(this.getUTCHours()) + ':' + p(this.getUTCMinutes()) + ':' + p(this.getUTCSeconds()) + 'Z';
    };
}

function readUtf8(p) {
    var st = new ActiveXObject('ADODB.Stream');
    st.Type = 2; st.Charset = 'utf-8'; st.Open(); st.LoadFromFile(p);
    var s = st.ReadText(); st.Close(); return s;
}

var page = readUtf8(path);
var block = page.match(/<script>([\s\S]*?)<\/script>/);
if (!block) { WScript.Echo('FAIL: no script block in ' + path); WScript.Quit(1); }

// --- minimal DOM ----------------------------------------------------------
function FakeEl(tag, attrs, text) {
    this.tag = tag; this.attrs = attrs || {}; this.style = {};
    this.className = this.attrs['class'] || ''; this.textContent = text || ''; this.value = ''; this.innerHTML = '';
}
FakeEl.prototype.getAttribute = function (n) { return this.attrs[n] === undefined ? null : this.attrs[n]; };

var app = new FakeEl('main', { id: 'app' });
var docEl = { lang: '' };
// The toolbar buttons and the export box the renderer wires up by id
var byId = {};
function elById(id) { if (!byId[id]) { byId[id] = new FakeEl('div', { id: id }); } return byId[id]; }

// Answers the selectors the renderer uses, by scanning the markup it produced.
function nodesFrom(markup, selector) {
    var out = [], re, m;
    if (selector === '.lang button') {
        re = /<button type="button" data-lang="(\w+)"/g;
        while ((m = re.exec(markup)) !== null) { out.push(new FakeEl('button', { 'data-lang': m[1] })); }
    } else if (selector === '.tile') {
        re = /<div class="card tile ([\w ]+?)" data-sev="(\w+)"/g;
        while ((m = re.exec(markup)) !== null) { out.push(new FakeEl('div', { 'data-sev': m[2], 'class': m[1] })); }
    } else if (selector === '#list .f') {
        re = /<div data-key="(\w+)" data-new="(\d)" data-mark="(\w*)" class="card f (\w+)" data-sev="(\w+)">([\s\S]*?)(?=<div data-key=|<\/div><h2)/g;
        while ((m = re.exec(markup)) !== null) {
            out.push(new FakeEl('div', { 'data-sev': m[5], 'data-key': m[1], 'data-new': m[2], 'data-mark': m[3] }, m[6].replace(/<[^>]*>/g, ' ')));
        }
    } else if (selector === '.tbtn') {
        re = /<button type="button" class="btn tbtn[^"]*" data-set="(\w+)" data-k="(\w+)"/g;
        while ((m = re.exec(markup)) !== null) { out.push(new FakeEl('button', { 'data-set': m[1], 'data-k': m[2] })); }
    }
    return out;
}
// Nodes are cached per markup version, so handlers and applyFilter() act on the same objects.
var cache = { html: null, sel: {} };
var document = {
    documentElement: docEl, title: '', body: { appendChild: function () {}, removeChild: function () {} },
    createElement: function (tag) { return new FakeEl(tag, {}); },
    getElementById: function (id) { return id === 'app' ? app : elById(id); },
    querySelectorAll: function (sel) {
        if (cache.html !== app.innerHTML) { cache.html = app.innerHTML; cache.sel = {}; }
        if (!cache.sel[sel]) { cache.sel[sel] = nodesFrom(app.innerHTML, sel); }
        return cache.sel[sel];
    }
};
var localStorage = {
    store: {},
    getItem: function (k) { return this.store[k] === undefined ? null : this.store[k]; },
    setItem: function (k, v) { this.store[k] = v; }
};

// --- run the page's own renderer ------------------------------------------
var fails = 0;
function check(name, ok) { if (!ok) { fails++; WScript.Echo('   FAIL ' + name); } }
function has(s) { return app.innerHTML.indexOf(s) >= 0; }

try { eval(block[1]); } catch (e) { WScript.Echo('FAIL: script error: ' + e.message); WScript.Quit(1); }

function checkLanguage(code) {
    var L = S[code], other = S[code === 'en' ? 'fr' : 'en'], i, list;
    check(code + ': page rendered', app.innerHTML.length > 1500);
    check(code + ': html lang attribute', docEl.lang === code);
    check(code + ': document title', document.title.indexOf(L.title) === 0);
    check(code + ': both language buttons', has('data-lang="en"') && has('data-lang="fr"'));
    var chrome = ['title', 'results', 'checksTitle', 'thCheck', 'thItems', 'thNotes', 'scope', 'profiles', 'limitsTitle'];
    for (i = 0; i < chrome.length; i++) { check(code + ': ' + chrome[i], has(esc(L[chrome[i]]))); }
    check(code + ': verdict', has(esc(D.verdicts[D.verdict][code])));
    check(code + ': severity labels', has(esc(D.sevs.Critical[code])) && has(esc(D.sevs.Info[code])));
    // Every finding, its category and its advice must show up in this language
    list = arr(D.findings);
    for (i = 0; i < list.length; i++) {
        check(code + ': finding "' + list[i].t.en + '"', has(esc(list[i].t[code])));
        check(code + ': category of "' + list[i].t.en + '"', has(esc(D.cats[list[i].c][code])));
        if (list[i].a && list[i].a[code]) { check(code + ': advice label', has(esc(L.todo))); }
    }
    if (!list.length) { check(code + ': empty-state text', has(esc(L.none))); }
    // Checks table: one row per check, with the localized check name
    list = arr(D.checks);
    for (i = 0; i < list.length; i++) { check(code + ': check row ' + list[i].n, has(esc(D.cats[list[i].n][code]))); }
    // No leftovers from the other language
    check(code + ': no stale chrome from the other language', !has(esc(other.checksTitle)) && !has(esc(other.limitsTitle)));
}

function clickLang(code) {
    var b = document.querySelectorAll('.lang button');
    for (var i = 0; i < b.length; i++) { if (b[i].getAttribute('data-lang') === code) { onLang.call(b[i]); return true; } }
    return false;
}

checkLanguage(D.lang === 'fr' ? 'fr' : 'en');
check('switch to french', clickLang('fr'));
checkLanguage('fr');
check('language remembered', localStorage.getItem('wintriage.lang') === 'fr');
check('switch back to english', clickLang('en'));
checkLanguage('en');

// Info findings start hidden, the other levels start visible
applyFilter();
var nodes = document.querySelectorAll('#list .f');
for (var k = 0; k < nodes.length; k++) {
    var want = nodes[k].getAttribute('data-sev') === 'Info' ? 'none' : '';
    check('visibility of a ' + nodes[k].getAttribute('data-sev') + ' finding', nodes[k].style.display === want);
}

// Timeline, suppressed and expired sections follow the data
var tl = arr(D.timeline);
check('timeline section', app.innerHTML.indexOf(esc(S[lang].timelineTitle)) >= 0);
if (tl.length) {
    check('timeline first entry', app.innerHTML.indexOf(esc(tl[0].w)) >= 0 && app.innerHTML.indexOf(esc(tl[0].t[lang])) >= 0);
} else {
    check('timeline empty state', app.innerHTML.indexOf(esc(S[lang].timelineEmpty)) >= 0);
}
var sup = arr(D.suppressed);
if (sup.length) {
    check('suppressed section', app.innerHTML.indexOf(esc(sup[0].t[lang])) >= 0 && app.innerHTML.indexOf(esc(sup[0].reason)) >= 0);
    check('suppressed are not in the findings list', nodesFrom(app.innerHTML, '#list .f').length === arr(D.findings).length);
}
if (arr(D.expired).length) { check('expired rules section', app.innerHTML.indexOf(esc(arr(D.expired)[0].title)) >= 0); }
if (D.baseline && D.baseline.file) { check('baseline line', app.innerHTML.indexOf(esc(D.baseline.file)) >= 0); }

// Triage: marking a finding accepted must persist and dim it
var all = arr(D.findings);
if (all.length) {
    var target = all[0].k;
    var btns = document.querySelectorAll('.tbtn'), hit = null;
    for (var b2 = 0; b2 < btns.length; b2++) {
        if (btns[b2].getAttribute('data-k') === target && btns[b2].getAttribute('data-set') === 'ok') { hit = btns[b2]; }
    }
    check('accept button present', hit !== null);
    if (hit) {
        onMark.call(hit);
        check('mark stored in the browser', (JSON.parse(localStorage.getItem('wintriage.triage.' + D.computer) || '{}'))[target] === 'ok');
        var after = document.querySelectorAll('#list .f'), dimmed = false;
        for (var c2 = 0; c2 < after.length; c2++) {
            if (after[c2].getAttribute('data-key') === target) { dimmed = (after[c2].style.opacity === '0.5'); }
        }
        check('accepted finding dimmed', dimmed);
        hideOk = true; applyFilter();
        var after2 = document.querySelectorAll('#list .f'), gone = false;
        for (var d2 = 0; d2 < after2.length; d2++) {
            if (after2[d2].getAttribute('data-key') === target) { gone = (after2[d2].style.display === 'none'); }
        }
        check('"hide accepted" hides it', gone);
        hideOk = false;
        // The export produces the JSON and an allowlist block carrying the key
        exportTriage();
        var box = elById('exp').innerHTML;
        check('export contains the decision', box.indexOf(target) >= 0 && box.indexOf('Suppress') >= 0);
        onMark.call(hit);   // back to no mark
        check('mark cleared', !(JSON.parse(localStorage.getItem('wintriage.triage.' + D.computer) || '{}'))[target]);
    }
}

if (fails) { WScript.Echo('   ' + fails + ' render check(s) failed'); WScript.Quit(1); }
WScript.Echo('       report renders in en and fr, switch works (' + arr(D.findings).length + ' findings)');
WScript.Quit(0);
