# Style sheet and script of the HTML report. Both are inlined into the page and
# listed by hash in its Content-Security-Policy, so nothing is loaded from outside.

CSS = r"""
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1a1f2b;--muted:#4b5563;--line:#d1d5db;--card:#f3f4f6;--link:#1d4ed8;
--unsafe-bg:#fde8e8;--unsafe-fg:#9b1c1c;--warn-bg:#fef3c7;--warn-fg:#7c2d12;--ok-bg:#dcfce7;--ok-fg:#14532d}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1420;--fg:#e6e9f0;--muted:#aab2c0;--line:#2b3446;--card:#18202f;--link:#8ab4ff;
--unsafe-bg:#4c1d1d;--unsafe-fg:#fecaca;--warn-bg:#4a3410;--warn-fg:#fde68a;--ok-bg:#14391f;--ok-fg:#bbf7d0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:0 16px 48px}
header{padding:24px 0 8px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.25rem;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--muted);margin:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em;overflow-wrap:anywhere}
a{color:var(--link)}
:focus-visible{outline:3px solid var(--link);outline-offset:2px}
[hidden]{display:none !important}
.verdict{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:16px;border-radius:8px;border:2px solid var(--line);margin:16px 0}
.verdict .word{font-size:1.5rem;font-weight:700}
.verdict.UNSAFE{background:var(--unsafe-bg);color:var(--unsafe-fg);border-color:var(--unsafe-fg)}
.verdict.WARN{background:var(--warn-bg);color:var(--warn-fg);border-color:var(--warn-fg)}
.verdict.OK{background:var(--ok-bg);color:var(--ok-fg);border-color:var(--ok-fg)}
.counts{display:flex;gap:8px;flex-wrap:wrap}
.sev{display:inline-block;font-weight:700;border-radius:4px;padding:1px 8px;white-space:nowrap}
.sev.UNSAFE{background:var(--unsafe-bg);color:var(--unsafe-fg);border:1px solid var(--unsafe-fg)}
.sev.WARN{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-fg)}
.sev.OK{background:var(--ok-bg);color:var(--ok-fg);border:1px solid var(--ok-fg)}
nav ul{list-style:none;display:flex;flex-wrap:wrap;gap:8px 16px;padding:0;margin:8px 0}
.controls{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin-bottom:8px}
.group{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
button{font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:6px;padding:4px 12px;cursor:pointer}
button[aria-pressed="true"]{background:var(--fg);color:var(--bg)}
input[type=search]{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:4px 8px;min-width:200px}
#list{list-style:none;padding:0;margin:0}
.finding{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--card)}
.finding summary::before{content:"\25B8";font-size:1.1em}.finding details[open] summary::before{content:"\25BE"}
.finding summary{cursor:pointer;padding:10px 12px;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:baseline}
.finding .body{padding:0 12px 12px}
.finding ul{margin:4px 0 8px;padding-left:20px}
.fix{border-left:4px solid var(--line);padding:4px 12px;margin:8px 0}
.small{color:var(--muted);font-size:.9em}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--card)}
.empty{color:var(--muted);padding:12px;border:1px dashed var(--line);border-radius:8px}
@media print{.controls,nav,button{display:none !important}}
@media (max-width:600px){table{min-width:560px}h1{font-size:1.3rem}.verdict .word{font-size:1.25rem}input[type=search]{min-width:0;width:100%}}
"""

JS = r"""
(function () {
  var list = document.getElementById('list');
  if (!list) { return; }
  var items = Array.prototype.slice.call(list.children);
  var count = document.getElementById('count');
  var empty = document.getElementById('none');
  var order = {UNSAFE: 0, WARN: 1, OK: 2};
  var severity = 'ALL', query = '';
  function apply() {
    var shown = 0;
    items.forEach(function (li) {
      var ok = (severity === 'ALL' || li.dataset.sev === severity) && (query === '' || li.dataset.text.indexOf(query) !== -1);
      li.hidden = !ok;
      if (ok) { shown += 1; }
    });
    count.textContent = 'Showing ' + shown + ' of ' + items.length + ' findings';
    empty.hidden = shown !== 0 || items.length === 0;
  }
  function sortBy(key) {
    items.sort(function (a, b) {
      if (key === 'severity') { return order[a.dataset.sev] - order[b.dataset.sev] || a.dataset.rule.localeCompare(b.dataset.rule); }
      return a.dataset[key].localeCompare(b.dataset[key]);
    });
    items.forEach(function (li) { list.appendChild(li); });
    Array.prototype.forEach.call(document.querySelectorAll('[data-sort]'), function (b) {
      b.setAttribute('aria-pressed', b.dataset.sort === key ? 'true' : 'false');
    });
  }
  function setOpen(open) {
    items.forEach(function (li) { if (!li.hidden) { li.firstElementChild.open = open; } });
  }
  function copyText(text, button) {
    var done = function (msg) { var old = button.dataset.label; button.textContent = msg; setTimeout(function () { button.textContent = old; }, 1500); };
    var fallback = function () {
      var area = document.createElement('textarea');
      area.value = text; document.body.appendChild(area); area.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(area);
      done(ok ? 'Copied' : 'Copy failed');
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done('Copied'); }, fallback);
    } else { fallback(); }
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-filter]'), function (b) {
    b.addEventListener('click', function () {
      severity = b.dataset.filter;
      Array.prototype.forEach.call(document.querySelectorAll('[data-filter]'), function (o) {
        o.setAttribute('aria-pressed', o === b ? 'true' : 'false');
      });
      apply();
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('[data-sort]'), function (b) {
    b.addEventListener('click', function () { sortBy(b.dataset.sort); });
  });
  document.getElementById('q').addEventListener('input', function (e) { query = e.target.value.trim().toLowerCase(); apply(); });
  document.getElementById('expand').addEventListener('click', function () { setOpen(true); });
  document.getElementById('collapse').addEventListener('click', function () { setOpen(false); });
  list.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (b) { copyText(b.dataset.copy, b); }
  });
  apply();
})();
"""
