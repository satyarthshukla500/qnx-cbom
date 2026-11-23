// Clicks every control of the HTML report in headless Chromium and logs PASS/FAIL per control.
// Builds three reports (small, empty, 600 findings) from synthetic images; no SDK files are used.
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qnxcbom-ui-'));
const logPath = process.env.UI_LOG || path.join(tmp, 'ui-test-log.txt');
const shots = process.env.UI_SHOTS || tmp;
const lines = [];
let fails = 0, controls = 0;

function log(page, what, result, detail) {
  controls += 1;
  if (!result) fails += 1;
  lines.push(`${result ? 'PASS' : 'FAIL'}  [${page}] ${what} -> ${detail}`);
}

function build() {
  // reports are made by the python helper so the test uses the real generator
  const out = execFileSync('python3', ['-I', path.join(__dirname, 'make_reports.py'), tmp], { env: { ...process.env, PYTHONPATH: path.join(root, 'src') } });
  return JSON.parse(out.toString());
}

async function exercise(browser, name, file, opts) {
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 } });
  const page = await ctx.newPage();
  const problems = [], requests = [];
  page.on('console', m => { if (['error', 'warning'].includes(m.type())) problems.push(m.type() + ': ' + m.text()); });
  page.on('pageerror', e => problems.push('pageerror: ' + e.message));
  page.on('request', r => { if (!r.url().startsWith('file://') && !r.url().startsWith('data:')) requests.push(r.url()); });
  await page.goto('file://' + file);
  const total = await page.locator('#list > li').count();
  log(name, 'page load', total === opts.findings, `${total} findings in list (expected ${opts.findings})`);
  if (total > 0) {
    const shown = () => page.locator('#list > li:not([hidden])').count();
    for (const sev of ['UNSAFE', 'WARN', 'OK', 'ALL']) {
      await page.click(`[data-filter="${sev}"]`);
      const n = await shown();
      const wrong = sev === 'ALL' ? 0 : await page.locator(`#list > li:not([hidden]):not([data-sev="${sev}"])`).count();
      const pressed = await page.getAttribute(`[data-filter="${sev}"]`, 'aria-pressed');
      log(name, `filter button ${sev}`, wrong === 0 && pressed === 'true' && (sev !== 'ALL' || n === total), `${n} shown, ${wrong} wrong severity, aria-pressed=${pressed}`);
    }
    await page.fill('#q', 'zzzz-no-such-text');
    let n = await shown();
    const none = await page.isVisible('#none');
    log(name, 'search box, no match', n === 0 && none, `${n} shown, empty message visible=${none}`);
    await page.fill('#q', opts.query);
    n = await shown();
    log(name, `search box "${opts.query}"`, n === opts.queryCount, `${n} shown (expected ${opts.queryCount})`);
    await page.fill('#q', '');
    n = await shown();
    log(name, 'search box cleared', n === total, `${n} shown`);
    for (const key of ['rule', 'subject', 'severity']) {
      await page.click(`[data-sort="${key}"]`);
      const vals = await page.$$eval('#list > li', els => els.map(e => [e.dataset.sev, e.dataset.rule, e.dataset.subject]));
      const order = { UNSAFE: 0, WARN: 1, OK: 2 };
      let ok = true;
      for (let i = 1; i < vals.length; i++) {
        const a = vals[i - 1], b = vals[i];
        if (key === 'severity' && order[a[0]] > order[b[0]]) ok = false;
        if (key === 'rule' && a[1].localeCompare(b[1]) > 0) ok = false;
        if (key === 'subject' && a[2].localeCompare(b[2]) > 0) ok = false;
      }
      log(name, `sort button ${key}`, ok, `list of ${vals.length} ${ok ? 'is' : 'is NOT'} ordered by ${key}`);
    }
    await page.click('#expand');
    const open1 = await page.locator('#list > li:not([hidden]) > details[open]').count();
    log(name, 'Expand all', open1 === total, `${open1} of ${total} open`);
    await page.click('#collapse');
    const open2 = await page.locator('#list > li > details[open]').count();
    log(name, 'Collapse all', open2 === 0, `${open2} open`);
    await page.click('#list > li:first-child summary');
    const first = await page.getAttribute('#list > li:first-child details', 'open');
    log(name, 'click on a finding summary', first !== null, 'details opened');
    await page.focus('#list > li:nth-child(2) summary');
    await page.keyboard.press('Enter');
    const second = await page.getAttribute('#list > li:nth-child(2) details', 'open');
    log(name, 'keyboard Enter on summary', second !== null, 'details opened');
    await ctx.grantPermissions(['clipboard-read', 'clipboard-write']).catch(() => {});
    const copyBtn = page.locator('#list > li:first-child [data-copy]');
    await copyBtn.click();
    const label = await copyBtn.textContent();
    let clip = '';
    try { clip = await page.evaluate(() => navigator.clipboard.readText()); } catch (e) { clip = ''; }
    const expected = await copyBtn.getAttribute('data-copy');
    log(name, 'Copy fix button', ['Copied', 'Copy failed'].includes(label) && (label === 'Copy failed' || clip === expected), `label "${label}", clipboard ${clip === expected ? 'equals fix text' : 'differs (' + clip.length + ' chars)'}`);
    const href = await page.getAttribute('#list > li:first-child a', 'href');
    const rel = await page.getAttribute('#list > li:first-child a', 'rel');
    log(name, 'source link', /^https:\/\//.test(href) && /noopener/.test(rel), `${href} rel=${rel}`);
  } else {
    log(name, 'empty state', await page.isVisible('text=No findings.'), 'message "No findings." visible');
    log(name, 'filter and sort buttons exist', await page.locator('[data-filter]').count() === 4, '4 filter buttons present');
  }
  for (const id of ['findings', 'programs', 'libraries', 'keys', 'config', 'runtime', 'method']) {
    await page.click(`nav a[href="#${id}"]`);
    const visible = await page.locator('#' + id).isVisible();
    log(name, `nav link #${id}`, visible && page.url().endsWith('#' + id), `section visible, url ends #${id}`);
  }
  await page.screenshot({ path: path.join(shots, `${name}-wide.png`), fullPage: true });
  // narrow window and keyboard tab order
  await page.setViewportSize({ width: 360, height: 800 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  log(name, 'narrow window 360 px', overflow <= 0, `page-wide horizontal overflow ${overflow}px`);
  await page.screenshot({ path: path.join(shots, `${name}-narrow.png`), fullPage: false });
  await page.setViewportSize({ width: 1200, height: 900 });
  await page.goto('file://' + file);
  const tabbed = [];
  for (let i = 0; i < 6; i++) { await page.keyboard.press('Tab'); tabbed.push(await page.evaluate(() => document.activeElement.tagName + ':' + (document.activeElement.textContent || document.activeElement.id).trim().slice(0, 14))); }
  log(name, 'Tab key moves focus', new Set(tabbed).size === 6 && !tabbed.some(t => t.startsWith('BODY')), tabbed.join(' > '));
  log(name, 'console errors and warnings', problems.length === 0, problems.length ? problems.join(' | ') : 'none');
  log(name, 'network requests leaving the page', requests.length === 0, requests.length ? requests.join(' ') : 'none');
  await ctx.close();
}

(async () => {
  const reports = build();
  const browser = await chromium.launch();
  await exercise(browser, 'small', reports.small, { findings: reports.smallCount, query: 'qcb-002', queryCount: reports.smallQuery });
  await exercise(browser, 'empty', reports.empty, { findings: 0 });
  await exercise(browser, 'large', reports.large, { findings: 600, query: '/x/7', queryCount: reports.largeQuery });
  // hostile text must stay plain text
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  let dialogs = 0;
  page.on('dialog', d => { dialogs += 1; d.dismiss(); });
  await page.goto('file://' + reports.hostile);
  const injected = await page.evaluate(() => document.querySelectorAll('#list script, #list img, #list [onmouseover]').length + (window.pwned ? 1 : 0));
  const text = await page.locator('#list').textContent();
  log('hostile', 'script/markup in file names and config text', injected === 0 && dialogs === 0 && text.includes('<script>'), `injected elements ${injected}, dialogs ${dialogs}, shown as text: ${text.includes('<script>')}`);
  await ctx.close();
  await browser.close();
  lines.push(`TOTAL controls/checks ${controls}, failed ${fails}`);
  fs.writeFileSync(logPath, lines.join('\n') + '\n');
  console.log(lines.join('\n'));
  process.exit(fails ? 1 : 0);
})();
