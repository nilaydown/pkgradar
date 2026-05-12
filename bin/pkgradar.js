#!/usr/bin/env node
'use strict';
const os = require('os');
const { scan, SEV } = require('../lib/scan');
const PKG = require('../package.json');

// ----------------------------------------------------------------------------
// args
// ----------------------------------------------------------------------------
const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f, d) => { const i = argv.indexOf(f); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };

if (has('-h') || has('--help')) {
  process.stdout.write(`pkgradar  -  content-based supply-chain scanner for npm / pnpm / yarn / bun

It opens the package files you actually installed and looks for what malware
does (install hooks, obfuscated payloads, known worm artifacts), instead of
just matching package names against an advisory list.

USAGE
  npx pkgradar [options]

OPTIONS
  --online            also cross-reference OSV.dev for known advisories (network)
  --json              machine-readable output
  --full              expanded per-finding output instead of the summary table
  --min-sev LEVEL     report findings at or above LEVEL
                      critical | high | medium | low | info        [default: medium]
  --stores LIST       comma list to limit which stores are scanned
                      project, pnpm-project, npm-global, npx-cache,
                      bun-cache, yarn-cache, yarn-berry
  --no-allowlist      do not downgrade findings on well-known packages
  --max-depth N       max node_modules nesting depth                [default: 12]
  --cwd DIR           project directory to scan                     [default: .]
  -h, --help

EXIT CODES
  0  clean       1  findings at or above --min-sev       2  scanner error
`);
  process.exit(0);
}

const SEV_FROM_NAME = { critical: SEV.CRITICAL, high: SEV.HIGH, medium: SEV.MEDIUM, low: SEV.LOW, info: SEV.INFO };
const minSevName = (val('--min-sev', 'medium') || 'medium').toLowerCase();
const minSev = SEV_FROM_NAME[minSevName] ?? SEV.MEDIUM;

// ----------------------------------------------------------------------------
// colour helpers
// ----------------------------------------------------------------------------
const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => COLOR ? `\x1b[${code}m${s}\x1b[0m` : `${s}`;
const C = {
  bold: paint('1'), dim: paint('2'), red: paint('31'), grn: paint('32'), ylw: paint('33'),
  blu: paint('34'), mag: paint('35'), cyan: paint('36'), gray: paint('90'),
};
// coloured "  CRITICAL  " cell: white-on-colour, fixed width
function sevCell(sev, width) {
  const bg = { CRITICAL: '41', HIGH: '45', MEDIUM: '43', LOW: '100', INFO: '100' }[sev] || '100';
  const fg = sev === 'MEDIUM' ? '30' : '97';
  const label = sev.padStart((width + sev.length) >> 1).padEnd(width);
  return COLOR ? `\x1b[${bg};${fg};1m${label}\x1b[0m` : label;
}
const SEV_TEXT = { CRITICAL: C.red, HIGH: C.mag, MEDIUM: C.ylw, LOW: C.gray, INFO: C.gray };
const homeShort = (p) => (p && p.startsWith(os.homedir())) ? '~' + p.slice(os.homedir().length) : p;

// ----------------------------------------------------------------------------
// foreground spinner (writes to stderr so stdout stays pipe-clean)
// ----------------------------------------------------------------------------
function makeSpinner() {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  const on = process.stderr.isTTY && !process.env.NO_COLOR;
  let i = 0, msg = 'starting', timer = null;
  const render = () => process.stderr.write(`\r\x1b[2K${C.cyan(frames[i = (i + 1) % frames.length])} ${C.gray(msg + ' …')}`);
  return {
    start() { if (!on) return; timer = setInterval(render, 80); render(); },
    set(m) { msg = m; },
    stop() { if (timer) clearInterval(timer); if (on) process.stderr.write('\r\x1b[2K'); },
  };
}

// ----------------------------------------------------------------------------
// table renderer
// ----------------------------------------------------------------------------
const clip = (s, n) => { s = String(s == null ? '' : s); return s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + '…'; };
const padTo = (s, n) => s + ' '.repeat(Math.max(0, n - s.length));

/**
 * Render an array of row objects as a box-drawn table.
 * @param {{key:string,label:string,width:number,color?:Function,raw?:boolean}[]} cols
 * @param {object[]} rows
 */
function table(cols, rows) {
  const B = COLOR ? C.gray : (s) => s;
  const line = (l, m, r) => B(l + cols.map((c) => '─'.repeat(c.width + 2)).join(m) + r);
  const out = [];
  out.push('  ' + line('┌', '┬', '┐'));
  out.push('  ' + B('│') + cols.map((c) => ' ' + C.bold(padTo(clip(c.label, c.width), c.width)) + ' ').join(B('│')) + B('│'));
  out.push('  ' + line('├', '┼', '┤'));
  for (const row of rows) {
    const cells = cols.map((c) => {
      const v = clip(row[c.key], c.width);
      if (c.raw) return ' ' + row[c.key] + ' ';                       // pre-formatted (already padded/coloured)
      const txt = padTo(v, c.width);
      return ' ' + (c.color ? c.color(txt) : txt) + ' ';
    });
    out.push('  ' + B('│') + cells.join(B('│')) + B('│'));
  }
  out.push('  ' + line('└', '┴', '┘'));
  return out.join('\n');
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
(async () => {
  const spin = makeSpinner();
  spin.start();
  spin.set('discovering package stores');
  let res;
  const t0 = Date.now();
  try {
    res = await scan({
      cwd: val('--cwd', process.cwd()),
      online: has('--online'),
      minSev,
      maxDepth: parseInt(val('--max-depth', '12'), 10) || 12,
      stores: (val('--stores', '') || '').split(',').map((s) => s.trim()).filter(Boolean),
      noAllowlist: has('--no-allowlist'),
      onPhase: (m) => spin.set(m),
    });
  } catch (err) {
    spin.stop();
    process.stderr.write(C.red('pkgradar error: ') + (err && err.stack || err) + '\n');
    process.exit(2);
  }
  spin.stop();
  const secs = ((Date.now() - t0) / 1000).toFixed(1);

  if (has('--json')) {
    process.stdout.write(JSON.stringify({ ...res, durationSeconds: Number(secs) }, null, 2) + '\n');
    process.exit(res.findings.some((f) => f.sevNum >= minSev) ? 1 : 0);
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of res.findings) counts[f.severity]++;
  const worst = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].find((k) => counts[k]) || null;
  const p = (...a) => process.stdout.write(a.join(' ') + '\n');

  // ---- header ----
  p('');
  p(`  ${C.bold('pkgradar')} ${C.gray('v' + PKG.version)}   ${C.gray('content-based supply-chain scan')}   ${C.gray(secs + 's')}`);
  p(`  ${C.gray('project')} ${homeShort(res.cwd)}`);
  p('');

  // ---- stores table ----
  p(table(
    [
      { key: 'kind', label: 'STORE', width: 14, color: C.cyan },
      { key: 'pkgs', label: 'PKGS', width: 6, color: C.dim },
      { key: 'root', label: 'PATH', width: Math.max(28, (process.stdout.columns || 120) - 32) },
    ],
    res.stores.map((s) => ({ kind: s.kind, pkgs: String(s.packages), root: homeShort(s.root) })),
  ));
  p(`  ${C.gray('total:')} ${C.bold(res.totalPackages)} ${C.gray('unique package@version,')} ${C.bold(res.totalScanned)} ${C.gray('locations inspected')}`);
  if (res.osv && res.osv.error) p(`  ${C.ylw('OSV lookup failed:')} ${C.dim(res.osv.error)}`);
  else if (!has('--online')) p(`  ${C.gray('tip: add')} ${C.dim('--online')} ${C.gray('to cross-check known advisories on OSV.dev')}`);
  p('');

  // ---- verdict ----
  if (!res.findings.length) {
    p(`  ${C.grn('●')} ${C.bold('Verdict:')} ${C.grn('clean')}  ${C.gray('nothing tripped the heuristics at ' + minSevName + ' and above')}`);
    p(`  ${C.gray('  (this inspects installed bytes; a clean run is not a proof of safety)')}`);
    p('');
    process.exit(0);
  }
  const bits = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].filter((k) => counts[k]).map((k) => SEV_TEXT[k](`${counts[k]} ${k.toLowerCase()}`));
  const dot = (worst === 'CRITICAL' || worst === 'HIGH') ? C.red('●') : worst === 'MEDIUM' ? C.ylw('●') : C.gray('●');
  p(`  ${dot} ${C.bold('Verdict:')} ${C.bold(res.findings.length + ' ' + (res.findings.length === 1 ? 'finding' : 'findings'))}  ${C.gray('(')}${bits.join(C.gray(', '))}${C.gray(')')}`);
  p('');

  // ---- findings ----
  const sorted = res.findings.slice().sort((a, b) => b.sevNum - a.sevNum || a.code.localeCompare(b.code) || a.package.localeCompare(b.package));

  if (has('--full')) {
    for (const f of sorted) {
      p(`  ${sevCell(f.severity, 10)} ${C.bold(f.package + '@' + f.version)}  ${C.gray(f.store)}  ${C.cyan(f.code)}`);
      p(`     ${f.message}`);
      if (f.evidence) p(`     ${C.gray('→ ' + f.evidence)}`);
      if (f.note) p(`     ${C.gray('note: ' + f.note)}`);
      if (f.dir) p(`     ${C.gray(homeShort(f.dir))}`);
      p('');
    }
  } else {
    const term = process.stdout.columns || 120;
    const W_PKG = 28, W_TYPE = 21, W_WHERE = 16;
    const W_DETAIL = Math.max(24, term - (2 + 3 + 10 + W_PKG + W_TYPE + W_WHERE + 3 * 5 + 1));
    const SHOW = 60;
    const rows = sorted.slice(0, SHOW).map((f) => ({
      sev: sevCell(f.severity, 10),
      pkg: f.package + '@' + f.version,
      type: f.code,
      where: f.store,
      detail: (f.evidence ? f.evidence + '  ' : '') + f.message,
    }));
    p(table(
      [
        { key: 'sev', label: 'SEVERITY', width: 10, raw: true },
        { key: 'pkg', label: 'PACKAGE', width: W_PKG, color: C.bold },
        { key: 'type', label: 'TYPE', width: W_TYPE, color: C.cyan },
        { key: 'where', label: 'WHERE', width: W_WHERE, color: C.dim },
        { key: 'detail', label: 'DETAIL', width: W_DETAIL, color: C.gray },
      ],
      rows,
    ));
    if (sorted.length > SHOW) p(`  ${C.gray('... and ' + (sorted.length - SHOW) + ' more (use --json for the full list)')}`);
    p(`  ${C.gray('use')} ${C.dim('--full')} ${C.gray('for untruncated details and on-disk paths')}`);
  }
  p('');

  // ---- what to do ----
  p(`  ${C.bold('What to do')}`);
  if (counts.CRITICAL || counts.HIGH) {
    p(`  ${C.red('•')} Treat ${C.bold('CRITICAL / HIGH "installed code" findings')} as suspect: don't run install`);
    p(`    scripts, remove the package, clear the relevant cache, rotate npm / GitHub / cloud tokens.`);
  }
  p(`  ${C.gray('•')} Check a flagged version against the registry: ${C.dim('npm view <pkg> versions')} ${C.gray('(publish dates, provenance).')}`);
  if (sorted.some((f) => f.code === 'osv-advisory')) p(`  ${C.gray('•')} OSV rows are the usual "known CVE in a dependency" set: ${C.dim('npm audit fix')} ${C.gray('/ bump.')}`);
  if (!has('--online')) p(`  ${C.gray('•')} Re-run with ${C.dim('--online')} ${C.gray('to add OSV.dev advisory matching by exact version.')}`);
  p('');

  process.exit(res.findings.some((f) => f.sevNum >= minSev) ? 1 : 0);
})();
