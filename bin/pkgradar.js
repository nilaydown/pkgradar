#!/usr/bin/env node
'use strict';
const os = require('os');
const { scan, SEV } = require('../lib/scan');
const PKG = require('../package.json');

// ----------------------------------------------------------------------------
// args
// ----------------------------------------------------------------------------
const argv = process.argv.slice(2);

/**
 * Returns true if the given flag is present in argv.
 * @param {string} f - Flag string, e.g. "--online".
 * @returns {boolean}
 */
const has = (f) => argv.includes(f);

/**
 * Returns the value of a flag argument, or a default if absent.
 * @param {string} f   - Flag string, e.g. "--min-sev".
 * @param {string} def - Default value when flag is missing or has no argument.
 * @returns {string}
 */
const val = (f, def) => { const i = argv.indexOf(f); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; };

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
  --compact           one terse line per finding instead of full blocks
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

/**
 * Returns a function that wraps a string in the given ANSI escape code.
 * Falls back to a no-op when COLOR is disabled.
 * @param {string} code - ANSI code fragment, e.g. "31" for red.
 * @returns {(s: string) => string}
 */
const paint = (code) => (s) => COLOR ? `\x1b[${code}m${s}\x1b[0m` : `${s}`;

const C = {
  bold: paint('1'), dim: paint('2'), red: paint('31'), grn: paint('32'), ylw: paint('33'),
  blu: paint('34'), mag: paint('35'), cyan: paint('36'), gray: paint('90'),
};


/** Maps severity name to a colouring function for plain-text severity mentions. */
const SEV_TEXT = { CRITICAL: C.red, HIGH: C.mag, MEDIUM: C.ylw, LOW: C.gray, INFO: C.gray };

/**
 * Replaces the home-directory prefix of a path with "~" for compact display.
 * @param {string|null} p - Absolute path, or null/undefined.
 * @returns {string|null}
 */
const homeShort = (p) => (p && p.startsWith(os.homedir())) ? '~' + p.slice(os.homedir().length) : p;

// ----------------------------------------------------------------------------
// foreground spinner (writes to stderr so stdout stays pipe-clean)
// ----------------------------------------------------------------------------

/**
 * Creates a TTY spinner that writes to stderr.
 * @returns {{start: Function, set: Function, stop: Function}}
 */
function makeSpinner() {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  const on = process.stderr.isTTY && !process.env.NO_COLOR;
  let i = 0, msg = 'starting', timer = null;
  const render = () => process.stderr.write(`\r\x1b[2K${C.cyan(frames[i = (i + 1) % frames.length])} ${C.gray(msg + ' …')}`);
  return {
    /** Start the spinner interval. */
    start() { if (!on) return; timer = setInterval(render, 80); render(); },
    /** Update the status message shown next to the spinner. @param {string} m */
    set(m) { msg = m; },
    /** Stop the spinner and clear the line. */
    stop() { if (timer) clearInterval(timer); if (on) process.stderr.write('\r\x1b[2K'); },
  };
}

// ----------------------------------------------------------------------------
// table renderer
// ----------------------------------------------------------------------------

/**
 * Clip string s to at most n chars, appending "…" if truncated.
 * @param {*}      s - Value to stringify and clip.
 * @param {number} n - Maximum character count.
 * @returns {string}
 */
const clip = (s, n) => { s = String(s == null ? '' : s); return s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + '…'; };

/**
 * Pad string s with trailing spaces to exactly n characters.
 * @param {string} s
 * @param {number} n
 * @returns {string}
 */
const padTo = (s, n) => s + ' '.repeat(Math.max(0, n - s.length));

/**
 * Render an array of row objects as a box-drawn table.
 * @param {{key:string, label:string, width:number, color?:Function, raw?:boolean}[]} cols - Column definitions.
 * @param {object[]} rows - Row data objects keyed by col.key.
 * @returns {string} Rendered table string (no trailing newline).
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
      if (c.raw) return ' ' + row[c.key] + ' ';       // pre-formatted (already padded/coloured)
      const txt = padTo(v, c.width);
      return ' ' + (c.color ? c.color(txt) : txt) + ' ';
    });
    out.push('  ' + B('│') + cells.join(B('│')) + B('│'));
  }
  out.push('  ' + line('└', '┴', '┘'));
  return out.join('\n');
}

/**
 * Word-wrap a plain string to a column width, returning an array of lines.
 * Tokens longer than the width are hard-split so nothing overflows.
 * @param {string} text  - Text to wrap (no ANSI codes).
 * @param {number} width - Max characters per line.
 * @returns {string[]}
 */
function wrap(text, width) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let cur = '';
  for (let w of words) {
    while (w.length > width) { if (cur) { lines.push(cur); cur = ''; } lines.push(w.slice(0, width)); w = w.slice(width); }
    if (!cur) cur = w;
    else if (cur.length + 1 + w.length <= width) cur += ' ' + w;
    else { lines.push(cur); cur = w; }
  }
  if (cur) lines.push(cur);
  return lines.length ? lines : [''];
}

/** One-line plain-language explanation of why each finding type matters. */
const WHY = {
  'lifecycle-hook': 'install hooks run automatically on npm/yarn/pnpm install; this one does something a normal build step would not',
  'worm-ioc-file': 'this filename is a known artifact of the Shai-Hulud worm family',
  'suspicious-js': 'code that decodes and then executes a payload, or hard-coded worm exfiltration constants',
  'embedded-gh-workflow': 'harmless on its own; just noting the package ships a CI workflow file',
  'malicious-gh-workflow': 'a bundled GitHub Actions workflow that pipes a remote script straight into a shell',
  'odd-bin': 'a bin entry pointing outside the package or at a shell script is unusual for a dependency',
  'osv-advisory': 'a publicly known vulnerability affects this exact version; check whether a patched release exists',
};

/** ●-marker colour by severity, used at the start of each finding block. */
const SEV_DOT = { CRITICAL: C.red('●'), HIGH: C.mag('●'), MEDIUM: C.ylw('●'), LOW: C.gray('●'), INFO: C.gray('○') };

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
/** Entry point: parses CLI flags, calls scan(), then renders results to stdout. */
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

  // Shorthand to write a line to stdout.
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
  // Grouped by severity, one readable block per finding. A fixed-width table would
  // truncate the detail text, so we wrap it to the terminal instead.
  const sorted = res.findings.slice().sort((a, b) => b.sevNum - a.sevNum || a.code.localeCompare(b.code) || a.package.localeCompare(b.package));
  const term = Math.max(60, Math.min(process.stdout.columns || 100, 120));
  const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  if (has('--compact')) {
    // one terse line per finding
    const pkgW = Math.min(34, Math.max(...sorted.map((f) => (f.package + '@' + f.version).length)));
    for (const f of sorted) {
      p(`  ${SEV_DOT[f.severity]} ${SEV_TEXT[f.severity](f.severity.padEnd(8))} ${C.bold(padTo(clip(f.package + '@' + f.version, pkgW), pkgW))}  ${C.cyan(padTo(f.code, 21))} ${C.gray(clip(f.evidence || f.message, term - pkgW - 36))}`);
    }
  } else {
    const FW = term - 13;                                    // width available for wrapped field text
    /** Print a labelled, word-wrapped field under a finding (label only on the first line). */
    const field = (key, text, paint) => {
      if (text == null || text === '') return;
      wrap(text, FW).forEach((ln, i) => p(`      ${C.gray((i === 0 ? key : '').padEnd(9))} ${paint ? paint(ln) : ln}`));
    };
    for (const sev of ORDER) {
      const group = sorted.filter((f) => f.severity === sev);
      if (!group.length) continue;
      p(`  ${SEV_TEXT[sev](C.bold(sev))} ${C.gray('· ' + group.length)}`);
      p(`  ${C.gray('─'.repeat(term - 2))}`);
      for (const f of group) {
        p(`  ${SEV_DOT[sev]} ${C.bold(f.package + '@' + f.version)}   ${C.cyan(f.code)}   ${C.gray('in ' + f.store)}`);
        field('what', f.message);
        field('evidence', f.evidence, C.gray);
        field('why', WHY[f.code], C.gray);
        field('note', f.note, C.gray);
        if (f.dir) p(`      ${C.gray('path'.padEnd(9))} ${C.gray(homeShort(f.dir))}`);
        p('');
      }
    }
    p(`  ${C.gray('use')} ${C.dim('--compact')} ${C.gray('for a one-line-per-finding view, or')} ${C.dim('--json')} ${C.gray('for machine output')}`);
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
