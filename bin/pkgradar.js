#!/usr/bin/env node
'use strict';
const os = require('os');
const { scan, SEV } = require('../lib/scan');

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? args[i + 1] : d; };

if (has('-h') || has('--help')) {
  console.log(`pkgradar  -  content-based supply-chain scanner for npm / pnpm / yarn / bun

It opens the package files you actually installed and looks for what malware
does (install hooks, obfuscated payloads, known worm artifacts), instead of
just matching package names against an advisory list.

USAGE
  npx pkgradar [options]

OPTIONS
  --online            also cross-reference OSV.dev for known advisories (network)
  --json              machine-readable output
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

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const e = (code) => useColor ? `\x1b[${code}m` : '';
const wrap = (code) => (s) => useColor ? `\x1b[${code}m${s}\x1b[0m` : `${s}`;
const C = {
  bold: wrap('1'), dim: wrap('2'), red: wrap('31'), grn: wrap('32'), ylw: wrap('33'),
  blu: wrap('34'), mag: wrap('35'), cyan: wrap('36'), gray: wrap('90'),
};
// severity badge: white text on a coloured background, padded
const badge = (sev) => {
  const bg = { CRITICAL: '41', HIGH: '45', MEDIUM: '43', LOW: '100', INFO: '100' }[sev] || '100';
  const fg = sev === 'MEDIUM' ? '30' : '97';
  const label = ` ${sev} `.padEnd(10);
  return useColor ? `\x1b[${bg};${fg};1m${label}\x1b[0m` : `[${sev}]`.padEnd(10);
};
const SEV_TEXT = { CRITICAL: C.red, HIGH: C.mag, MEDIUM: C.ylw, LOW: C.gray, INFO: C.gray };
const homeShort = (p) => (p && p.startsWith(os.homedir())) ? '~' + p.slice(os.homedir().length) : p;

function rule(ch = '─', n = 64) { return C.gray(ch.repeat(n)); }

(async () => {
  let res;
  const started = Date.now();
  try {
    res = await scan({
      cwd: val('--cwd', process.cwd()),
      online: has('--online'),
      minSev,
      maxDepth: parseInt(val('--max-depth', '12'), 10) || 12,
      stores: (val('--stores', '') || '').split(',').map((s) => s.trim()).filter(Boolean),
      noAllowlist: has('--no-allowlist'),
    });
  } catch (err) {
    console.error(C.red('pkgradar error: ') + (err && err.stack || err));
    process.exit(2);
  }
  const secs = ((Date.now() - started) / 1000).toFixed(1);

  if (has('--json')) {
    console.log(JSON.stringify({ ...res, durationSeconds: Number(secs) }, null, 2));
    process.exit(res.findings.some((f) => f.sevNum >= minSev) ? 1 : 0);
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of res.findings) counts[f.severity]++;
  const localFindings = res.findings.filter((f) => f.code !== 'osv-advisory');
  const osvFindings = res.findings.filter((f) => f.code === 'osv-advisory');
  const hits = res.findings.length;
  const worst = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].find((k) => counts[k]) || null;

  // ---- header ----
  console.log('');
  console.log(`  ${C.bold('pkgradar')} ${C.gray('v' + require('../package.json').version)}   ${C.gray('content-based supply-chain scan')}`);
  console.log(`  ${C.gray('project')} ${homeShort(res.cwd)}   ${C.gray(res.stores.length + ' stores, ' + secs + 's')}`);
  console.log('');

  // ---- stores table ----
  const nameW = Math.max(...res.stores.map((s) => s.kind.length), 6);
  for (const s of res.stores) {
    console.log(`  ${C.cyan(s.kind.padEnd(nameW))}  ${C.dim(String(s.packages).padStart(5) + ' pkgs')}  ${C.gray(homeShort(s.root))}`);
  }
  console.log(`  ${C.gray('total:')} ${C.bold(res.totalPackages)} ${C.gray('unique package@version,')} ${C.bold(res.totalScanned)} ${C.gray('locations inspected')}`);
  if (res.osv && res.osv.error) console.log(`  ${C.ylw('OSV lookup failed:')} ${C.dim(res.osv.error)}`);
  if (!res.osv && !has('--online')) console.log(`  ${C.gray('tip: add')} ${C.dim('--online')} ${C.gray('to also cross-check known advisories on OSV.dev')}`);
  console.log('');

  // ---- verdict line ----
  if (!hits) {
    console.log(`  ${C.grn('●')} ${C.bold('Verdict:')} ${C.grn('clean')} ${C.gray('- nothing tripped the heuristics at')} ${C.dim(minSevName)} ${C.gray('and above')}`);
    console.log(`  ${C.gray('  (this inspects installed bytes; a clean run is not a proof of safety)')}`);
    console.log('');
    process.exit(0);
  }
  const summaryBits = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].filter((k) => counts[k]).map((k) => SEV_TEXT[k](`${counts[k]} ${k.toLowerCase()}`));
  const dot = worst === 'CRITICAL' || worst === 'HIGH' ? C.red('●') : worst === 'MEDIUM' ? C.ylw('●') : C.gray('●');
  console.log(`  ${dot} ${C.bold('Verdict:')} ${C.bold(hits + (hits === 1 ? ' finding' : ' findings'))}  ${C.gray('(')}${summaryBits.join(C.gray(', '))}${C.gray(')')}`);
  if (localFindings.length && osvFindings.length) {
    console.log(`  ${C.gray('  ' + localFindings.length + ' from inspecting installed code, ' + osvFindings.length + ' known advisories (OSV.dev)')}`);
  }
  console.log('');

  // ---- findings, grouped by severity, local first then OSV ----
  const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const printGroup = (title, list) => {
    if (!list.length) return;
    console.log(`  ${rule()}`);
    console.log(`  ${C.bold(title)}`);
    console.log('');
    list.sort((a, b) => b.sevNum - a.sevNum || a.package.localeCompare(b.package));
    for (const f of list) {
      console.log(`  ${badge(f.severity)} ${C.bold(f.package + '@' + f.version)}  ${C.gray(f.store)}  ${C.cyan(f.code)}`);
      console.log(`     ${f.message}`);
      if (f.evidence) console.log(`     ${C.gray('→ ' + f.evidence)}`);
      if (f.note) console.log(`     ${C.gray('note: ' + f.note)}`);
      if (f.dir) console.log(`     ${C.gray(homeShort(f.dir))}`);
      console.log('');
    }
  };
  printGroup('From inspecting installed code', localFindings);
  printGroup('Known advisories (OSV.dev)', osvFindings);

  // ---- next steps ----
  console.log(`  ${rule()}`);
  console.log(`  ${C.bold('What to do')}`);
  if (counts.CRITICAL || counts.HIGH) {
    console.log(`  ${C.red('•')} Treat ${C.bold('CRITICAL / HIGH "installed code" findings')} as suspect: do not run install`);
    console.log(`    scripts, remove the package, clear the relevant cache, and rotate any npm /`);
    console.log(`    GitHub / cloud tokens this machine has held.`);
  }
  console.log(`  ${C.gray('•')} Check a flagged version against the registry: ${C.dim('npm view <pkg> versions')} ${C.gray('and look at')}`);
  console.log(`    ${C.gray('publish dates and provenance.')}`);
  if (osvFindings.length) console.log(`  ${C.gray('•')} OSV findings are the usual "known CVE in a dependency" set: ${C.dim('npm audit fix')} ${C.gray('/ bump.')}`);
  if (!has('--online')) console.log(`  ${C.gray('•')} Re-run with ${C.dim('--online')} ${C.gray('to add OSV.dev advisory matching by exact version.')}`);
  console.log('');

  process.exit(res.findings.some((f) => f.sevNum >= minSev) ? 1 : 0);
})();
