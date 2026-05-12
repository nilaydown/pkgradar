#!/usr/bin/env node
'use strict';
const { scan, SEV } = require('../lib/scan');

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? args[i + 1] : d; };

if (has('-h') || has('--help')) {
  console.log(`pkgradar — content-based supply-chain scanner for npm/pnpm/yarn/bun

Looks at the bytes you actually installed (install hooks, obfuscated payloads,
known worm artifacts) instead of just matching package names against a list.

USAGE
  npx pkgradar [options]

OPTIONS
  --online            also cross-reference OSV.dev for known advisories (network)
  --json              machine-readable output
  --min-sev LEVEL     report findings >= LEVEL (critical|high|medium|low|info)  [default: medium]
  --stores LIST       comma list to limit which stores are scanned
                      (project,pnpm-project,npm-global,npx-cache,bun-cache,yarn-cache,yarn-berry)
  --no-allowlist      don't downgrade findings on well-known packages (data/allowlist.json)
  --max-depth N       max node_modules nesting depth                            [default: 12]
  --cwd DIR           project directory to scan                                 [default: .]
  -h, --help

EXIT CODES
  0  clean      1  findings at or above --min-sev      2  scanner error
`);
  process.exit(0);
}

const SEV_FROM_NAME = { critical: SEV.CRITICAL, high: SEV.HIGH, medium: SEV.MEDIUM, low: SEV.LOW, info: SEV.INFO };
const minSev = SEV_FROM_NAME[(val('--min-sev', 'medium') || '').toLowerCase()] ?? SEV.MEDIUM;

const C = process.stdout.isTTY ? {
  red: (s) => `\x1b[31m${s}\x1b[0m`, ylw: (s) => `\x1b[33m${s}\x1b[0m`, grn: (s) => `\x1b[32m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m`, cyan: (s) => `\x1b[36m${s}\x1b[0m`,
} : new Proxy({}, { get: () => (s) => s });

const SEV_COLOR = { CRITICAL: C.red, HIGH: C.red, MEDIUM: C.ylw, LOW: C.dim, INFO: C.dim };

(async () => {
  let res;
  try {
    res = await scan({
      cwd: val('--cwd', process.cwd()),
      online: has('--online'),
      minSev,
      maxDepth: parseInt(val('--max-depth', '12'), 10) || 12,
      stores: (val('--stores', '') || '').split(',').map((s) => s.trim()).filter(Boolean),
      noAllowlist: has('--no-allowlist'),
    });
  } catch (e) {
    console.error(C.red('pkgradar: ') + (e && e.stack || e));
    process.exit(2);
  }

  if (has('--json')) {
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.findings.some((f) => f.sevNum >= minSev) ? 1 : 0);
  }

  console.log(C.bold('\npkgradar') + C.dim(`  —  scanning ${res.cwd}`));
  console.log(C.dim('stores scanned:'));
  for (const s of res.stores) console.log(C.dim(`  • ${s.kind.padEnd(14)} ${String(s.packages).padStart(5)} pkgs  ${s.root}`));
  console.log(C.dim(`  ${res.totalPackages} unique package@version pairs, ${res.totalScanned} package locations inspected\n`));

  if (res.osv && res.osv.error) console.log(C.ylw(`  OSV lookup skipped: ${res.osv.error}\n`));

  if (!res.findings.length) {
    console.log(C.grn('✓ no findings at or above ' + Object.keys(SEV_FROM_NAME).find((k) => SEV_FROM_NAME[k] === minSev)));
    console.log(C.dim("  (this checks installed bytes; it can't prove a package is safe — just that nothing tripped the heuristics)\n"));
    process.exit(0);
  }

  const counts = {};
  for (const f of res.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const summary = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].filter((k) => counts[k]).map((k) => SEV_COLOR[k](`${counts[k]} ${k}`)).join('  ');
  console.log(C.bold(`Findings: `) + summary + '\n');

  for (const f of res.findings) {
    const tag = SEV_COLOR[f.severity](`[${f.severity}]`);
    console.log(`${tag} ${C.bold(f.package + '@' + f.version)} ${C.dim('(' + f.store + ')')}  ${C.cyan(f.code)}`);
    console.log(`   ${f.message}`);
    if (f.evidence) console.log(C.dim(`   ↳ ${f.evidence}`));
    if (f.note) console.log(C.dim(`   note: ${f.note}`));
    if (f.dir) console.log(C.dim(`   ${f.dir}`));
    console.log();
  }

  console.log(C.dim('Next steps:'));
  console.log(C.dim('  • CRITICAL/HIGH: do not run install scripts; remove the package, clear caches, and rotate any npm/GitHub/cloud tokens this machine has held.'));
  console.log(C.dim('  • Verify suspicious versions against the registry: `npm view <pkg> versions` and check publish dates / provenance.'));
  console.log(C.dim('  • Re-run with --online to cross-check OSV.dev advisories.\n'));

  process.exit(res.findings.some((f) => f.sevNum >= minSev) ? 1 : 0);
})();
