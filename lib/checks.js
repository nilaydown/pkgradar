'use strict';
// Content-based heuristics. Each check inspects the bytes actually on disk for one
// package and returns zero or more findings: { sev, code, msg, evidence }.
const fs = require('fs');
const path = require('path');

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

// ---- Known Shai-Hulud / Mini-Shai-Hulud worm indicators (filenames & content markers) ----
const WORM_FILENAMES = [
  'setup_bun.sh', 'setup_bun.js', 'bun_environment.js',
  'shai-hulud-workflow.yml', 'shai-hulud.yaml', 'shai-hulud.yml',
  'processor.sh', 'migrate-repos.sh', 'cloud.json', 'contents.json', 'environment.json',
  'truffleSecrets.json', 'actionsSecrets.json',
];
// High-confidence exfiltration endpoints / payload constants seen in Shai-Hulud-family
// worms. A mention of the string "shai-hulud" alone is NOT here on purpose -- security
// tools (including this one) legitimately contain that word.
const WORM_HARD_MARKERS = [
  'webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
  'eyJ3ZWJob29rIjp7InVybCI6', // base64 of the worm's config preamble
  'hxxps://', // defanged URL only ever appears in payloads, never real code
];
// "Soft" markers: only meaningful when several co-occur in one file.
const WORM_SOFT_MARKERS = [
  'shai-hulud', 'Shai-Hulud', 'shaihulud',
  'truffleSecrets', 'actionsSecrets', 'NpmModuleListWebhook',
  'migrate-repos', 'setup_bun', 'bun_environment',
];
const SECRET_NAMES = [
  'NPM_TOKEN', 'NPM_CONFIG_TOKEN', 'NODE_AUTH_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'GHP_',
  'AWS_ACCESS_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'GCP_', 'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_', 'DIGITALOCEAN_TOKEN',
  'SLACK_TOKEN', 'STRIPE_', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
];
const NET_TOKENS = ['curl ', 'wget ', 'http://', 'https://', 'fetch(', 'net.connect', 'dns.lookup', 'request(', 'axios', 'XMLHttpRequest'];
const EXEC_TOKENS = ['child_process', 'execSync', 'spawnSync', 'exec(', 'spawn(', 'node -e', 'node --eval', 'eval(', 'Function(', 'vm.runInThisContext'];
const ENCODE_TOKENS = ['base64 -d', "from('", 'Buffer.from(', 'atob(', 'fromCharCode', 'unescape('];

/**
 * Reads a file safely, returning its text and metadata.
 * Truncates to `max` bytes if the file is larger.
 * @param {string} p - Absolute path to the file.
 * @param {number} [max=2_000_000] - Maximum bytes to read.
 * @returns {{ truncated: boolean, text: string, size: number } | null} File contents, or null on error.
 */
function readSafe(p, max = 2_000_000) {
  try {
    const st = fs.statSync(p);
    if (st.size > max) return { truncated: true, text: fs.readFileSync(p, 'utf8').slice(0, max), size: st.size };
    return { truncated: false, text: fs.readFileSync(p, 'utf8'), size: st.size };
  } catch { return null; }
}

/**
 * Checks whether a token string appears in a source string.
 * Iterates over a list of tokens and collects all matches.
 * @param {string[]} tokens - List of substrings to look for.
 * @param {string} src - Source string to search.
 * @param {Set<string>} hits - Set to accumulate matching tokens into.
 * @returns {void}
 */
function collectTokenHits(tokens, src, hits) {
  for (const t of tokens) if (src.includes(t)) hits.add(t);
}

// 1. Lifecycle install hooks (the #1 detonation vector)
/**
 * Checks package.json lifecycle hooks for suspicious behaviour.
 * Only inspects hooks that fire when a package is installed as a registry dependency.
 * @param {{ manifest: { scripts?: Record<string, string> } }} pkg - Package object.
 * @returns {{ sev: number, code: string, msg: string, evidence: string }[]} Array of findings.
 */
function checkLifecycleHooks(pkg) {
  const out = [];
  const s = (pkg.manifest && pkg.manifest.scripts) || {};
  // Only the hooks that fire when a package is installed *as a dependency from the
  // registry*. `prepare` is excluded: it only runs on local installs / git deps.
  const HOOKS = ['preinstall', 'install', 'postinstall'];
  for (const h of HOOKS) {
    const cmd = s[h];
    if (!cmd) continue;
    const c = cmd.trim();
    // common, well-known native-build / tooling hooks
    const benign = /^(node-gyp\b|prebuild-install\b|node-pre-gyp\b|cmake-js\b|napi\b|neon\b|install-from-cache\b|node-waf\b|husky\b|patch-package\b|opencollective\b|node-pre-gyp\b)/.test(c)
      || /^(node\s+)?(scripts\/)?install(\.js)?$/.test(c)
      || /^(ng-?ccc?|ngcc)\b/.test(c);
    const hits = new Set();
    collectTokenHits([...NET_TOKENS, ...EXEC_TOKENS, ...ENCODE_TOKENS], cmd, hits);
    collectTokenHits(SECRET_NAMES, cmd.toUpperCase(), hits);
    if (cmd.includes('.npmrc') || cmd.includes('/.ssh/') || cmd.includes('.aws/credentials')) hits.add('credential-file');
    const piped = /\b(curl|wget|fetch)\b[^|;&]*[|;&]+\s*(ba|z|d)?sh\b/.test(cmd) || /\|\s*node\b/.test(cmd);

    let sev;
    if (hits.size >= 3 || piped) sev = SEV.CRITICAL;
    else if (hits.size >= 1) sev = SEV.HIGH;
    else if (benign) sev = SEV.INFO;
    else sev = SEV.LOW; // an unrecognised install hook -- worth a glance, not an alarm
    out.push({ sev, code: 'lifecycle-hook', msg: `${h} script${hits.size ? ', touches: ' + [...hits].join(', ') : (benign ? ' (recognised build tool)' : ' (unrecognised command)')}`, evidence: `"${h}": ${cmd.slice(0, 240)}` });
  }
  return out;
}

// 2. Worm IOC files sitting inside the package
/**
 * Walks the package directory tree looking for known worm artifact filenames
 * and embedded GitHub Actions workflow files.
 * @param {{ dir: string }} pkg - Package object with a resolved directory path.
 * @returns {{ sev: number, code: string, msg: string, evidence: string }[]} Array of findings.
 */
function checkWormFiles(pkg) {
  if (!pkg.dir) return [];
  const out = [];
  const stack = [pkg.dir];
  let budget = 4000;
  while (stack.length && budget-- > 0) {
    const d = stack.pop();
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (e.name === 'node_modules') continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) { stack.push(full); continue; }
      const low = e.name.toLowerCase();
      if (WORM_FILENAMES.some((w) => low === w.toLowerCase())) {
        out.push({ sev: SEV.CRITICAL, code: 'worm-ioc-file', msg: `known worm artifact file: ${e.name}`, evidence: path.relative(pkg.dir, full) });
      }
      if (/(^|[\\/])\.github[\\/]workflows([\\/]|$)/.test(d) && /\.ya?ml$/i.test(low)) {
        // Lots of legit packages publish their whole repo, .github included, and plenty
        // of normal CI workflows pipe an installer into a shell. On its own this is not a
        // signal, so it is INFO only. A genuinely malicious workflow file with a known
        // name is already caught by worm-ioc-file.
        out.push({ sev: SEV.INFO, code: 'embedded-gh-workflow', msg: `package ships a GitHub Actions workflow (${e.name})`, evidence: path.relative(pkg.dir, full) });
      }
    }
  }
  return out;
}

// 3. Obfuscated / packed JS payload heuristics on the package's own JS
/**
 * Scans JS files in the package for obfuscation patterns, worm IOC strings,
 * and suspicious combinations of credential access and network calls.
 * Applies per-file and per-package byte budgets to bound scan time.
 * @param {{ dir: string }} pkg - Package object with a resolved directory path.
 * @returns {{ sev: number, code: string, msg: string, evidence: string }[]} Array of findings.
 */
function checkObfuscation(pkg) {
  if (!pkg.dir) return [];
  const out = [];
  // Collect candidate JS files, then scan them under a strict per-package budget so a
  // package full of huge vendored bundles (typescript.js, lighthouse bundles, ...) can't
  // make a scan run for minutes.
  const files = [];
  const stack = [pkg.dir];
  let dirBudget = 3000;
  while (stack.length && dirBudget-- > 0 && files.length < 200) {
    const d = stack.pop();
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (e.name === 'node_modules' || e.name === 'test' || e.name === 'tests' || e.name === '__tests__' || e.name === 'fixtures') continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) { stack.push(full); continue; }
      if (/\.(c|m)?js$/.test(e.name)) { files.push(full); if (files.length >= 200) break; }
    }
  }
  const PER_FILE = 1_500_000;        // scan at most the first 1.5MB of any one file
  const TAIL = 96 * 1024;            // ...plus the last 96KB (payloads are often appended)
  let pkgByteBudget = 24_000_000;    // ...and at most ~24MB across the whole package
  for (const f of files) {
    if (pkgByteBudget <= 0) break;
    let st; try { st = fs.statSync(f); } catch { continue; }
    let t, truncated = false;
    if (st.size > PER_FILE) {
      truncated = true;
      // big file: scan head + tail only
      let head = '', tail = '';
      try {
        const fd = fs.openSync(f, 'r');
        const hb = Buffer.alloc(Math.min(PER_FILE, st.size)); fs.readSync(fd, hb, 0, hb.length, 0); head = hb.toString('utf8');
        const tb = Buffer.alloc(Math.min(TAIL, st.size)); fs.readSync(fd, tb, 0, tb.length, st.size - tb.length); tail = tb.toString('utf8');
        fs.closeSync(fd);
      } catch { continue; }
      t = head + '\n' + tail;
      pkgByteBudget -= (head.length + tail.length);
    } else {
      const r = readSafe(f, PER_FILE);
      if (!r) continue;
      t = r.text;
      pkgByteBudget -= st.size;
    }
    const strong = [];   // each strong reason alone is reportable
    const weak = [];     // weak reasons only matter in combination
    let critical = false;

    // --- "executable payload" context: dynamic code execution over decoded data, or
    //     heavy identifier mangling. Worm IOC strings are only damning when they sit
    //     alongside one of these; on their own they also appear in scanners, advisories,
    //     and writeups (this file included). ---
    const hexIds = (t.match(/_0x[a-f0-9]{4,6}\b/g) || []).length;
    const evalOverDecoded = /(eval|new Function|Function\()\s*\(?\s*(atob|Buffer\.from\s*\([^)]*base64|unescape|decodeURIComponent)/.test(t);
    const procFromDecoded = /\bchild_process\b[\s\S]{0,400}\b(atob|Buffer\.from\s*\([^)]*base64)/.test(t);
    const execContext = evalOverDecoded || procFromDecoded || hexIds > 80;
    if (evalOverDecoded) strong.push('constructs & executes decoded payload (eval/Function over atob/Buffer.from)');
    if (procFromDecoded) strong.push('spawns a process from decoded data');
    if (hexIds > 80) strong.push(`${hexIds} _0x… mangled identifiers (javascript-obfuscator)`);
    else if (hexIds > 20) weak.push(`${hexIds} _0x… identifiers`);

    // --- worm IOC strings ---
    const hardHits = WORM_HARD_MARKERS.filter((m) => t.includes(m));
    if (hardHits.length) {
      if (execContext) { strong.push(`worm IOC string(s) in an executing payload: ${hardHits.join(', ')}`); critical = true; }
      else weak.push(`contains known IOC string(s): ${hardHits.join(', ')} (also found in security tooling / advisories / writeups)`);
    }
    const softHits = WORM_SOFT_MARKERS.filter((m) => t.includes(m));
    if (softHits.length >= 3 && execContext) strong.push(`co-occurring worm terms with an executable payload: ${softHits.slice(0, 6).join(', ')}`);
    else if (softHits.length) weak.push(`worm term(s): ${softHits.slice(0, 6).join(', ')}`);

    // --- weak structural signals (modern bundlers do these constantly) ---
    const longest = t.split('\n').reduce((m, l) => Math.max(m, l.length), 0);
    const minified = longest > 20000;
    if (minified && !/sourceMappingURL/.test(t.slice(-400))) weak.push(`minified (${longest.toLocaleString()}-char line, no sourcemap)`);
    const b64big = (t.match(/['"`][A-Za-z0-9+/]{1200,}={0,2}['"`]/g) || []).length;
    if (b64big) weak.push(`${b64big} large base64 literal(s)`);
    const readsSecret = SECRET_NAMES.some((n) => t.includes(n)) || /['"`][^'"`]*\.npmrc/.test(t) || t.includes('/.ssh/id_') || t.includes('.aws/credentials') || t.includes('.config/gh/hosts');
    const doesNet = /(fetch\s*\(|https?\.(get|request)\s*\(|new XMLHttpRequest|net\.connect|dgram\.)/.test(t)
      && /https?:\/\/(?!(registry\.npmjs\.org|nodejs\.org|raw\.githubusercontent\.com|api\.github\.com))[\w.-]+/.test(t);
    if (readsSecret) weak.push('references credential file/env names');
    if (doesNet) weak.push('makes an outbound network call to a non-package-registry host');

    // --- decide ---
    const reasons = [...strong, ...weak];
    let sev = null;
    if (critical) sev = SEV.CRITICAL;
    else if (strong.length) sev = SEV.HIGH;
    else if (readsSecret && doesNet && (minified || b64big || hexIds > 20)) sev = SEV.HIGH; // creds + net + obfuscation
    else if (weak.length >= 3) sev = SEV.MEDIUM;
    // (minified-alone, base64-alone, single weak signal => not reported: too noisy)
    if (sev != null) {
      out.push({ sev, code: 'suspicious-js', msg: reasons.join('; '), evidence: path.relative(pkg.dir, f) + (truncated ? ` (${(st.size / 1e6).toFixed(1)}MB file, scanned head ${(PER_FILE / 1e6).toFixed(1)}MB + tail ${(TAIL / 1024) | 0}KB)` : '') });
    }
  }
  return out;
}

// 4. Manifest oddities (cheap, offline)
/**
 * Inspects package.json for structural anomalies that warrant attention.
 * Currently checks bin entries that point outside the package or to shell scripts.
 * @param {{ manifest: object, name?: string }} pkg - Package object.
 * @returns {{ sev: number, code: string, msg: string, evidence: string }[]} Array of findings.
 */
function checkManifestAnomalies(pkg) {
  const out = [];
  const m = pkg.manifest || {};
  // bin pointing outside the package, or to a shell script
  if (m.bin) {
    const bins = typeof m.bin === 'string' ? { [m.name]: m.bin } : m.bin;
    for (const [k, v] of Object.entries(bins)) {
      if (typeof v === 'string' && (v.includes('..') || /\.(sh|bat|cmd|ps1)$/.test(v))) {
        out.push({ sev: SEV.MEDIUM, code: 'odd-bin', msg: `bin "${k}" -> ${v}`, evidence: 'package.json#bin' });
      }
    }
  }
  return out;
}

let SELF = null;
try { SELF = require('../package.json').name; } catch { /* ignore */ }

/**
 * Runs all checks against a single package and returns the combined findings.
 * Skips pkgradar's own package to avoid false positives from IOC strings in this file.
 * @param {{ name?: string, version?: string, dir?: string, store?: string, manifest?: object }} pkg - Package to inspect.
 * @returns {{ sev: number, code: string, msg: string, evidence: string }[]} Combined findings from all checks.
 */
function runAll(pkg) {
  // Don't scan our own package: this file necessarily contains the IOC strings it
  // searches for, so scanning a cached copy of pkgradar would flag pkgradar.
  if (SELF && pkg && pkg.manifest && pkg.manifest.name === SELF) return [];
  const findings = [];
  for (const fn of [checkLifecycleHooks, checkWormFiles, checkManifestAnomalies, checkObfuscation]) {
    try { findings.push(...fn(pkg)); } catch (e) { /* ignore per-check failure */ }
  }
  return findings;
}

module.exports = { runAll, SEV };
