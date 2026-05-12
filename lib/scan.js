'use strict';
const { discoverStores, packagesInStore } = require('./stores');
const { runAll, SEV } = require('./checks');
const { queryOSV } = require('./osv');

const SEV_NAME = { 4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW', 0: 'INFO' };

let ALLOW_EXACT = new Set(), ALLOW_SCOPES = [];
try {
  const a = require('../data/allowlist.json');
  for (const n of a.names || []) { if (n.endsWith('/*')) ALLOW_SCOPES.push(n.slice(0, -1)); else ALLOW_EXACT.add(n); }
} catch { /* allowlist optional */ }
function isAllowlisted(name) {
  if (ALLOW_EXACT.has(name)) return true;
  return ALLOW_SCOPES.some((s) => name.startsWith(s));
}

async function scan(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const stores = discoverStores(cwd);
  const kindFilter = Array.isArray(opts.stores) && opts.stores.length ? new Set(opts.stores) : null;
  const storeStats = [];
  const seen = new Map();        // "name@version@dir" -> pkg (dedupe)
  const findings = [];
  const allPkgList = [];

  for (const store of stores) {
    if (kindFilter && !kindFilter.has(store.kind)) continue;
    let count = 0;
    for (const pkg of packagesInStore(store, { maxDepth: opts.maxDepth })) {
      count++;
      const key = `${pkg.name}@${pkg.version}@${pkg.dir || store.root}`;
      if (seen.has(key)) continue;
      seen.set(key, pkg);
      allPkgList.push({ name: pkg.name, version: pkg.version });
      if (pkg.archiveOnly) continue; // can't inspect bytes inside a yarn-berry zip
      const allow = !opts.noAllowlist && isAllowlisted(pkg.name);
      for (const f of runAll(pkg)) {
        let sev = f.sev, note;
        // allowlist downgrades benign-looking findings — but NEVER suppresses a hard worm
        // IOC (worm-ioc-file / CRITICAL suspicious-js), since that's the compromise case.
        if (allow && sev < SEV.CRITICAL) { sev = SEV.INFO; note = 'allowlisted package, heuristic likely benign; review only if context warrants'; }
        if (sev < (opts.minSev ?? SEV.MEDIUM)) continue;
        findings.push({
          severity: SEV_NAME[sev], sevNum: sev, code: f.code, message: f.msg, evidence: f.evidence,
          package: pkg.name, version: pkg.version, store: store.kind, dir: pkg.dir, note,
        });
      }
    }
    storeStats.push({ kind: store.kind, root: store.root, note: store.note, packages: count });
  }

  let osv = null;
  if (opts.online) {
    try {
      const map = await queryOSV(allPkgList);
      osv = [];
      const SEV_RANK = { CRITICAL: SEV.CRITICAL, HIGH: SEV.HIGH, MEDIUM: SEV.MEDIUM, LOW: SEV.LOW };
      for (const [nv, vulns] of map) {
        const [name, version] = splitNV(nv);
        const top = vulns.reduce((m, v) => Math.max(m, SEV_RANK[v.severity] ?? SEV.MEDIUM), SEV.LOW);
        const bySev = {};
        for (const v of vulns) bySev[v.severity] = (bySev[v.severity] || 0) + 1;
        const breakdown = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].filter((k) => bySev[k]).map((k) => `${bySev[k]} ${k.toLowerCase()}`).join(', ');
        const ids = vulns.map((v) => v.id);
        findings.push({
          severity: SEV_NAME[top], sevNum: top, code: 'osv-advisory',
          message: `${vulns.length} OSV ${vulns.length === 1 ? 'advisory' : 'advisories'} (${breakdown}): ${ids.slice(0, 8).join(', ')}${ids.length > 8 ? ', …' : ''}`,
          evidence: 'https://osv.dev/' + ids.find((id) => vulns.find((v) => v.id === id && SEV_RANK[v.severity] === top)),
          package: name, version, store: 'registry', dir: null,
        });
        osv.push({ package: name, version, advisories: vulns });
      }
    } catch (e) {
      osv = { error: e.message };
    }
  }

  findings.sort((a, b) => b.sevNum - a.sevNum || a.package.localeCompare(b.package));
  const totalPackages = [...new Set(allPkgList.map((p) => `${p.name}@${p.version}`))].length;
  return { cwd, stores: storeStats, totalPackages, totalScanned: seen.size, findings, osv };
}

function splitNV(nv) { const i = nv.lastIndexOf('@'); return [nv.slice(0, i), nv.slice(i + 1)]; }

module.exports = { scan, SEV };
