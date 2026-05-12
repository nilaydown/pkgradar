'use strict';
// Optional online cross-reference against OSV.dev — precise (package, version) matching,
// no API key. Used only when --online is passed. Two phases:
//   1. /v1/querybatch  — fast: which (name@version) have advisories at all
//   2. /v1/query       — for just those packages, fetch full vuln objects so we can
//                        read each advisory's real severity instead of blanket-HIGH.
const https = require('https');

function request(method, host, pathname, body) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = data ? { 'content-type': 'application/json', 'content-length': data.length } : {};
    const req = https.request({ host, path: pathname, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) return reject(new Error(`OSV ${res.statusCode} ${pathname}`));
        try { resolve(JSON.parse(txt)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('OSV request timed out')));
    if (data) req.end(data); else req.end();
  });
}

// CVSS v3 vector -> approximate numeric base score is non-trivial; instead bucket by the
// vector's impact + exploitability shape. Good enough to pick LOW/MEDIUM/HIGH/CRITICAL.
function bucketFromCvssVector(vec) {
  if (!vec || typeof vec !== 'string') return null;
  const m = Object.fromEntries(vec.split('/').map((p) => p.split(':')).filter((a) => a.length === 2));
  const impactHigh = ['C', 'I', 'A'].filter((k) => m[k] === 'H').length;
  const network = m.AV === 'N';
  const noPriv = m.PR === 'N' || m.PR === undefined;
  const noUI = m.UI === 'N' || m.UI === undefined;
  if (impactHigh >= 2 && network && noPriv && noUI) return 'CRITICAL';
  if (impactHigh >= 1 && network && noPriv) return 'HIGH';
  if (impactHigh >= 1) return 'MEDIUM';
  return 'LOW';
}

function severityOfVuln(v) {
  const ds = v.database_specific && (v.database_specific.severity || v.database_specific.cvss);
  if (typeof ds === 'string') {
    const s = ds.toUpperCase();
    if (s.startsWith('CRIT')) return 'CRITICAL';
    if (s === 'HIGH') return 'HIGH';
    if (s === 'MODERATE' || s === 'MEDIUM') return 'MEDIUM';
    if (s === 'LOW') return 'LOW';
  }
  for (const s of v.severity || []) {
    if (typeof s.score === 'string') {
      const num = parseFloat(s.score);
      if (!Number.isNaN(num) && /^\d/.test(s.score.trim())) {
        if (num >= 9) return 'CRITICAL';
        if (num >= 7) return 'HIGH';
        if (num >= 4) return 'MEDIUM';
        return 'LOW';
      }
      const b = bucketFromCvssVector(s.score);
      if (b) return b;
    }
  }
  return 'MEDIUM'; // unknown -> don't over- or under-claim
}

// pkgs: [{name, version}]. Returns Map "name@version" -> [{ id, severity, summary }]
async function queryOSV(pkgs) {
  const uniq = new Map();
  for (const p of pkgs) if (p.name && p.version) uniq.set(`${p.name}@${p.version}`, p);
  const entries = [...uniq.values()];

  // phase 1: which entries have anything
  const affected = [];
  for (let i = 0; i < entries.length; i += 900) {
    const batch = entries.slice(i, i + 900);
    const resp = await request('POST', 'api.osv.dev', '/v1/querybatch', {
      queries: batch.map((p) => ({ package: { ecosystem: 'npm', name: p.name }, version: p.version })),
    });
    (resp.results || []).forEach((r, idx) => { if ((r.vulns || []).length) affected.push(batch[idx]); });
  }

  // phase 2: full details for affected packages only (bounded concurrency)
  const result = new Map();
  const queue = affected.slice();
  const worker = async () => {
    for (let p; (p = queue.shift()); ) {
      try {
        const resp = await request('POST', 'api.osv.dev', '/v1/query', { package: { ecosystem: 'npm', name: p.name }, version: p.version });
        const vulns = (resp.vulns || []).map((v) => ({ id: v.id, severity: severityOfVuln(v), summary: v.summary || '' }));
        if (vulns.length) result.set(`${p.name}@${p.version}`, vulns);
      } catch { /* skip this one */ }
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, queue.length) }, worker));
  return result;
}

module.exports = { queryOSV };
