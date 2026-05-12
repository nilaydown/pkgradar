'use strict';
// Optional online cross-reference against OSV.dev. Precise (package, version) matching,
// no API key. Used only when --online is passed. Two phases:
//   1. /v1/querybatch  fast: which (name@version) have advisories at all
//   2. /v1/query       for just those packages, fetch full vuln objects so we can
//                      read each advisory's real severity instead of blanket-HIGH.
const https = require('https');

/**
 * Sends an HTTPS request and resolves with the parsed JSON response body.
 * Rejects on HTTP 4xx/5xx, JSON parse error, network error, or 15 s timeout.
 * @param {string} method - HTTP method (e.g. 'POST').
 * @param {string} host - Hostname (e.g. 'api.osv.dev').
 * @param {string} pathname - URL path (e.g. '/v1/querybatch').
 * @param {object|null} body - Request body, serialised as JSON, or null for no body.
 * @returns {Promise<object>} Parsed response JSON.
 */
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
/**
 * Approximates a severity bucket from a CVSS v3 vector string without full scoring math.
 * Examines Confidentiality/Integrity/Availability impact and network/privilege/UI metrics.
 * @param {string} vec - CVSS v3 vector string (e.g. 'CVSS:3.1/AV:N/AC:L/...').
 * @returns {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|null} Severity bucket, or null if unparseable.
 */
function bucketFromCvssVector(vec) {
  if (!vec || typeof vec !== 'string') return null;
  const metrics = Object.fromEntries(vec.split('/').map((p) => p.split(':')).filter((a) => a.length === 2));
  const impactHighCount = ['C', 'I', 'A'].filter((k) => metrics[k] === 'H').length;
  const network = metrics.AV === 'N';
  const noPriv = metrics.PR === 'N' || metrics.PR === undefined;
  const noUI = metrics.UI === 'N' || metrics.UI === undefined;
  if (impactHighCount >= 2 && network && noPriv && noUI) return 'CRITICAL';
  if (impactHighCount >= 1 && network && noPriv) return 'HIGH';
  if (impactHighCount >= 1) return 'MEDIUM';
  return 'LOW';
}

/**
 * Derives a severity label for a single OSV vulnerability object.
 * Tries database_specific.severity first, then numeric score, then CVSS vector bucketing.
 * Defaults to MEDIUM when the data is ambiguous to avoid both over- and under-claiming.
 * @param {object} v - OSV vulnerability object.
 * @returns {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'}
 */
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
      const bucket = bucketFromCvssVector(s.score);
      if (bucket) return bucket;
    }
  }
  return 'MEDIUM'; // unknown -> don't over- or under-claim
}

/**
 * Queries OSV.dev for known advisories for a list of npm packages.
 * Phase 1: batched querybatch to find which packages have any advisories.
 * Phase 2: parallel per-package queries (up to 8 concurrent) to fetch full details.
 * @param {{name:string, version:string}[]} pkgs - Packages to look up.
 * @returns {Promise<Map<string, {id:string, severity:string, summary:string}[]>>}
 *   Map from "name@version" to list of advisory summaries.
 */
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
      } catch { /* skip this package if its individual query fails */ }
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, queue.length) }, worker));
  return result;
}

module.exports = { queryOSV };
