'use strict';
// Optional online cross-reference against OSV.dev — precise (package, version) matching,
// no API key. Used only when --online is passed.
const https = require('https');

function postJSON(host, pathname, body) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = https.request({ host, path: pathname, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('OSV request timed out')));
    req.end(data);
  });
}

// pkgs: array of {name, version}. Returns Map "name@version" -> [advisoryId,...]
async function queryOSV(pkgs) {
  const uniq = new Map();
  for (const p of pkgs) if (p.name && p.version) uniq.set(`${p.name}@${p.version}`, p);
  const entries = [...uniq.values()];
  const result = new Map();
  for (let i = 0; i < entries.length; i += 900) {
    const batch = entries.slice(i, i + 900);
    const queries = batch.map((p) => ({ package: { ecosystem: 'npm', name: p.name }, version: p.version }));
    let resp;
    try { resp = await postJSON('api.osv.dev', '/v1/querybatch', { queries }); }
    catch (e) { throw new Error(`OSV query failed: ${e.message}`); }
    (resp.results || []).forEach((r, idx) => {
      const ids = (r.vulns || []).map((v) => v.id);
      if (ids.length) result.set(`${batch[idx].name}@${batch[idx].version}`, ids);
    });
  }
  return result;
}

module.exports = { queryOSV };
