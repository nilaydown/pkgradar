const assert = require('assert');
const { scan, SEV } = require('../lib/scan');
const path = require('path');
(async () => {
  const r = await scan({ cwd: path.join(__dirname, 'fixtures'), stores: ['project'], minSev: SEV.INFO });
  const evil = r.findings.filter(f => f.package === 'evil-pkg');
  const safe = r.findings.filter(f => f.package === 'safe-pkg');
  assert(evil.some(f => f.severity === 'CRITICAL' && f.code === 'lifecycle-hook'), 'expected CRITICAL lifecycle-hook on evil-pkg');
  assert(evil.some(f => f.code === 'suspicious-js' && (f.severity === 'HIGH' || f.severity === 'CRITICAL')), 'expected suspicious-js on evil-pkg');
  assert(safe.length === 0, 'safe-pkg should be clean, got: ' + JSON.stringify(safe));
  console.log('smoke ok —', evil.length, 'findings on evil-pkg, 0 on safe-pkg');
})().catch(e => { console.error('SMOKE FAILED:', e.message); process.exit(1); });
