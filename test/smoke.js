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

// extra coverage: worm-ioc-file + embedded-gh-workflow
(async () => {
  const { scan, SEV } = require('../lib/scan');
  const path = require('path');
  const assert = require('assert');
  const r = await scan({ cwd: path.join(__dirname, 'fixtures'), stores: ['project'], minSev: SEV.INFO });
  const w = r.findings.filter(f => f.package === 'wormy-pkg');
  assert(w.some(f => f.code === 'worm-ioc-file' && f.severity === 'CRITICAL'), 'expected worm-ioc-file CRITICAL on wormy-pkg, got ' + JSON.stringify(w));
  assert(w.some(f => f.code === 'embedded-gh-workflow'), 'expected embedded-gh-workflow on wormy-pkg');
  console.log('worm-fixture ok —', w.map(f=>f.code+':'+f.severity).join(', '));
})().catch(e => { console.error('SMOKE FAILED:', e.message); process.exit(1); });
