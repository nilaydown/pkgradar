'use strict';
// Discover every place a JS package manager leaves extracted package code, and
// iterate the packages found there.
const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');

const exists = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };
const readdir = (p) => { try { return fs.readdirSync(p, { withFileTypes: true }); } catch { return []; } };
const sh = (cmd) => { try { return cp.execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { return ''; } };

function discoverStores(cwd) {
  const home = os.homedir();
  const out = [];
  const add = (kind, root, note) => { if (exists(root)) out.push({ kind, root, note }); };

  add('project', path.join(cwd, 'node_modules'), 'current project node_modules');
  add('pnpm-project', path.join(cwd, 'node_modules', '.pnpm'), 'pnpm in-project store');
  const g = sh('npm root -g'); if (g) add('npm-global', g, 'npm global packages');
  add('npx-cache', path.join(home, '.npm', '_npx'), 'npx ephemeral installs');
  add('bun-cache', path.join(home, '.bun', 'install', 'cache'), 'bun global cache');
  add('bun-cache', path.join(home, '.cache', 'bun', 'install', 'cache'), 'bun cache (xdg)');
  for (const p of [
    path.join(home, 'Library', 'pnpm', 'store'),
    path.join(home, '.local', 'share', 'pnpm', 'store'),
    process.env.PNPM_HOME && path.join(process.env.PNPM_HOME, 'store'),
  ].filter(Boolean)) add('pnpm-store', p, 'pnpm global content store (count only)');
  const yc = sh('yarn cache dir'); if (yc) add('yarn-cache', yc, 'yarn v1 cache');
  add('yarn-berry', path.join(cwd, '.yarn', 'cache'), 'yarn berry zip cache (names only)');
  return out;
}

function readManifest(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { return null; }
}
function pkgFromDir(dir, store) {
  const m = readManifest(dir);
  if (!m) return null;
  return { name: m.name || path.basename(dir), version: m.version || '', dir, store, manifest: m };
}

function* walkTree(nmDir, store, maxDepth, depth = 0) {
  if (depth > maxDepth || !exists(nmDir)) return;
  for (const ent of readdir(nmDir)) {
    if (ent.name.startsWith('.')) continue;
    const full = path.join(nmDir, ent.name);
    if (ent.name.startsWith('@')) {
      for (const sub of readdir(full)) {
        const d = path.join(full, sub.name);
        const p = pkgFromDir(d, store); if (p) yield p;
        yield* walkTree(path.join(d, 'node_modules'), store, maxDepth, depth + 1);
      }
    } else {
      const p = pkgFromDir(full, store); if (p) yield p;
      yield* walkTree(path.join(full, 'node_modules'), store, maxDepth, depth + 1);
    }
  }
}

function* packagesInStore(store, opts = {}) {
  const maxDepth = opts.maxDepth || 12;
  switch (store.kind) {
    case 'bun-cache': {
      for (const ent of readdir(store.root)) {
        if (!ent.isDirectory() || ent.name === '.bin' || ent.name === '.cache') continue;
        const full = path.join(store.root, ent.name);
        if (ent.name.startsWith('@')) {
          for (const sub of readdir(full)) if (sub.isDirectory()) { const p = pkgFromDir(path.join(full, sub.name), store); if (p) yield p; }
        } else { const p = pkgFromDir(full, store); if (p) yield p; }
      }
      return;
    }
    case 'yarn-berry': {
      for (const ent of readdir(store.root)) {
        if (ent.isFile() && ent.name.endsWith('.zip')) {
          const m = ent.name.match(/^(.*)-npm-(.+)-[a-f0-9]{8,}\.zip$/);
          if (m) yield { name: m[1].replace(/^@([^-]+)-/, '@$1/'), version: m[2], dir: null, store, archiveOnly: true };
        }
      }
      return;
    }
    case 'pnpm-store': return; // content-addressed blobs; not extracted trees
    case 'npx-cache':
    case 'pnpm-project': {
      for (const ent of readdir(store.root)) {
        if (ent.isDirectory()) yield* walkTree(path.join(store.root, ent.name, 'node_modules'), store, maxDepth);
      }
      return;
    }
    default: // project, npm-global, yarn-cache
      yield* walkTree(store.root, store, maxDepth);
  }
}

module.exports = { discoverStores, packagesInStore, exists, readdir };
