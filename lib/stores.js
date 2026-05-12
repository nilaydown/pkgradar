'use strict';
// Discover every place a JS package manager leaves extracted package code, and
// iterate the packages found there.
const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');

/**
 * Returns true if the path exists and is accessible, false otherwise.
 * @param {string} p - Filesystem path to test.
 * @returns {boolean}
 */
const exists = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };

/**
 * Returns directory entries for a path, or an empty array on any error.
 * @param {string} p - Directory path.
 * @returns {fs.Dirent[]}
 */
const readdir = (p) => { try { return fs.readdirSync(p, { withFileTypes: true }); } catch { return []; } };

/**
 * Runs a shell command and returns its trimmed stdout, or '' on failure.
 * @param {string} cmd - Shell command to execute.
 * @returns {string}
 */
const sh = (cmd) => { try { return cp.execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { return ''; } };

/**
 * Finds all package-manager store roots relevant to the given working directory.
 * Checks project-local node_modules, npm/pnpm/yarn/bun global and cache locations.
 * @param {string} cwd - Project root directory.
 * @returns {{kind:string, root:string, note:string}[]} List of discovered stores.
 */
function discoverStores(cwd) {
  const home = os.homedir();
  const out = [];
  const add = (kind, root, note) => { if (exists(root)) out.push({ kind, root, note }); };

  add('project', path.join(cwd, 'node_modules'), 'current project node_modules');
  add('pnpm-project', path.join(cwd, 'node_modules', '.pnpm'), 'pnpm in-project store');
  const npmGlobal = sh('npm root -g'); if (npmGlobal) add('npm-global', npmGlobal, 'npm global packages');
  add('npx-cache', path.join(home, '.npm', '_npx'), 'npx ephemeral installs');
  add('bun-cache', path.join(home, '.bun', 'install', 'cache'), 'bun global cache');
  add('bun-cache', path.join(home, '.cache', 'bun', 'install', 'cache'), 'bun cache (xdg)');
  for (const p of [
    path.join(home, 'Library', 'pnpm', 'store'),
    path.join(home, '.local', 'share', 'pnpm', 'store'),
    process.env.PNPM_HOME && path.join(process.env.PNPM_HOME, 'store'),
  ].filter(Boolean)) add('pnpm-store', p, 'pnpm global content store (count only)');
  const yarnCache = sh('yarn cache dir'); if (yarnCache) add('yarn-cache', yarnCache, 'yarn v1 cache');
  add('yarn-berry', path.join(cwd, '.yarn', 'cache'), 'yarn berry zip cache (names only)');
  return out;
}

/**
 * Reads and parses the package.json inside a directory.
 * @param {string} dir - Directory that should contain package.json.
 * @returns {object|null} Parsed manifest, or null if missing or unparseable.
 */
function readManifest(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { return null; }
}

/**
 * Builds a pkg object from a directory and a store, or null if no valid manifest.
 * @param {string} dir - Extracted package directory.
 * @param {{kind:string, root:string, note:string}} store - Parent store object.
 * @returns {{name:string, version:string, dir:string, store:object, manifest:object}|null}
 */
function pkgFromDir(dir, store) {
  const m = readManifest(dir);
  if (!m) return null;
  return { name: m.name || path.basename(dir), version: m.version || '', dir, store, manifest: m };
}

/**
 * Recursively yields pkg objects from a node_modules tree, handling scoped packages.
 * @param {string} nmDir - node_modules directory to walk.
 * @param {{kind:string, root:string, note:string}} store - Owning store.
 * @param {number} maxDepth - Maximum recursion depth for nested node_modules.
 * @param {number} [depth=0] - Current recursion depth.
 * @yields {{name:string, version:string, dir:string, store:object, manifest:object}}
 */
function* walkTree(nmDir, store, maxDepth, depth = 0) {
  if (depth > maxDepth || !exists(nmDir)) return;
  for (const ent of readdir(nmDir)) {
    if (ent.name.startsWith('.')) continue;
    const full = path.join(nmDir, ent.name);
    if (ent.name.startsWith('@')) {
      // scoped packages: one more level for "@scope/pkg-name"
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

/**
 * Yields every pkg found in the given store, adapting traversal to the store kind.
 * Handles bun-cache, yarn-berry (zip names only), pnpm-store (skipped, content-addressed),
 * npx-cache, pnpm-project, and conventional node_modules trees.
 * @param {{kind:string, root:string, note:string}} store - Store to enumerate.
 * @param {{maxDepth?:number}} [opts={}] - Options; maxDepth limits node_modules nesting.
 * @yields {{name:string, version:string, dir:string|null, store:object, manifest?:object}}
 */
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
      // zip archives: parse name and version from filename, no extracted tree to walk
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
      // each subdirectory is a separate install hash; node_modules lives one level in
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
