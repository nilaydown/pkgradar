# pkgradar

**A supply-chain scanner that reads the bytes you actually installed — not just the package names.**

Most "supply-chain" CLIs work by downloading an advisory list and checking whether any package *name* in your project appears on it. That produces scary "potential exposure" verdicts for packages like `zod-to-json-schema` or `lightningcss` that are simply *named* in an advisory's "affected ecosystem" — even when your specific, untouched version is fine. It also misses anything not yet on a list.

`pkgradar` does the opposite: it walks every place your machine extracts package code (npm, pnpm, yarn classic/berry, bun, the global root, and the `npx` scratch cache), opens the files, and looks for the things malware actually does:

- **Install hooks that detonate** — `preinstall` / `install` / `postinstall` scripts, scored by whether they spawn processes, pipe `curl | bash`, read `~/.npmrc` / `~/.ssh` / `~/.aws/credentials`, or touch `NPM_TOKEN` / `GITHUB_TOKEN` / cloud creds. (`prepare` is ignored — it doesn't run for registry deps.)
- **Known worm artifacts** — `setup_bun.sh`, `bun_environment.js`, `migrate-repos.sh`, embedded `.github/workflows/*`, hard-coded Shai-Hulud exfil endpoints, and the rest of the Shai-Hulud / "Mini Shai-Hulud" IOC set.
- **Obfuscated / packed payloads** — `javascript-obfuscator` `_0x…` fingerprints, `eval`/`new Function` over `atob`/`Buffer.from(base64)`, `child_process` fed from decoded data, giant base64 literals — with the noisy "this file is just minified" signals deliberately demoted so a normal bundled CLI doesn't drown the report.
- **Manifest oddities** — `bin` entries pointing outside the package or at shell scripts.
- **(optional) precise advisory matching** — `--online` cross-references [OSV.dev](https://osv.dev) by exact `(name, version)`, so you get real CVE/GHSA IDs (not name collisions) — and each advisory is reported at *its own* severity (from the GHSA/CVSS rating), not a blanket level, so a moderate ReDoS in a dev tool doesn't shout as loud as an RCE.

A curated allowlist (`data/allowlist.json`) downgrades benign-but-trippy findings on famous packages (`vercel`, `corepack`, `core-js`, `esbuild`, …) to `INFO` — but it **never** suppresses a hard worm IOC, because "trusted package suddenly ships a worm" is exactly the attack.

## Usage

```bash
npx pkgradar                 # scan the current project + all caches on this machine
npx pkgradar --online        # also cross-check OSV.dev advisories
npx pkgradar --min-sev high  # only show HIGH and CRITICAL
npx pkgradar --json          # machine-readable, for CI
```

Exit code: `0` clean · `1` findings at/above `--min-sev` · `2` scanner error. Drop it in CI with `npx pkgradar --min-sev high`.

```
pkgradar  —  scanning /repo
stores scanned:
  • project         1390 pkgs  /repo/node_modules
  • npm-global        390 pkgs  /usr/local/lib/node_modules
  • npx-cache        1086 pkgs  ~/.npm/_npx
  • bun-cache          99 pkgs  ~/.bun/install/cache
  2068 unique package@version pairs, 2965 package locations inspected

Findings: 1 CRITICAL  2 HIGH

[CRITICAL] some-pkg@9.9.9 (project)  lifecycle-hook
   postinstall script — touches: child_process, https://, NPM_TOKEN, credential-file
   ↳ "postinstall": node -e "require('https').get('https://x/'+require('fs')...
   /repo/node_modules/some-pkg
...
```

## Options

| flag | meaning |
|---|---|
| `--online` | also query OSV.dev for known advisories (network) |
| `--json` | machine-readable output |
| `--min-sev LEVEL` | `critical` \| `high` \| `medium` \| `low` \| `info` (default `medium`) |
| `--stores LIST` | limit scan to `project,pnpm-project,npm-global,npx-cache,bun-cache,yarn-cache,yarn-berry` |
| `--no-allowlist` | don't downgrade findings on well-known packages |
| `--max-depth N` | max `node_modules` nesting depth (default 12) |
| `--cwd DIR` | project directory to scan (default `.`) |

## What it is not

Heuristics surface *candidates*, not verdicts. A clean run means "nothing tripped the checks on the bytes present" — not a proof of safety. A finding on a big bundled CLI is often a false positive (that's what the allowlist is for); a finding with a worm IOC string or a `curl | bash` postinstall is not. Read the evidence line, then decide.

Zero runtime dependencies (Node ≥ 18, built-ins only) — fitting, for a tool you're meant to trust about dependencies.

## License

MIT
