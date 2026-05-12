# pkgradar

A supply-chain scanner that reads the bytes you actually installed, not just the package names.

```
npx pkgradar
```

That is the whole thing. One command, no install, no config. It scans your project and every package cache on the machine, and tells you whether anything looks like malware.

## Why this exists

A lot of "supply-chain" CLIs work like this: download a list of advisories, check whether any package *name* in your project appears on it, print a scary verdict. So you run one, and it tells you something like:

```
Verdict: potential supply-chain exposure - 3 package hits
  zod-to-json-schema@3.25.2
  lightningcss-darwin-arm64@1.30.2
```

...even though `zod-to-json-schema` is a perfectly normal package downloaded millions of times a week, and the version you have was never touched. The advisory just *mentioned* that package's ecosystem. Name matching cannot tell the difference between "this package was trojanized" and "this package shares a name with something in a writeup".

`pkgradar` does the opposite. It opens the files. For every package it finds on disk it checks:

- **Install hooks that detonate.** `preinstall` / `install` / `postinstall` scripts, scored by whether they spawn processes, pipe `curl | bash`, read `~/.npmrc` / `~/.ssh` / `~/.aws/credentials`, or reference `NPM_TOKEN` / `GITHUB_TOKEN` / cloud credentials. (`prepare` is ignored on purpose: it does not run when a package is installed as a dependency.)
- **Known worm artifacts.** Files like `setup_bun.sh`, `bun_environment.js`, `migrate-repos.sh`, hard-coded Shai-Hulud exfiltration endpoints, and the rest of the Shai-Hulud / "Mini Shai-Hulud" indicator set. A bundled GitHub Actions workflow that runs a piped shell download or exfiltrates secrets is flagged too.
- **Obfuscated or packed payloads.** The `javascript-obfuscator` `_0x...` fingerprint, `eval` / `new Function` over `atob` / `Buffer.from(base64)`, `child_process` fed from decoded data, large base64 blobs. The "this file is just minified" signals are deliberately demoted so a normal bundled CLI does not drown the report.
- **Manifest oddities.** `bin` entries pointing outside the package or at a shell script.
- **Known advisories, precisely (optional).** With `--online` it cross-references [OSV.dev](https://osv.dev) by exact `(name, version)`, so you get real GHSA / CVE IDs instead of name collisions, and each advisory is reported at its own severity, so a moderate ReDoS in a dev tool does not shout as loud as an RCE.

A small curated allowlist (`data/allowlist.json`) downgrades benign-but-trippy findings on famous packages (`vercel`, `corepack`, `core-js`, `esbuild`, and so on) to `INFO`. It never suppresses a hard worm indicator, because "a trusted package suddenly ships a worm" is exactly the attack worth catching.

## How it works

```
                            npx pkgradar
                                 |
                                 v
   +-----------------------------------------------------------+
   |  1. DISCOVER STORES                                        |
   |     where package code is extracted on this machine        |
   |                                                            |
   |   project node_modules   pnpm in-project store (.pnpm)     |
   |   npm global root        npx ephemeral cache (~/.npm/_npx) |
   |   bun cache              yarn v1 cache    yarn berry zips  |
   |   pnpm global store                                        |
   +-----------------------------------------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |  2. WALK EACH STORE                                        |
   |     yield every package directory found                    |
   |     dedupe by  name @ version @ path                       |
   +-----------------------------------------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |  3. INSPECT THE BYTES   (per package, budgeted)            |
   |                                                            |
   |   +-------------------+   reads package.json scripts       |
   |   | lifecycle-hook    |   pre/install/postinstall          |
   |   +-------------------+   scored by what they touch        |
   |                                                            |
   |   +-------------------+   walks the package tree           |
   |   | worm-ioc-file     |   matches known artifact names     |
   |   | embedded-workflow |   inspects bundled CI workflows    |
   |   +-------------------+                                    |
   |                                                            |
   |   +-------------------+   reads .js files (<= 1.5MB head    |
   |   | suspicious-js     |   + 96KB tail, <= 24MB per pkg)    |
   |   +-------------------+   obfuscation / eval / exfil combo  |
   |                                                            |
   |   +-------------------+   reads package.json bin           |
   |   | odd-bin           |                                    |
   |   +-------------------+                                    |
   +-----------------------------------------------------------+
                                 |
                  +--------------+--------------+
                  |                             |
            (--online only)                     |
                  v                             |
   +---------------------------+                 |
   | 4. OSV.dev cross-check    |                 |
   |    querybatch -> which    |                 |
   |    pkgs have advisories   |                 |
   |    then /v1/query each    |                 |
   |    -> real severity       |                 |
   +---------------------------+                 |
                  |                             |
                  +--------------+--------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |  5. ALLOWLIST PASS                                         |
   |     downgrade benign findings on famous packages to INFO   |
   |     (never a hard worm indicator)                          |
   +-----------------------------------------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |  6. REPORT                                                 |
   |     verdict line, findings grouped by severity,            |
   |     coloured badges, evidence paths, what-to-do            |
   |     exit 0 clean / 1 findings / 2 error                    |
   +-----------------------------------------------------------+
```

A finding object looks like this:

```
+------------------------------------------------------+
| package    name of the package                       |
| version    version on disk                           |
| store      which store it was found in               |
| code       lifecycle-hook | worm-ioc-file |          |
|            suspicious-js | odd-bin | osv-advisory ... |
| severity   CRITICAL | HIGH | MEDIUM | LOW | INFO      |
| message    what tripped, in plain words              |
| evidence   the file path or script line that did it  |
| dir        full path to the package on disk          |
+------------------------------------------------------+
```

## Usage

```bash
npx pkgradar                 # scan the current project plus every cache on this machine
npx pkgradar --online        # also cross-check OSV.dev advisories by exact version
npx pkgradar --min-sev high  # only show HIGH and CRITICAL (good for CI)
npx pkgradar --json          # machine-readable output
```

Exit codes: `0` clean, `1` findings at or above `--min-sev`, `2` scanner error. In CI: `npx pkgradar --min-sev high`.

| flag | meaning |
|---|---|
| `--online` | also query OSV.dev for known advisories (needs network) |
| `--json` | machine-readable output |
| `--min-sev LEVEL` | `critical`, `high`, `medium`, `low`, `info` (default `medium`) |
| `--stores LIST` | limit to `project,pnpm-project,npm-global,npx-cache,bun-cache,yarn-cache,yarn-berry` |
| `--no-allowlist` | do not downgrade findings on well-known packages |
| `--max-depth N` | max `node_modules` nesting depth (default `12`) |
| `--cwd DIR` | project directory to scan (default `.`) |

## What it is not

These are heuristics. They surface candidates, not verdicts. A clean run means "nothing tripped the checks on the bytes that are present", not "this is proven safe". A finding on a big bundled CLI is often a false positive, which is what the allowlist is for. A finding with a worm indicator string or a `curl | bash` postinstall is not a false positive. Read the evidence line, then decide.

Current coverage gaps, on the roadmap: yarn-berry packages are matched by name only (the zip archives are not opened yet), the pnpm global store and the npm `_cacache` tarballs are not extracted and scanned, and there is no npm-provenance / attestation check or typosquat-distance check yet.

`pkgradar` reads files only. It never executes any package code, install script, or workflow. Zero runtime dependencies, Node 18 or newer, built-ins only, which feels right for a tool you are meant to trust about your dependencies.

## License

MIT
