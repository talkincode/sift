# sift

> English | [中文](docs/README.zh.md)

Cost-controlled open-source project auditor: **tiered funnel + compute mismatch + ReACT scheduling**. Before adopting a dependency, get a file/line-level risk ledger without force-feeding tens of thousands of lines into a frontier model.

- Grunt work (structure extraction / deterministic coarse filtering) → tree-sitter + local rules
- Logic convergence → frontier large model, orchestrated by a ReACT state machine over deterministic findings
- Single binary, zero-config; audits a whole project or a single module; sift must pass its internal release gates

See [docs/ROADMAP.md](docs/ROADMAP.md) for full design.

## Usage

```sh
sift ./repo --scan-only        # scan layer only (no key needed)
sift ./repo --agent-gate       # deterministic pre-run gate (no key needed)
sift ./repo --agent-gate --format json
sift ./repo --benchmark        # scan/model budget telemetry JSON (no key needed)
sift github owner/repo         # safe GitHub intake, defaults to --agent-gate
sift github owner/repo --ref main --scan-only
sift eval-corpus               # run the checked-in repo-intake precision corpus
sift query ./repo --calls 'exec|spawn'          # stateless evidence query → file:line
sift query ./repo --imports reqwest --lang rust # who imports reqwest, rust files only
sift query ./repo --any 'curl|wget' --format json
sift surface ./repo            # install-time capability ledger (no key needed)
sift surface ./repo --capability network,execute --fail-on execute
sift surface ./repo --format json
sift diff pkg-1.2.3 pkg-1.4.0  # what the install surface gained or lost
sift ./repo --module src        # audit a submodule
SIFT_API_KEY=<KEY> sift ./repo  # full pipeline
sift ./repo --api-key-file ~/.sift/key
sift ./repo --report-language zh # request a Simplified Chinese Markdown report
sift ./repo --save               # also save the report to reports/sift-audit-result-YYYYMMDD-NNN.md
sift ./repo --save-to out/audits # save the report into a custom directory (implies --save)
sift ./repo --debug              # print extra diagnostics to stderr
sift doctor                    # check config, key_env, and endpoint/key mismatches
```

`--agent-gate` is a local, deterministic repo-intake gate for agents and wrapper
scripts. It writes only this stable contract to stdout:

```text
VERDICT: ACCEPT | CAUTION | REJECT | INCOMPLETE
WHY:
- <top evidence>
BLOCKERS:
- <file:line evidence or coverage blocker>
SAFE_TO_AGENT_RUN: yes | no
```

Use `--format json` with `--agent-gate` for automation. The JSON contract
contains `verdict`, `safe_to_agent_run`, `exit_reason`, `coverage`, `findings`,
`blockers`, artifact inventory, truncation details, and policy actions.

The command exits `0` only when `SAFE_TO_AGENT_RUN: yes`; `CAUTION`,
`REJECT`, and `INCOMPLETE` exit non-zero so callers can stop before setup,
install, build, or run steps.

`sift query` is a stateless retrieval view over the same dehydrated evidence
that `--scan-only` streams. Every invocation re-runs the local scan (seconds,
no key, no index or cache) and filters the evidence with flat regex flags:
`--calls`, `--imports`, `--signatures`, `--external`, `--any`, plus `--lang`
and `--path` record filters. Multiple flags AND together at the file level.
Text output is grep-style `path:line: kind: text` evidence; `--format json`
emits one document with `schema_version`, the echoed `query`, `coverage`,
match counts, and `matches`. Emitted evidence is capped by `--limit`
(default 200) with visible truncation. Exit codes follow grep: `0` matched,
`1` no matches, `2` usage or configuration errors.

`sift surface` is the install-surface ledger: it answers *what can this tree do
at install, build, or CI time* with `file:line` evidence, without judging
severity. Capabilities are fixed and emitted in this order: `artifact`, `deps`,
`execute`, `fs-write`, `hook`, `network`, `secret`. Each entry carries a
`trigger` (the entry point that can run it: `postinstall`, `ci-run`,
`docker-run`, `make`, `python-setup`, `install-script`, `doc`, or
`source`/`manifest` when it is only reachable from code), a `confidence`
(`strong` when the line proves the capability, `weak` when it only indicates
reach, such as an import or a URL literal), and the scope (`production`, `ci`,
`test`, `fixture`, `docs`). Text output groups entries by capability; JSON adds
`schema_version`, counts, and coverage. `--capability` filters, `--scope`
selects path scopes (default `production,ci`, hidden entries always counted),
`--limit` caps emission (default 200), and `--fail-on <capability,...>` exits
`1` when a capability is present. Exit codes: `0` ledger produced, `1`
`--fail-on` matched, `2` usage or configuration error. Unlike the audit path,
`surface` and `diff` never read the target's `.env` or `sift-policy.toml`: the
ledger is a pure function of the tree.

The `artifact` capability also covers **source files whose shape is opaque**:
token detectors cannot see an obfuscated payload, because the payload is a
string array plus generated identifiers and no capability token ever appears.
`sift surface` therefore reports `obfuscated_source` (strong, ≥ 100 generated
`_0x`-style identifiers) or `minified_source` (weak, a generated line of
20 000+ characters) with the file's metrics, which is what makes an obfuscated
version bump visible to `sift diff`.

`sift diff <a> <b>` reduces two trees to the same entries and reports what the
install surface gained or lost, keyed on `(capability, path, evidence text)` so
line moves are not changes; a shared wrapper directory (`package/`,
`foo-1.2.3/`) is stripped so two extracted distributions compare directly.
Exit codes: `0` identical, `1` changed, `2` usage or configuration error.

The deterministic supply-chain layer currently flags npm install lifecycle
scripts, manifest/lockfile reproducibility gaps, git/path/http dependency
sources, Rust `build.rs` command boundaries, shell/Dockerfile download-execute
patterns, base64 decode-to-execute flows, GitHub Actions permission/trigger
risk, secrets coupled to shell execution, unpinned GitHub Actions, Dockerfile
root/remote repository patterns, and suspicious binary/archive artifacts.

`sift github` accepts `owner/repo` or `https://github.com/owner/repo`, fetches a
temporary checkout with `git`, resolves the commit SHA, then runs the local
scan/gate/benchmark pipeline against that checkout. It never runs repository
code, package manager commands, build scripts, hooks, install commands, or
submodules. The checkout is inspected for file/byte limits, `.gitmodules`, and
Git LFS indicators before scanning. Temporary checkouts are removed by default;
use `--keep-checkout` only when you need to inspect the fetched tree.

Project-local policy lives in `sift-policy.toml`. It supports
`max_candidate_files`, `[[allowlist]]`, `[[denylist]]`, and
`[[severity_override]]` entries keyed by `path`, `rule`, `severity`, and
`reason`; applied policy decisions are shown in text and JSON gate output.

On first run, sift creates `~/.sift/config.toml` from the built-in default
template. The default file contains only non-secret settings; put model keys in
environment variables or pass `--api-key-file`.

Full audits keep stdout reserved for the final Markdown report. Progress,
status, and debug diagnostics are printed to stderr so long runs do not look
stalled and downstream tools can still pipe stdout safely.

The current full-audit path does not call small-model Map by default. It
converges from the deterministic ledger with the configured large model, while
the small-model Map implementation remains an experimental diagnostic path.

`--benchmark` is a local telemetry mode for release notes and cost checks. It
does not call models; stdout is stable JSON unless `--benchmark-output <path>`
is used. The report includes candidate/dehydrated/skipped counts, scan timing,
best-available resident memory, seed bytes, planned Reduce batches, model-call
counts, approximate token counts, and optional USD cost estimates. Pricing is
explicit and never inferred:

```sh
sift ./repo --benchmark \
  --benchmark-input-1m-cost 0.25 \
  --benchmark-output-1m-cost 1.00 \
  --benchmark-estimated-output-tokens 2000
```

The input estimate counts the Reduce prompts the audit would actually send, not
just the seed. Each batch costs a seed turn plus, once the model asks for the
local `coarse_filter`, an observation turn carrying the deterministic findings,
so `tokens.planned_prompt_bytes` covers both and `tokens.seed_prompt_bytes` is
the floor for a model that answers `<FINAL>` immediately. Counting the
observation turns runs that local filter, which is why benchmark mode costs a
fraction of a second more than the scan alone; it still makes no model calls.

## Supported Languages

The scan layer currently dehydrates Rust, Python, Go, JavaScript, TypeScript/TSX,
HTML, CSS, Zig, Bash-compatible shell files (`.sh`, `.bash`, `.zsh`), Dart,
Kotlin, Java, C/C++, C#, PHP, Swift, Ruby, SQL, Dockerfile/Containerfile, YAML,
HCL/Terraform, Vue, Svelte, `package.json`, common package manifests/lockfiles,
Makefile, and Markdown install snippets.

## Install

Build from source:

```sh
make ci
make install
```

Install local git hooks:

```sh
make githooks-install
```

The pre-commit hook runs `make local-ci` before each commit. To bypass it for an
intentional emergency commit, run `SIFT_SKIP_LOCAL_CI=1 git commit ...`.

## Test Fixtures

`tests/fixtures/repo-intake/` contains synthetic malicious and benign repository
trees used by the deterministic `--agent-gate` regression suite. `sift
eval-corpus` emits the release-oriented precision table over those fixtures.
The fixture commands are inert examples and must never be executed as install
scripts.

macOS releases are published through the talkincode tap. Tagging `v*` runs
`release.yml`, which publishes the `.tar.xz` assets with checksums, renders
`Formula/sift.rb` for that tap, and pushes it with the `HOMEBREW_TAP_TOKEN`
secret; `HOMEBREW_TAP_REPO` and `HOMEBREW_LICENSE` repository variables
override the tap target without editing the workflow.

```sh
brew install talkincode/tap/sift
```

## Status

P0 scaffold + P1 AST dehydrate + P2 model layer + P3 ReACT scheduler (tool protocol, compile-time skills, retry→partial) done. P4 is in progress: local AST risk ledger, Markdown renderer, `[[model]]` config parsing, stable JSON gate output, policy, artifact inventory, and eval corpus are wired. Full audits currently reduce deterministic findings with the large model; small-model Map is retained as inactive diagnostic code until it is reintroduced behind behavior-level gates. Internal release gates write local reports under `reports/` for maintainers.

## Docs

- [Roadmap](docs/ROADMAP.md) · [路线图](docs/ROADMAP.zh.md)
- [Contributor handbook (AGENT.md)](AGENT.md) · [中文](docs/AGENT.zh.md)

Build the bilingual mdBook site locally:

```sh
make docs
```

## License

MIT — see [LICENSE](LICENSE). The Homebrew formula carries the same license,
taken from the `HOMEBREW_LICENSE` repository variable at release time: an SPDX
id is rendered as a string (`MIT` becomes `license "MIT"`), and a value that
starts with `:` is passed through as a symbol (the default
`:cannot_represent`).
