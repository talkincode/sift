//! Missing-key behavior on the full-audit path.
//!
//! ROADMAP P0: a full audit without a large-model key must exit immediately
//! with an injection hint — never hang, never fall back to a silent
//! deterministic-only run, never prompt. The deterministic layers
//! (`--scan-only`) keep working without any key.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A valid config that simply carries no key.
const KEYLESS_CONFIG: &str = "max_bytes = 524288\nconcurrency = 2\n";

#[test]
fn full_audit_without_a_key_exits_one_with_an_injection_hint() {
    let home = keyless_home("no-key");
    let repo = fixture_repo("no-key");

    let started = Instant::now();
    let output = run_sift(&home, &[repo.display().to_string()]);
    let elapsed = started.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing large key must exit 1\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("missing large-model API key"),
        "the diagnostic must name the missing key\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("SIFT_API_KEY"),
        "the hint must show the environment variable to set\nstderr:\n{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "no report may be printed when the audit never ran\nstdout:\n{stdout}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "the process must fail fast, took {elapsed:?}"
    );

    cleanup(&home, &repo);
}

#[test]
fn scan_only_still_runs_without_any_key() {
    let home = keyless_home("scan-only");
    let repo = fixture_repo("scan-only");

    let output = run_sift(
        &home,
        &[repo.display().to_string(), "--scan-only".to_string()],
    );

    assert!(
        output.status.success(),
        "scan-only must not need a key\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"path\""),
        "scan-only should still stream dehydrated records"
    );

    cleanup(&home, &repo);
}

/// Run the real binary with every key source cleared, so only the config file
/// decides whether a key exists.
fn run_sift(home: &Path, args: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sift"));
    command.args(args).env("HOME", home);
    for key in [
        "SIFT_API_KEY",
        "SIFT_SMALL_KEY",
        "SIFT_ENDPOINT",
        "SIFT_MODEL",
        "SIFT_INTERNAL_GATE",
    ] {
        command.env_remove(key);
    }
    command.output().expect("run sift")
}

fn keyless_home(name: &str) -> PathBuf {
    let home = unique_dir(&format!("{name}-home"));
    let sift_home = home.join(".sift");
    fs::create_dir_all(&sift_home).expect("create isolated sift home");
    fs::write(sift_home.join("config.toml"), KEYLESS_CONFIG).expect("write isolated config");
    home
}

fn fixture_repo(name: &str) -> PathBuf {
    let repo = unique_dir(&format!("{name}-repo"));
    fs::create_dir_all(&repo).expect("create fixture repo");
    fs::write(repo.join("lib.rs"), "pub fn a() {}\n").expect("write fixture file");
    repo
}

fn cleanup(home: &Path, repo: &Path) {
    fs::remove_dir_all(home).ok();
    fs::remove_dir_all(repo).ok();
}

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-{name}-{}-{nanos}", std::process::id()))
}
