//! Parallel-scan contract tests.
//!
//! The scan fans per-file work out over `concurrency` workers. Scheduling must
//! never leak into stdout: one tree has to produce byte-identical JSONL, gate
//! JSON, query output, and surface ledgers at any worker count.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn scan_only_stream_is_identical_at_any_concurrency() {
    assert_same_stdout(
        "scan-only",
        vec![fixture("benign-controls"), "--scan-only".to_string()],
    );
}

#[test]
fn agent_gate_json_is_identical_at_any_concurrency() {
    assert_same_stdout(
        "agent-gate",
        vec![
            fixture("benign-controls"),
            "--agent-gate".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
    );
}

#[test]
fn query_output_is_identical_at_any_concurrency() {
    assert_same_stdout(
        "query",
        vec![
            "query".to_string(),
            fixture("benign-controls"),
            "--lang".to_string(),
            "rust".to_string(),
        ],
    );
}

#[test]
fn surface_ledger_is_identical_at_any_concurrency() {
    assert_same_stdout(
        "surface",
        vec![
            "surface".to_string(),
            fixture("benign-controls"),
            "--format".to_string(),
            "json".to_string(),
        ],
    );
}

#[test]
fn absurd_concurrency_is_capped_visibly_and_keeps_output_identical() {
    let args = vec![fixture("benign-controls"), "--scan-only".to_string()];
    let capped = run_with_concurrency(100_000, &args);
    let serial = run_with_concurrency(1, &args);
    let stderr = String::from_utf8_lossy(&capped.stderr);

    assert!(capped.status.success(), "capped run should succeed");
    assert!(
        stderr.contains("scan workers capped at 256"),
        "the cap must be visible, not silent\nstderr:\n{stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&capped.stdout),
        String::from_utf8_lossy(&serial.stdout),
        "capping workers must not change the stream"
    );
}

fn assert_same_stdout(case: &str, args: Vec<String>) {
    let serial = run_with_concurrency(1, &args);
    let parallel = run_with_concurrency(8, &args);
    assert_eq!(
        serial.status.code(),
        parallel.status.code(),
        "{case}: exit codes must match across worker counts"
    );
    assert_eq!(
        String::from_utf8_lossy(&serial.stdout),
        String::from_utf8_lossy(&parallel.stdout),
        "{case}: stdout must be byte-identical across worker counts"
    );
}

/// Run one command with `concurrency` pinned through an isolated user config.
fn run_with_concurrency(concurrency: usize, args: &[String]) -> Output {
    let home = unique_dir(&format!("scan-concurrency-{concurrency}"));
    let sift_home = home.join(".sift");
    fs::create_dir_all(&sift_home).expect("create isolated sift home");
    fs::write(
        sift_home.join("config.toml"),
        format!("concurrency = {concurrency}\n"),
    )
    .expect("write isolated config");
    let output = Command::new(env!("CARGO_BIN_EXE_sift"))
        .args(args)
        .env("HOME", &home)
        .env_remove("SIFT_INTERNAL_GATE")
        .env_remove("SIFT_API_KEY")
        .env_remove("SIFT_SMALL_KEY")
        .output()
        .expect("run sift");
    fs::remove_dir_all(&home).ok();
    output
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/repo-intake")
        .join(name)
        .display()
        .to_string()
}

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-{name}-{}-{nanos}", std::process::id()))
}
