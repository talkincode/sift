//! Scale smoke for the memory contract.
//!
//! ROADMAP promises resident memory decoupled from tree size: a 6x larger tree
//! must not cost 6x the resident set. These tests generate their corpus at run
//! time (no committed fixture) and read the peak back from `--benchmark`, which
//! is the same number the tool reports to its users.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FILE_BYTES: usize = 64 * 1024;
const SMALL_FILES: usize = 64;
const LARGE_FILES: usize = 384;
/// Both runs pin the worker count, so the comparison measures the tree, not the
/// machine's core count.
const CONCURRENCY: usize = 4;

#[test]
fn resident_memory_does_not_scale_with_corpus_size() {
    let small = unique_dir("memory-small");
    let large = unique_dir("memory-large");
    write_corpus(&small, SMALL_FILES);
    write_corpus(&large, LARGE_FILES);

    let small_run = benchmark(&small);
    let large_run = benchmark(&large);

    assert!(
        small_run.status.success() && large_run.status.success(),
        "--benchmark must succeed on both corpora"
    );
    assert_eq!(
        scanned_files(&large_run),
        LARGE_FILES as u64,
        "every generated file should be dehydrated"
    );
    assert_eq!(
        scanned_files(&small_run),
        SMALL_FILES as u64,
        "every generated file should be dehydrated"
    );

    // Platforms without a resident-memory metric report `None`; the scale
    // contract is only checkable where the number exists.
    let (Some(small_peak), Some(large_peak)) = (peak_kib(&small_run), peak_kib(&large_run)) else {
        fs::remove_dir_all(&small).ok();
        fs::remove_dir_all(&large).ok();
        return;
    };

    // 6x the files: a stream-and-drop scan stays close to flat, while holding
    // the tree would grow with it. 3x leaves headroom for allocator behavior.
    assert!(
        large_peak < small_peak.saturating_mul(3),
        "{LARGE_FILES} files peaked at {large_peak} KiB against {small_peak} KiB for {SMALL_FILES} files"
    );
    // Absolute guard: the corpus is ~24 MiB of source.
    assert!(
        large_peak < 512 * 1024,
        "peak resident set {large_peak} KiB is not a streaming footprint"
    );

    fs::remove_dir_all(&small).ok();
    fs::remove_dir_all(&large).ok();
}

fn benchmark(corpus: &Path) -> Output {
    let home = unique_dir("memory-home");
    fs::create_dir_all(&home).expect("create isolated HOME");
    let output = Command::new(env!("CARGO_BIN_EXE_sift"))
        .args([
            corpus.display().to_string(),
            "--benchmark".to_string(),
            "--concurrency".to_string(),
            CONCURRENCY.to_string(),
        ])
        .env("HOME", &home)
        .env_remove("SIFT_INTERNAL_GATE")
        .env_remove("SIFT_API_KEY")
        .env_remove("SIFT_SMALL_KEY")
        .output()
        .expect("run sift --benchmark");
    fs::remove_dir_all(&home).ok();
    output
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("benchmark stdout is JSON")
}

fn peak_kib(output: &Output) -> Option<u64> {
    report(output)["memory"]["resident_set_peak_kib"].as_u64()
}

fn scanned_files(output: &Output) -> u64 {
    report(output)["scan"]["dehydrated_files"]
        .as_u64()
        .unwrap_or(0)
}

/// Dense-but-ordinary Rust files, truncated to an exact size so the two
/// corpora differ only in file count.
fn write_corpus(root: &Path, files: usize) {
    fs::create_dir_all(root).expect("create corpus dir");
    let body: String = (0..1200)
        .map(|idx| format!("pub fn helper_{idx}(input: &str) -> usize {{ input.len() + {idx} }}\n"))
        .collect();
    let slice = &body[..FILE_BYTES.min(body.len())];
    for idx in 0..files {
        fs::write(root.join(format!("module_{idx:05}.rs")), slice).expect("write corpus file");
    }
}

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-{name}-{}-{nanos}", std::process::id()))
}
