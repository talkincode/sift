//! Black-box contract tests for `sift surface` and `sift diff`.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/surface")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    let home = unique_home();
    std::fs::create_dir_all(&home).expect("create isolated HOME");
    let output = Command::new(env!("CARGO_BIN_EXE_sift"))
        .args(args)
        .env("HOME", &home)
        .env_remove("SIFT_INTERNAL_GATE")
        .env_remove("SIFT_API_KEY")
        .env_remove("SIFT_SMALL_KEY")
        .env_remove("SIFT_ENDPOINT")
        .output()
        .expect("run sift");
    std::fs::remove_dir_all(&home).ok();
    output
}

fn unique_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-surface-home-{}-{nanos}", std::process::id()))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn surface_text_lists_capabilities_with_evidence() {
    let v2 = fixture("pkg-v2");
    let output = run(&["surface", v2.to_str().unwrap_or(".")]);
    let text = stdout(&output);
    assert!(output.status.success(), "surface should exit 0\n{text}");
    assert!(text.contains("INSTALL_SURFACE:"), "{text}");
    assert!(text.contains("== execute ("), "{text}");
    assert!(text.contains("== hook ("), "{text}");
    assert!(text.contains("postinstall"), "{text}");
    assert!(text.contains("download-execute"), "{text}");
    assert!(text.contains("npm-postinstall"), "{text}");
    assert!(text.contains("ci-secret"), "{text}");
}

#[test]
fn surface_json_exposes_stable_shape() {
    let v2 = fixture("pkg-v2");
    let output = run(&["surface", v2.to_str().unwrap_or("."), "--format", "json"]);
    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("surface json parses");
    assert_eq!(parsed["schema_version"], 1);
    assert!(parsed["entries_total"].as_u64().unwrap_or(0) > 0);
    assert_eq!(parsed["truncated"], false);
    let counts = &parsed["counts"];
    assert!(counts["execute"].as_u64().unwrap_or(0) >= 1, "{counts}");
    assert!(counts["hook"].as_u64().unwrap_or(0) >= 2, "{counts}");
    let entries = parsed["entries"].as_array().cloned().unwrap_or_default();
    assert!(
        entries
            .iter()
            .any(|entry| entry["capability"] == "hook" && entry["trigger"] == "postinstall"),
        "expected a postinstall hook entry"
    );
    assert!(
        entries.iter().all(|entry| entry["path"].is_string()),
        "every entry carries a path"
    );
}

#[test]
fn fail_on_controls_the_exit_code() {
    let v2 = fixture("pkg-v2");
    let failing = run(&[
        "surface",
        v2.to_str().unwrap_or("."),
        "--fail-on",
        "execute",
    ]);
    assert_eq!(failing.status.code(), Some(1));
    let passing = run(&[
        "surface",
        v2.to_str().unwrap_or("."),
        "--fail-on",
        "artifact",
    ]);
    assert_eq!(passing.status.code(), Some(0));
}

#[test]
fn unknown_capability_is_a_usage_error() {
    let v2 = fixture("pkg-v2");
    let output = run(&["surface", v2.to_str().unwrap_or("."), "--fail-on", "rm-rf"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown capability"), "{stderr}");
}

#[test]
fn unknown_scope_is_a_usage_error_and_scope_all_is_accepted() {
    let v2 = fixture("pkg-v2");
    let bad = run(&["surface", v2.to_str().unwrap_or("."), "--scope", "bogus"]);
    assert_eq!(bad.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("unknown scope"), "{stderr}");

    let all = run(&[
        "surface",
        v2.to_str().unwrap_or("."),
        "--scope",
        "all",
        "--format",
        "json",
    ]);
    assert!(all.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&all)).expect("surface json parses");
    assert!(parsed["hidden_by_scope"].is_object(), "{parsed}");
}

#[test]
fn capability_filter_narrows_the_ledger() {
    let v2 = fixture("pkg-v2");
    let output = run(&[
        "surface",
        v2.to_str().unwrap_or("."),
        "--capability",
        "hook",
        "--format",
        "json",
    ]);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("surface json parses");
    let entries = parsed["entries"].as_array().cloned().unwrap_or_default();
    assert!(!entries.is_empty());
    assert!(
        entries.iter().all(|entry| entry["capability"] == "hook"),
        "{entries:?}"
    );
}

#[test]
fn obfuscated_source_is_reported_as_an_artifact() {
    let obfuscated = fixture("obfuscated");
    let output = run(&["surface", obfuscated.to_str().unwrap_or(".")]);
    let text = stdout(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("obfuscated_source"), "{text}");

    let json = run(&[
        "surface",
        obfuscated.to_str().unwrap_or("."),
        "--format",
        "json",
    ]);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&json)).expect("surface json parses");
    let entries = parsed["entries"].as_array().cloned().unwrap_or_default();
    assert!(
        entries
            .iter()
            .any(|entry| entry["capability"] == "artifact"
                && entry["evidence"] == "obfuscated_source"),
        "{entries:?}"
    );

    let failing = run(&[
        "surface",
        obfuscated.to_str().unwrap_or("."),
        "--fail-on",
        "artifact",
    ]);
    assert_eq!(failing.status.code(), Some(1));
}

#[test]
fn diff_reports_added_surface_between_versions() {
    let v1 = fixture("pkg-v1");
    let v2 = fixture("pkg-v2");
    let changed = run(&[
        "diff",
        v1.to_str().unwrap_or("."),
        v2.to_str().unwrap_or("."),
    ]);
    let text = stdout(&changed);
    assert_eq!(changed.status.code(), Some(1), "{text}");
    assert!(text.contains("INSTALL_SURFACE_DIFF"), "{text}");
    assert!(text.contains("== added =="), "{text}");
    assert!(text.contains("download-execute"), "{text}");

    let same = run(&[
        "diff",
        v1.to_str().unwrap_or("."),
        v1.to_str().unwrap_or("."),
    ]);
    assert_eq!(same.status.code(), Some(0), "{}", stdout(&same));
}

#[test]
fn diff_json_exposes_added_and_removed() {
    let v1 = fixture("pkg-v1");
    let v2 = fixture("pkg-v2");
    let output = run(&[
        "diff",
        v1.to_str().unwrap_or("."),
        v2.to_str().unwrap_or("."),
        "--format",
        "json",
    ]);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("diff json parses");
    assert_eq!(parsed["schema_version"], 1);
    assert!(parsed["added"].as_u64().unwrap_or(0) > 0, "{parsed}");
    assert_eq!(parsed["removed"], 0);
    let added = parsed["added_entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        added
            .iter()
            .any(|entry| entry["evidence"] == "npm-postinstall"),
        "{added:?}"
    );
}
