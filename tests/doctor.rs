//! `sift doctor` diagnostics: the command users run when a config is wrong.
//!
//! Each test gets a throwaway `HOME`, so the checks read a config this test
//! wrote and never the machine's real `~/.sift/config.toml`. No network is
//! involved: `doctor` only inspects configuration and environment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// Config that configures a usable large model: a reachable local endpoint,
/// which needs no key at all.
const HEALTHY_CONFIG: &str = r#"max_bytes = 524288
[[model]]
role = "large"
endpoint = "http://127.0.0.1:11434/v1/chat/completions"
model = "local-large"
key_env = "SIFT_API_KEY"
timeout_ms = 30000
max_retries = 1
"#;

#[test]
fn healthy_config_prints_rows_and_exits_zero() {
    let home = home_with("healthy", Some(HEALTHY_CONFIG), 0o600);
    let output = doctor(&home, "present");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "a usable config must pass\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("# sift doctor"),
        "header missing:\n{stdout}"
    );
    assert!(
        stdout.contains("| Status | Area | Detail |"),
        "table header missing:\n{stdout}"
    );
    assert!(
        stdout.contains("| PASS | `config` | file exists |"),
        "config pass row missing:\n{stdout}"
    );
    assert!(
        stdout.contains("| PASS | `config` | permissions 600 |"),
        "permission row missing:\n{stdout}"
    );
    assert!(
        !stdout.contains("| FAIL |"),
        "healthy config must not fail:\n{stdout}"
    );

    fs::remove_dir_all(home).ok();
}

#[test]
fn invalid_toml_fails_and_exits_nonzero() {
    let home = home_with("invalid", Some("concurrency = \"oops\"\n"), 0o600);
    let output = doctor(&home, "present");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "invalid TOML must exit non-zero\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("| FAIL | `config` | invalid TOML"),
        "invalid TOML row missing:\n{stdout}"
    );

    fs::remove_dir_all(home).ok();
}

#[test]
fn absent_config_is_created_without_secrets_and_reported_as_warn() {
    let home = home_with("missing", None, 0o600);
    let output = doctor(&home, "present");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "a missing config is recoverable, not a failure\nstdout:\n{stdout}"
    );
    assert!(
        stdout
            .contains("| WARN | `config` | file was missing; created default non-secret config |"),
        "creation warning missing:\n{stdout}"
    );

    let created = home.join(".sift/config.toml");
    let contents = fs::read_to_string(&created).expect("doctor creates the default config");
    assert!(
        !contents.contains("sk-"),
        "the created config must not contain a real key:\n{contents}"
    );
    assert!(
        contents.contains("key_env"),
        "the created config should point at key_env, not an inline secret"
    );

    fs::remove_dir_all(home).ok();
}

#[test]
fn loose_permissions_are_a_warning_not_a_failure() {
    let home = home_with("permissions", Some(HEALTHY_CONFIG), 0o644);
    let output = doctor(&home, "present");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "loose mode is advisory:\n{stdout}");
    assert!(
        stdout.contains("consider chmod 600"),
        "permission advice missing:\n{stdout}"
    );

    fs::remove_dir_all(home).ok();
}

#[test]
fn local_endpoint_without_key_passes_without_auth() {
    // A local OpenAI-compatible server takes no auth, so this is healthy.
    let home = home_with("local-no-key", Some(HEALTHY_CONFIG), 0o600);
    let output = doctor_with_env(&home, &[("SIFT_API_KEY", None)]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "a local endpoint runs without a key\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("local endpoint will run without auth"),
        "local no-auth detail missing:\n{stdout}"
    );
    assert!(!stdout.contains("| FAIL |"), "must not fail:\n{stdout}");

    fs::remove_dir_all(home).ok();
}

#[test]
fn large_model_without_its_key_env_fails() {
    let config = r#"[[model]]
role = "large"
endpoint = "https://api.openai.com/v1/chat/completions"
model = "gpt-4o"
key_env = "SIFT_API_KEY"
timeout_ms = 30000
max_retries = 1
"#;
    let home = home_with("no-key", Some(config), 0o600);
    // The config names SIFT_API_KEY, so clearing it is what makes the model
    // unusable while everything else stays valid.
    let output = doctor_with_env(&home, &[("SIFT_API_KEY", None)]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "an unusable large model must exit non-zero\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("key_env SIFT_API_KEY is not set"),
        "missing key detail not reported:\n{stdout}"
    );
    assert!(
        stdout.contains("| FAIL | `secrets` |"),
        "missing key must be a FAIL row:\n{stdout}"
    );

    fs::remove_dir_all(home).ok();
}

#[test]
fn azure_key_with_public_endpoint_is_flagged() {
    let config = r#"[[model]]
role = "large"
endpoint = "https://api.openai.com/v1/chat/completions"
model = "gpt-4o"
key_env = "WJT_AZURE_OPENAI_API_KEY"
"#;
    let home = home_with("azure-mismatch", Some(config), 0o600);
    let output = doctor_with_env(&home, &[("WJT_AZURE_OPENAI_API_KEY", Some("azure-shaped"))]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "the endpoint/key mismatch must fail\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("| FAIL | `endpoint` |") && stdout.contains("commonly returns 401"),
        "endpoint mismatch row missing:\n{stdout}"
    );

    fs::remove_dir_all(home).ok();
}

#[test]
fn doctor_never_prints_the_key_value() {
    let home = home_with("no-leak", Some(HEALTHY_CONFIG), 0o600);
    let secret = "sk-do-not-print-me-abcdef";
    let output = doctor_with_env(&home, &[("SIFT_API_KEY", Some(secret))]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "healthy config should pass:\n{stdout}"
    );
    assert!(
        !stdout.contains(secret) && !stderr.contains(secret),
        "doctor leaked the key value"
    );

    fs::remove_dir_all(home).ok();
}

/// Run `sift doctor` with `HOME` pointed at a throwaway directory.
fn doctor(home: &Path, api_key: &str) -> Output {
    doctor_with_env(home, &[("SIFT_API_KEY", Some(api_key))])
}

fn doctor_with_env(home: &Path, env: &[(&str, Option<&str>)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sift"));
    command.arg("doctor").env("HOME", home);
    for key in [
        "SIFT_API_KEY",
        "SIFT_SMALL_KEY",
        "WJT_AZURE_OPENAI_API_KEY",
        "SIFT_ENDPOINT",
        "SIFT_MODEL",
    ] {
        command.env_remove(key);
    }
    for (key, value) in env {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    command.output().expect("run sift doctor")
}

fn home_with(name: &str, config: Option<&str>, mode: u32) -> PathBuf {
    let home = unique_dir(&format!("doctor-{name}"));
    let sift_home = home.join(".sift");
    fs::create_dir_all(&sift_home).expect("create isolated sift home");
    if let Some(config) = config {
        let path = sift_home.join("config.toml");
        fs::write(&path, config).expect("write isolated config");
        set_mode(&path, mode);
    }
    home
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set config mode");
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-{name}-{}-{nanos}", std::process::id()))
}
