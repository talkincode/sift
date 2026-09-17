//! Full-audit smoke against a local mock endpoint.
//!
//! The Reduce path is the only place sift spends real money and real wall
//! clock, so it gets an automated end-to-end proof instead of a manual run: a
//! mock OpenAI-compatible server records how many requests arrived and how many
//! were in flight at once, and the test asserts the audit both finishes and
//! actually overlaps independent batches.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A converged Markdown table row: `render_batch_reports` keeps table rows and
/// drops everything else, so the mock must answer with one to survive merging.
const MOCK_FINDING: &str = "| Low | production | src/module_000.rs:1 | mock-rule | mock finding |";
const MOCK_FINAL: &str = "<FINAL>| Severity | Scope | Location | Rule | Finding |\n|---|---|---|---|---|\n| Low | production | src/module_000.rs:1 | mock-rule | mock finding |</FINAL>";
/// What a model following the prompt does first: ask for the local filter.
const MOCK_TOOL_CALL: &str =
    "<TOOL_CALL>{\"skill\":\"coarse_filter\",\"input\":\"$SEED\"}</TOOL_CALL>";

struct MockEndpoint {
    endpoint: String,
    requests: Arc<AtomicUsize>,
    prompt_bytes: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl MockEndpoint {
    /// Start an OpenAI-compatible endpoint that answers after `delay`, so
    /// overlapping Reduce batches are observable as in-flight requests > 1.
    fn start(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
        let addr = listener.local_addr().expect("mock endpoint address");
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");

        let requests = Arc::new(AtomicUsize::new(0));
        let prompt_bytes = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let accept = {
            let requests = Arc::clone(&requests);
            let prompt_bytes = Arc::clone(&prompt_bytes);
            let in_flight = Arc::clone(&in_flight);
            let max_in_flight = Arc::clone(&max_in_flight);
            let stop = Arc::clone(&stop);
            let workers = Arc::clone(&workers);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let requests = Arc::clone(&requests);
                            let prompt_bytes = Arc::clone(&prompt_bytes);
                            let in_flight = Arc::clone(&in_flight);
                            let max_in_flight = Arc::clone(&max_in_flight);
                            let handle = std::thread::spawn(move || {
                                let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                                max_in_flight.fetch_max(current, Ordering::SeqCst);
                                requests.fetch_add(1, Ordering::SeqCst);
                                let sent = answer(stream, delay);
                                prompt_bytes.fetch_add(sent, Ordering::SeqCst);
                                in_flight.fetch_sub(1, Ordering::SeqCst);
                            });
                            if let Ok(mut workers) = workers.lock() {
                                workers.push(handle);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            endpoint: format!("http://{addr}/v1/chat/completions"),
            requests,
            prompt_bytes,
            max_in_flight,
            stop,
            accept: Some(accept),
        }
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MockEndpoint {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Read one HTTP request (headers plus body) and answer with a valid completion.
fn answer(mut stream: TcpStream, delay: Duration) -> usize {
    let Ok(reader_stream) = stream.try_clone() else {
        return 0;
    };
    let mut reader = BufReader::new(reader_stream);
    let mut content_length = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return 0;
    }

    std::thread::sleep(delay);

    // Count the prompt the way a provider bills it: decoded content bytes.
    let prompt = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("messages")?
                .get(0)?
                .get("content")?
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_default();
    let turn = if prompt.contains("OBSERVATION:") {
        MOCK_FINAL
    } else {
        MOCK_TOOL_CALL
    };
    // Build the response as JSON: the tool-call reply contains quotes, and
    // hand-rolled escaping is exactly how a mock starts lying about the wire.
    let payload = serde_json::json!({
        "choices": [{"message": {"content": turn}}],
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    prompt.len()
}

#[test]
fn full_audit_overlaps_reduce_batches_against_a_mock_endpoint() {
    let mut endpoint = MockEndpoint::start(Duration::from_millis(250));

    let home = unique_dir("full-audit-home");
    let sift_home = home.join(".sift");
    fs::create_dir_all(&sift_home).expect("create isolated sift home");
    fs::write(
        sift_home.join("config.toml"),
        format!(
            "concurrency = 4\nmax_bytes = 524288\n[[model]]\nrole = \"large\"\nendpoint = \"{}\"\nmodel = \"mock\"\nkey_env = \"SIFT_API_KEY\"\ntimeout_ms = 30000\nmax_retries = 1\n",
            endpoint.endpoint
        ),
    )
    .expect("write isolated config");

    let repo = unique_dir("full-audit-repo");
    write_seed_repo(&repo);

    let output = run_sift(&home, &[repo.display().to_string()]);
    endpoint.shutdown();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the mock full audit must succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = endpoint.requests.load(Ordering::SeqCst);
    let peak = endpoint.max_in_flight.load(Ordering::SeqCst);
    let sent_bytes = endpoint.prompt_bytes.load(Ordering::SeqCst);
    eprintln!("mock endpoint: requests={requests} peak_in_flight={peak} prompt_bytes={sent_bytes}");
    assert!(
        requests >= 2,
        "the fixture must force at least two Reduce batches, saw {requests}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("parallel: 4"),
        "configured concurrency should reach the Reduce fan-out\nstderr:\n{stderr}"
    );
    assert!(
        peak >= 2,
        "independent Reduce batches must overlap, peak in flight was {peak}"
    );
    assert!(
        stdout.contains(MOCK_FINDING),
        "the converged model report should reach stdout\nstdout:\n{stdout}"
    );

    // The Reduce stage opens on the deterministic findings, so the raw seed
    // never reaches the endpoint: that is where the input cost went.
    let benchmark = run_sift(
        &home,
        &[repo.display().to_string(), "--benchmark".to_string()],
    );
    let report: serde_json::Value =
        serde_json::from_slice(&benchmark.stdout).expect("benchmark stdout is JSON");
    let planned_bytes = report["tokens"]["planned_prompt_bytes"]
        .as_u64()
        .unwrap_or(0);
    let planned_requests = report["tokens"]["planned_requests"].as_u64().unwrap_or(0);
    assert_eq!(
        planned_requests as usize, requests,
        "the plan must count the requests the audit actually makes"
    );
    assert!(
        planned_bytes as usize >= sent_bytes,
        "the estimate ({planned_bytes}) must not understate what was sent ({sent_bytes})"
    );
    assert!(
        planned_bytes as usize <= sent_bytes.saturating_mul(110) / 100,
        "the estimate ({planned_bytes}) overstates what was sent ({sent_bytes}) by more than 10%"
    );

    // The headline: one request per batch, and the seed stays local.
    let seed_bytes = report["seed"]["bytes_sent"].as_u64().unwrap_or(0);
    assert_eq!(
        requests,
        report["seed"]["reduce_batches"].as_u64().unwrap_or(0) as usize,
        "each batch must cost exactly one request"
    );
    assert!(
        sent_bytes.saturating_mul(5) < seed_bytes as usize,
        "the payload sent ({sent_bytes}) should be far below the seed ({seed_bytes})"
    );

    fs::remove_dir_all(&home).ok();
    fs::remove_dir_all(&repo).ok();
}

#[test]
fn full_audit_saves_the_report_it_prints() {
    let mut endpoint = MockEndpoint::start(Duration::from_millis(20));

    let home = unique_dir("save-home");
    let sift_home = home.join(".sift");
    fs::create_dir_all(&sift_home).expect("create isolated sift home");
    fs::write(
        sift_home.join("config.toml"),
        format!(
            "concurrency = 2\nmax_bytes = 524288\n[[model]]\nrole = \"large\"\nendpoint = \"{}\"\nmodel = \"mock\"\nkey_env = \"SIFT_API_KEY\"\ntimeout_ms = 30000\nmax_retries = 1\n",
            endpoint.endpoint
        ),
    )
    .expect("write isolated config");

    let repo = unique_dir("save-repo");
    write_seed_repo(&repo);
    let out_dir = unique_dir("save-out");

    // `--save-to` implies saving; the report must land in the requested dir
    // under the dated name, and match what was printed.
    let output = run_sift(
        &home,
        &[
            repo.display().to_string(),
            "--save-to".to_string(),
            out_dir.display().to_string(),
        ],
    );
    endpoint.shutdown();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the mock audit must succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let saved: Vec<PathBuf> = fs::read_dir(&out_dir)
        .expect("the save directory must exist")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(saved.len(), 1, "one audit, one file: {saved:?}");

    let name = saved[0]
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    assert!(
        name.starts_with("sift-audit-result-") && name.ends_with("-001.md"),
        "unexpected report name: {name}"
    );
    assert!(
        stderr.contains("audit result saved:"),
        "saving must be reported on stderr\nstderr:\n{stderr}"
    );

    let contents = fs::read_to_string(&saved[0]).expect("read saved report");
    assert_eq!(
        contents, stdout,
        "the saved report must be byte-identical to what was printed"
    );

    // A second audit in the same directory must not overwrite the first.
    let mut endpoint = MockEndpoint::start(Duration::from_millis(20));
    fs::write(
        sift_home.join("config.toml"),
        format!(
            "concurrency = 2\nmax_bytes = 524288\n[[model]]\nrole = \"large\"\nendpoint = \"{}\"\nmodel = \"mock\"\nkey_env = \"SIFT_API_KEY\"\ntimeout_ms = 30000\nmax_retries = 1\n",
            endpoint.endpoint
        ),
    )
    .expect("rewrite isolated config");
    let second = run_sift(
        &home,
        &[
            repo.display().to_string(),
            "--save-to".to_string(),
            out_dir.display().to_string(),
        ],
    );
    endpoint.shutdown();
    assert!(second.status.success(), "the second audit must succeed");

    let mut names: Vec<String> = fs::read_dir(&out_dir)
        .expect("save directory")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "reports must accumulate: {names:?}");
    assert!(
        names.iter().any(|name| name.ends_with("-002.md")),
        "the second report must take the next number: {names:?}"
    );

    cleanup(&home, &repo);
    fs::remove_dir_all(&out_dir).ok();
}

fn run_sift(home: &Path, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sift"))
        .args(args)
        .env("HOME", home)
        .env("SIFT_API_KEY", "mock-key")
        .env_remove("SIFT_INTERNAL_GATE")
        .env_remove("SIFT_SMALL_KEY")
        .output()
        .expect("run sift")
}

/// Enough dehydrated evidence to exceed the 64 KiB Reduce batch cap several
/// times over, which is what forces more than one model call.
fn write_seed_repo(root: &Path) {
    fs::create_dir_all(root).expect("create fixture repo");
    for file in 0..24 {
        let mut src = String::from("use std::collections::HashMap;\n");
        for item in 0..60 {
            src.push_str(&format!(
                "pub fn helper_{file}_{item}(input: &str) -> usize {{ input.len() + {item} }}\n"
            ));
        }
        src.push_str("pub fn run(input: &str) -> usize {\n");
        for item in 0..60 {
            src.push_str(&format!(
                "    let value_{item} = helper_{file}_{item}(input);\n"
            ));
        }
        src.push_str("    0\n}\n");
        fs::write(root.join(format!("module_{file:03}.rs")), src).expect("write fixture file");
    }
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
