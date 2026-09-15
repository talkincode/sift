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
const MOCK_REPLY: &str = "<FINAL>| Severity | Scope | Location | Rule | Finding |\n|---|---|---|---|---|\n| Low | production | src/module_000.rs:1 | mock-rule | mock finding |</FINAL>";

struct MockEndpoint {
    endpoint: String,
    requests: Arc<AtomicUsize>,
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
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let accept = {
            let requests = Arc::clone(&requests);
            let in_flight = Arc::clone(&in_flight);
            let max_in_flight = Arc::clone(&max_in_flight);
            let stop = Arc::clone(&stop);
            let workers = Arc::clone(&workers);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let requests = Arc::clone(&requests);
                            let in_flight = Arc::clone(&in_flight);
                            let max_in_flight = Arc::clone(&max_in_flight);
                            let handle = std::thread::spawn(move || {
                                let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                                max_in_flight.fetch_max(current, Ordering::SeqCst);
                                requests.fetch_add(1, Ordering::SeqCst);
                                answer(stream, delay);
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
fn answer(mut stream: TcpStream, delay: Duration) {
    let Ok(reader_stream) = stream.try_clone() else {
        return;
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
        return;
    }

    std::thread::sleep(delay);

    let content = MOCK_REPLY.replace('\n', "\\n");
    let payload = format!("{{\"choices\":[{{\"message\":{{\"content\":\"{content}\"}}}}]}}");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
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
    eprintln!("mock endpoint: requests={requests} peak_in_flight={peak}");
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

    fs::remove_dir_all(&home).ok();
    fs::remove_dir_all(&repo).ok();
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

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("sift-{name}-{}-{nanos}", std::process::id()))
}
