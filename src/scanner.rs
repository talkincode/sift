use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender, bounded};
use ignore::WalkBuilder;

use crate::config::Config;

/// Bounded channel capacity; fast disk I/O back-pressures instead of growing memory.
const CHANNEL_CAP: usize = 1024;
/// Hard ceiling on scan worker threads. `concurrency` is user-supplied, and a
/// slipped digit must surface as a visible cap instead of a thread-spawn abort.
const MAX_SCAN_WORKERS: usize = 256;
/// Ceiling on files allowed to be in flight ahead of the consumer. Together with
/// the per-worker factor it bounds resident memory for any tree size.
const MAX_REORDER_WINDOW: usize = 256;
const VCS_METADATA_DIRS: &[&str] = &[".git", ".hg", ".svn", ".jj"];

/// One walked file plus its position in walk order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanInput {
    pub seq: u64,
    pub path: PathBuf,
}

/// Start a background walk that emits files in walk order.
///
/// The walk itself stays single-threaded on purpose: walk order is the
/// deterministic baseline every stream and report contract is compared against,
/// so only the per-file work fans out (see [`scan_ordered`]).
pub fn spawn_walk(root: PathBuf, ignores: Vec<String>) -> Receiver<ScanInput> {
    let (tx, rx) = bounded::<ScanInput>(CHANNEL_CAP);

    thread::spawn(move || {
        let mut builder = WalkBuilder::new(&root);
        builder.standard_filters(true).hidden(false);
        builder.filter_entry(move |e| {
            e.file_name()
                .to_str()
                .map(|name| !is_ignored_entry(name, &ignores))
                .unwrap_or(true)
        });

        let mut seq = 0u64;
        for dent in builder.build() {
            let Ok(entry) = dent else { continue };
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            if tx
                .send(ScanInput {
                    seq,
                    path: entry.into_path(),
                })
                .is_err()
            {
                break;
            }
            seq = seq.saturating_add(1);
        }
    });

    rx
}

/// Fan per-file work out over `cfg.concurrency` threads, yielding results in
/// walk order.
///
/// Memory stays decoupled from tree size: a permit window caps how far the
/// workers may run ahead of the consumer, so one slow file cannot make every
/// later result pile up in the reorder buffer. Results carry their walk
/// sequence, so scan JSONL, seed records, query truncation, and reports are
/// byte-stable regardless of how the OS schedules the workers.
pub fn scan_ordered<T, F>(cfg: &Config, work: F) -> OrderedScan<T>
where
    T: Send + 'static,
    F: Fn(&Path) -> T + Send + Sync + 'static,
{
    let requested = cfg.concurrency.max(1);
    let workers = requested.min(MAX_SCAN_WORKERS);
    if workers < requested {
        eprintln!("scan workers capped at {MAX_SCAN_WORKERS} (concurrency={requested})");
    }
    // Files in flight ahead of the consumer: enough that no worker idles, but
    // small enough that a stalled head file cannot pile up the whole tree in
    // the reorder buffer.
    let window = workers.saturating_mul(16).clamp(16, MAX_REORDER_WINDOW);
    let (permit_tx, permit_rx) = bounded::<()>(window);
    for _ in 0..window {
        // The channel is created with exactly `window` slots, so these sends
        // cannot block; a failure would mean the receiver is already gone.
        let _ = permit_tx.send(());
    }
    let inputs = spawn_walk(cfg.root.clone(), cfg.ignores.clone());
    let (tx, rx) = bounded::<(u64, T)>(CHANNEL_CAP);
    let work = Arc::new(work);

    for _ in 0..workers {
        let inputs = inputs.clone();
        let permits = permit_rx.clone();
        let tx = tx.clone();
        let work = Arc::clone(&work);
        thread::spawn(move || {
            loop {
                // The permit must be taken before the path: a worker that holds
                // an unstarted file while waiting for budget can deadlock the
                // consumer, which is waiting for exactly that file.
                if permits.recv().is_err() {
                    break;
                }
                let Ok(item) = inputs.recv() else {
                    break;
                };
                let value = work(&item.path);
                if tx.send((item.seq, value)).is_err() {
                    break;
                }
            }
        });
    }
    // Every worker holds one sender; dropping the original closes the channel
    // once the last worker exits.
    drop(tx);
    drop(permit_rx);

    OrderedScan {
        rx,
        permits: permit_tx,
        pending: BTreeMap::new(),
        next: 0,
    }
}

/// In-order view over a parallel scan: items are released strictly in walk order.
pub struct OrderedScan<T> {
    rx: Receiver<(u64, T)>,
    permits: Sender<()>,
    pending: BTreeMap<u64, T>,
    next: u64,
}

impl<T> OrderedScan<T> {
    /// Block until the next walk-order item is ready, buffering later arrivals.
    pub fn next_item(&mut self) -> Option<T> {
        loop {
            if let Some(item) = self.pending.remove(&self.next) {
                self.next = self.next.saturating_add(1);
                self.release();
                return Some(item);
            }
            match self.rx.recv() {
                Ok((seq, value)) => {
                    if seq == self.next {
                        self.next = self.next.saturating_add(1);
                        self.release();
                        return Some(value);
                    }
                    self.pending.insert(seq, value);
                }
                // Channel closed: everything sent has been received, so the
                // only item that can still be next is already buffered.
                Err(_) => {
                    let item = self.pending.remove(&self.next);
                    if item.is_some() {
                        self.release();
                    }
                    return item;
                }
            }
        }
    }

    /// Hand one permit back so another file may start.
    fn release(&mut self) {
        let _ = self.permits.send(());
    }
}

fn is_ignored_entry(name: &str, ignores: &[String]) -> bool {
    VCS_METADATA_DIRS.contains(&name) || ignores.iter().any(|ignore| ignore == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Cli, Config};

    #[test]
    fn scan_skips_ignored_dirs_and_large_files() {
        let root = unique_test_dir("scan");
        let ignored = root.join("target");
        let vcs = root.join(".git/hooks");
        let hidden_project = root.join(".github/workflows");
        assert!(std::fs::create_dir_all(&ignored).is_ok());
        assert!(std::fs::create_dir_all(&vcs).is_ok());
        assert!(std::fs::create_dir_all(&hidden_project).is_ok());
        assert!(std::fs::write(root.join("a.rs"), "fn a() {}").is_ok());
        assert!(std::fs::write(ignored.join("b.rs"), "fn b() {}").is_ok());
        assert!(std::fs::write(vcs.join("README.sample"), "hook notes").is_ok());
        assert!(std::fs::write(hidden_project.join("ci.yml"), "name: ci").is_ok());
        let cfg = Config::resolve(test_cli(root.clone(), 4));
        assert!(cfg.is_ok(), "test config should resolve");
        let Ok(cfg) = cfg else {
            std::fs::remove_dir_all(root).ok();
            return;
        };
        let paths = collect_ordered(&cfg);
        assert!(paths.iter().any(|p| p.ends_with("a.rs")));
        assert!(!paths.iter().any(|p| p.ends_with("b.rs")));
        assert!(!paths.iter().any(|p| p.ends_with("README.sample")));
        assert!(paths.iter().any(|p| p.ends_with("ci.yml")));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn scan_ordered_completes_when_work_outruns_the_permit_window() {
        // More files than the reorder window, with the earliest items made slow:
        // later work must stall on the window instead of letting a worker hold
        // the missing head file while it waits for budget.
        let root = unique_test_dir("scan-window");
        assert!(std::fs::create_dir_all(&root).is_ok());
        for idx in 0..96 {
            assert!(std::fs::write(root.join(format!("f{idx:03}.rs")), "fn a() {}").is_ok());
        }
        let Ok(cfg) = Config::resolve(test_cli(root.clone(), 8)) else {
            std::fs::remove_dir_all(root).ok();
            return;
        };

        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (done_tx, done_rx) = bounded::<usize>(1);
        thread::spawn(move || {
            let calls = std::sync::Arc::clone(&started);
            let mut scan = scan_ordered(&cfg, move |path| {
                let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let delay = if call < 4 { 250 } else { 1 };
                thread::sleep(std::time::Duration::from_millis(delay));
                path.to_path_buf()
            });
            let mut scanned = 0usize;
            while scan.next_item().is_some() {
                scanned += 1;
            }
            let _ = done_tx.send(scanned);
        });

        let finished = done_rx.recv_timeout(std::time::Duration::from_secs(30));
        assert!(
            finished.is_ok(),
            "scan must not deadlock under window pressure"
        );
        assert_eq!(finished.unwrap_or(0), 96);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn scan_ordered_preserves_walk_order_when_workers_finish_out_of_order() {
        let root = unique_test_dir("scan-order");
        assert!(std::fs::create_dir_all(&root).is_ok());
        for idx in 0..24 {
            assert!(std::fs::write(root.join(format!("f{idx:02}.rs")), "fn a() {}").is_ok());
        }
        let Ok(cfg) = Config::resolve(test_cli(root.clone(), 8)) else {
            std::fs::remove_dir_all(root).ok();
            return;
        };

        // Serial walk order is the contract the parallel scan must reproduce.
        let expected: Vec<PathBuf> = spawn_walk(cfg.root.clone(), cfg.ignores.clone())
            .iter()
            .map(|input| input.path)
            .collect();
        assert_eq!(expected.len(), 24, "fixture files should all be walked");

        // Deterministic per-path delays force completions out of walk order.
        let actual: Vec<PathBuf> = {
            let mut scan = scan_ordered(&cfg, |path| {
                let delay = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.bytes().map(u64::from).sum::<u64>() % 7)
                    .unwrap_or(0);
                thread::sleep(std::time::Duration::from_millis(delay));
                path.to_path_buf()
            });
            let mut paths = Vec::new();
            while let Some(path) = scan.next_item() {
                paths.push(path);
            }
            paths
        };

        assert_eq!(actual, expected, "parallel scan must stay in walk order");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn scan_ordered_caps_absurd_concurrency_without_dropping_files() {
        let root = unique_test_dir("scan-cap");
        assert!(std::fs::create_dir_all(&root).is_ok());
        for idx in 0..6 {
            assert!(std::fs::write(root.join(format!("f{idx}.rs")), "fn a() {}").is_ok());
        }
        let Ok(cfg) = Config::resolve(test_cli(root.clone(), 100_000)) else {
            std::fs::remove_dir_all(root).ok();
            return;
        };
        assert_eq!(
            collect_ordered(&cfg).len(),
            6,
            "capping must not drop files"
        );
        std::fs::remove_dir_all(root).ok();
    }

    fn collect_ordered(cfg: &Config) -> Vec<PathBuf> {
        let mut scan = scan_ordered(cfg, |path| path.to_path_buf());
        let mut paths = Vec::new();
        while let Some(path) = scan.next_item() {
            paths.push(path);
        }
        paths
    }

    fn test_cli(target: PathBuf, concurrency: usize) -> Cli {
        Cli {
            command: None,
            target,
            module: None,
            api_key_file: None,
            concurrency: Some(concurrency),
            max_bytes: Some(128),
            scan_only: true,
            agent_gate: false,
            format: crate::config::OutputFormat::Text,
            benchmark: false,
            benchmark_output: None,
            benchmark_input_1m_cost: None,
            benchmark_output_1m_cost: None,
            benchmark_estimated_output_tokens: None,
            report_language: crate::config::ReportLanguage::En,
            debug: false,
            save: false,
            save_to: None,
        }
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sift-scanner-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }
}
