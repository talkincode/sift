//! Install-surface diff.
//!
//! Two trees are reduced to the same capability entries `sift surface` emits,
//! then compared on `(capability, path, evidence text)`. Line numbers are
//! reported per side but are not part of the key, so a version bump that only
//! moves code around does not show up as a change. When every entry of a tree
//! shares one leading path component (`package/`, `foo-1.2.3/`), that wrapper
//! is stripped so two extracted distributions compare directly.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::ExitCode;

use serde::Serialize;

use crate::config::{Config, DiffCli, OutputFormat};
use crate::surface::{self, CAPABILITIES, SurfaceEntry};

const DIFF_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct SideSummary {
    root: String,
    entries: usize,
}

#[derive(Serialize)]
struct DiffReport<'a> {
    schema_version: u32,
    a: SideSummary,
    b: SideSummary,
    added: usize,
    removed: usize,
    added_entries: &'a [SurfaceEntry],
    removed_entries: &'a [SurfaceEntry],
}

/// Exit 0 when the install surface is identical, 1 when it changed, 2 on usage
/// or configuration errors.
pub fn run_diff(cli: DiffCli) -> ExitCode {
    if let Some(bad) = cli
        .capability
        .iter()
        .find(|name| !CAPABILITIES.contains(&name.as_str()))
    {
        eprintln!(
            "diff error: unknown capability {bad:?} (known: {})",
            CAPABILITIES.join(", ")
        );
        return ExitCode::from(2);
    }
    let max_bytes = cli.max_bytes.unwrap_or(512 * 1024);
    let (cfg_a, cfg_b) = match (
        Config::for_reader(cli.a.clone(), None, max_bytes),
        Config::for_reader(cli.b.clone(), None, max_bytes),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("diff error: {e}");
            return ExitCode::from(2);
        }
    };

    let (entries_a, coverage_a) = surface::collect(&cfg_a);
    let (entries_b, coverage_b) = surface::collect(&cfg_b);
    let scopes = match surface::parse_scopes(&cli.scope) {
        Ok(scopes) => scopes,
        Err(e) => {
            eprintln!("diff error: {e}");
            return ExitCode::from(2);
        }
    };
    let filter = |entries: Vec<SurfaceEntry>| -> Vec<SurfaceEntry> {
        entries
            .into_iter()
            .filter(|entry| scopes.includes(entry.scope))
            .filter(|entry| {
                cli.capability.is_empty() || cli.capability.iter().any(|c| c == entry.capability)
            })
            .collect()
    };
    let entries_a = normalise_paths(filter(entries_a));
    let entries_b = normalise_paths(filter(entries_b));

    let keys_a = key_set(&entries_a);
    let keys_b = key_set(&entries_b);
    let removed: Vec<SurfaceEntry> = pick(&entries_a, &keys_b);
    let added: Vec<SurfaceEntry> = pick(&entries_b, &keys_a);

    if cli.debug {
        eprintln!(
            "debug: a scanned={} unsupported={} parse_failed={} | b scanned={} unsupported={} parse_failed={}",
            coverage_a.scanned_files,
            coverage_a.unsupported_files,
            coverage_a.parse_failed,
            coverage_b.scanned_files,
            coverage_b.unsupported_files,
            coverage_b.parse_failed
        );
    }

    let mut out = std::io::stdout().lock();
    let write_failed = match cli.format {
        OutputFormat::Text => write_text(
            &mut out, &cfg_a, &cfg_b, &entries_a, &entries_b, &added, &removed,
        ),
        OutputFormat::Json => write_json(
            &mut out, &cfg_a, &cfg_b, &entries_a, &entries_b, &added, &removed,
        ),
    }
    .is_err();
    if write_failed {
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "diff complete: a_entries={} b_entries={} added={} removed={}",
        entries_a.len(),
        entries_b.len(),
        added.len(),
        removed.len()
    );

    if added.is_empty() && removed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Strip a shared leading path component so `package/` and `foo-1.2.3/`
/// wrappers do not make every entry look changed.
fn normalise_paths(entries: Vec<SurfaceEntry>) -> Vec<SurfaceEntry> {
    let Some(wrapper) = shared_wrapper(&entries) else {
        return entries;
    };
    entries
        .into_iter()
        .map(|mut entry| {
            if let Some(rest) = entry.path.strip_prefix(&wrapper) {
                entry.path = rest.to_string();
            }
            entry
        })
        .collect()
}

fn shared_wrapper(entries: &[SurfaceEntry]) -> Option<String> {
    let first = entries.first()?.path.split('/').next()?;
    if first.is_empty() || !entries.iter().all(|entry| entry.path.starts_with(first)) {
        return None;
    }
    // Only strip when the component is a real directory prefix on every entry.
    if entries
        .iter()
        .all(|entry| entry.path.len() > first.len() && entry.path.as_bytes()[first.len()] == b'/')
    {
        Some(format!("{first}/"))
    } else {
        None
    }
}

type Key = (String, String, String);

fn key_of(entry: &SurfaceEntry) -> Key {
    (
        entry.capability.to_string(),
        entry.path.clone(),
        entry.text.trim().to_string(),
    )
}

fn key_set(entries: &[SurfaceEntry]) -> BTreeSet<Key> {
    entries.iter().map(key_of).collect()
}

fn pick(entries: &[SurfaceEntry], other: &BTreeSet<Key>) -> Vec<SurfaceEntry> {
    let mut seen: BTreeMap<Key, SurfaceEntry> = BTreeMap::new();
    for entry in entries {
        let key = key_of(entry);
        if other.contains(&key) {
            continue;
        }
        seen.entry(key).or_insert_with(|| entry.clone());
    }
    let mut out: Vec<SurfaceEntry> = seen.into_values().collect();
    out.sort_by(|a, b| (a.capability, &a.path, &a.text).cmp(&(b.capability, &b.path, &b.text)));
    out
}

fn counts(entries: &[SurfaceEntry]) -> BTreeMap<&'static str, usize> {
    let mut map = BTreeMap::new();
    for capability in CAPABILITIES {
        let n = entries
            .iter()
            .filter(|entry| entry.capability == capability)
            .count();
        if n > 0 {
            map.insert(capability, n);
        }
    }
    map
}

fn render_entry(entry: &SurfaceEntry) -> String {
    match entry.line {
        Some(line) => format!(
            "{}:{}: {} {} {} {}: {}",
            entry.path,
            line,
            entry.confidence,
            entry.trigger,
            entry.evidence,
            entry.scope,
            entry.text
        ),
        None => format!(
            "{}:-: {} {} {} {}: {}",
            entry.path, entry.confidence, entry.trigger, entry.evidence, entry.scope, entry.text
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_text(
    out: &mut impl Write,
    cfg_a: &Config,
    cfg_b: &Config,
    entries_a: &[SurfaceEntry],
    entries_b: &[SurfaceEntry],
    added: &[SurfaceEntry],
    removed: &[SurfaceEntry],
) -> std::io::Result<()> {
    writeln!(out, "INSTALL_SURFACE_DIFF")?;
    writeln!(
        out,
        "- a: {} ({} entries)",
        cfg_a.root.display(),
        entries_a.len()
    )?;
    writeln!(
        out,
        "- b: {} ({} entries)",
        cfg_b.root.display(),
        entries_b.len()
    )?;
    writeln!(out, "- added: {} removed: {}", added.len(), removed.len())?;
    writeln!(out, "- added_by_capability: {:?}", counts(added))?;
    writeln!(out, "- removed_by_capability: {:?}", counts(removed))?;
    if !added.is_empty() {
        writeln!(out, "\n== added ==")?;
        for entry in added {
            writeln!(out, "+ {}", render_entry(entry))?;
        }
    }
    if !removed.is_empty() {
        writeln!(out, "\n== removed ==")?;
        for entry in removed {
            writeln!(out, "- {}", render_entry(entry))?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_json(
    out: &mut impl Write,
    cfg_a: &Config,
    cfg_b: &Config,
    entries_a: &[SurfaceEntry],
    entries_b: &[SurfaceEntry],
    added: &[SurfaceEntry],
    removed: &[SurfaceEntry],
) -> std::io::Result<()> {
    let report = DiffReport {
        schema_version: DIFF_SCHEMA_VERSION,
        a: SideSummary {
            root: cfg_a.root.display().to_string(),
            entries: entries_a.len(),
        },
        b: SideSummary {
            root: cfg_b.root.display().to_string(),
            entries: entries_b.len(),
        },
        added: added.len(),
        removed: removed.len(),
        added_entries: added,
        removed_entries: removed,
    };
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    writeln!(out, "{json}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(capability: &'static str, path: &str, text: &str) -> SurfaceEntry {
        SurfaceEntry {
            capability,
            trigger: "source",
            confidence: "strong",
            evidence: "test",
            path: path.to_string(),
            line: Some(1),
            scope: "production",
            text: text.to_string(),
        }
    }

    #[test]
    fn shared_wrapper_is_stripped_from_both_sides() {
        let entries = vec![
            entry("network", "foo-1.2.3/setup.py", "url"),
            entry("execute", "foo-1.2.3/bin/run.sh", "x"),
        ];
        let normalised = normalise_paths(entries);
        assert_eq!(normalised[0].path, "setup.py");
        assert_eq!(normalised[1].path, "bin/run.sh");
    }

    #[test]
    fn repo_layout_keeps_paths() {
        let entries = vec![
            entry("network", "src/a.py", "url"),
            entry("execute", "README.md", "x"),
        ];
        let normalised = normalise_paths(entries);
        assert_eq!(normalised[0].path, "src/a.py");
        assert_eq!(normalised[1].path, "README.md");
    }

    #[test]
    fn added_and_removed_are_keyed_on_capability_path_text() {
        let a = vec![entry("network", "package.json", "curl x")];
        let b = vec![
            entry("network", "package.json", "curl x"),
            entry("execute", "package.json", "sh -c y"),
        ];
        let keys_a = key_set(&a);
        let keys_b = key_set(&b);
        let added = pick(&b, &keys_a);
        let removed = pick(&a, &keys_b);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].capability, "execute");
        assert!(removed.is_empty());
    }

    #[test]
    fn line_moves_do_not_count_as_changes() {
        let mut a = entry("network", "setup.py", "requests.get(url)");
        a.line = Some(10);
        let mut b = a.clone();
        b.line = Some(42);
        assert!(key_set(&[a]) == key_set(&[b]));
    }
}
