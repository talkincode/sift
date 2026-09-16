use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::ReportLanguage;
use crate::model::{CallError, ModelClient};
use crate::skills::Skill;

/// Widest Reduce fan-out sift will open on its own. The large model is the
/// expensive resource, so past this point extra concurrency mostly buys rate
/// limits; callers with a lower `concurrency` get their value unchanged.
pub const MAX_REDUCE_PARALLEL: usize = 8;

/// Abstraction over large-model completion so tests can inject deterministic fakes.
///
/// `&self` plus `Send + Sync` lets one client serve several Reduce batches at
/// once; the shared breaker inside `ModelClient` stops them together.
pub trait Completer: Send + Sync {
    fn ask(&self, prompt: &str) -> Result<String, CallError>;
}

impl Completer for ModelClient {
    fn ask(&self, prompt: &str) -> Result<String, CallError> {
        self.complete(prompt)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Final(String),
    Partial(String),
}

pub struct ReAct {
    max_steps: u32,
    max_errors: u32,
    report_language: ReportLanguage,
}

impl Default for ReAct {
    fn default() -> Self {
        Self {
            max_steps: 8,
            max_errors: 3,
            report_language: ReportLanguage::En,
        }
    }
}

impl ReAct {
    #[cfg(test)]
    pub fn new(max_steps: u32, max_errors: u32) -> Self {
        Self {
            max_steps: max_steps.max(1),
            max_errors: max_errors.max(1),
            report_language: ReportLanguage::En,
        }
    }

    pub fn with_language(report_language: ReportLanguage) -> Self {
        Self {
            report_language,
            ..Self::default()
        }
    }

    /// Run until <FINAL>; bounded steps/errors return a partial result instead of looping.
    ///
    /// The loop opens on the deterministic coarse-filter observation, not on the
    /// raw seed. The seed turn existed only so the model could ask for a filter
    /// this loop runs locally anyway, and it cost ~92% of the Reduce input
    /// bytes; the model still sees the same authoritative findings, one request
    /// per batch instead of two.
    pub fn run<M: Completer + ?Sized>(&self, m: &M, seed: &str) -> Outcome {
        let observation = Skill::CoarseFilter.run_with_language(seed, self.report_language);
        let mut last = observation.clone();
        let mut prompt = observation_prompt(&observation, self.report_language);
        let mut errors = 0u32;
        for _ in 0..self.max_steps {
            let reply = match m.ask(&prompt) {
                Ok(r) => r,
                Err(e) => return Outcome::Partial(partial(&last, &e.label())),
            };
            if let Some(f) = extract(&reply, "FINAL") {
                return Outcome::Final(f);
            }
            match extract(&reply, "TOOL_CALL").and_then(|j| parse_call(&j)) {
                Some((skill, input)) => {
                    let tool_input = resolve_tool_input(&input, seed);
                    let obs = skill.run_with_language(tool_input, self.report_language);
                    last = obs.clone();
                    prompt = observation_prompt(&obs, self.report_language);
                }
                None => {
                    errors += 1;
                    if errors >= self.max_errors {
                        return Outcome::Partial(partial(&last, "format_errors_exhausted"));
                    }
                    prompt =
                        "Invalid format. Return <TOOL_CALL>{json}</TOOL_CALL> or <FINAL>.".into();
                }
            }
        }
        Outcome::Partial(partial(&last, "step_cap_reached"))
    }
}

/// Run independent Reduce batches across at most `max_parallel` workers.
///
/// Batches are independent evidence, so they may overlap; the returned list is
/// ordered by batch index no matter which batch finishes first, which keeps the
/// merged report byte-stable. Progress is written to stderr because a full
/// audit can queue dozens of batches.
pub fn run_batches<C: Completer + ?Sized>(
    completer: &C,
    batches: &[String],
    language: ReportLanguage,
    max_parallel: usize,
) -> Vec<(usize, Outcome)> {
    let workers = max_parallel.max(1).min(batches.len());
    let mut results: Vec<(usize, Outcome)> = Vec::with_capacity(batches.len());
    if workers <= 1 {
        for (idx, seed) in batches.iter().enumerate() {
            log_batch_started(idx, batches.len(), seed.len());
            let outcome = ReAct::with_language(language).run(completer, seed);
            log_batch_outcome(idx, batches.len(), &outcome);
            results.push((idx, outcome));
        }
        return results;
    }

    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Outcome>>> = batches.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    let Some(seed) = batches.get(idx) else {
                        break;
                    };
                    log_batch_started(idx, batches.len(), seed.len());
                    let outcome = ReAct::with_language(language).run(completer, seed);
                    log_batch_outcome(idx, batches.len(), &outcome);
                    if let Some(slot) = slots.get(idx)
                        && let Ok(mut slot) = slot.lock()
                    {
                        *slot = Some(outcome);
                    }
                }
            });
        }
    });

    results.extend(slots.into_iter().enumerate().filter_map(|(idx, slot)| {
        slot.into_inner()
            .ok()
            .flatten()
            .map(|outcome| (idx, outcome))
    }));
    debug_assert_eq!(
        results.len(),
        batches.len(),
        "every Reduce batch must report an outcome"
    );
    results
}

fn log_batch_started(idx: usize, total: usize, evidence_bytes: usize) {
    // The batch's evidence size, not the prompt size: the loop sends the
    // deterministic observation built from it, and never the raw seed.
    eprintln!(
        "large-model Reduce batch {}/{} started, evidence_bytes: {evidence_bytes}",
        idx + 1,
        total
    );
}

fn log_batch_outcome(idx: usize, total: usize, outcome: &Outcome) {
    match outcome {
        Outcome::Final(_) => eprintln!("large-model Reduce batch {}/{} complete", idx + 1, total),
        Outcome::Partial(report) => {
            eprintln!(
                "partial result in Reduce batch {}/{}: {report}",
                idx + 1,
                total
            );
        }
    }
}

/// Prompt bytes a Reduce run costs, before any model is called.
///
/// The loop opens on the deterministic coarse-filter observation, so one batch
/// is one request. A model that asks for extra tool calls sends more; nothing
/// sends the raw seed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PlannedPrompts {
    /// Observation prompts, one per batch.
    pub observation_bytes: usize,
    /// Requests the converging path costs: one per batch.
    pub requests: usize,
}

impl PlannedPrompts {
    /// Bytes the converging path sends. A model that answers `<FINAL>` on the
    /// first turn sends exactly this; extra tool calls add more.
    pub fn converging_bytes(&self) -> usize {
        self.observation_bytes
    }
}

/// Count the prompts the Reduce stage would send for `batches`.
///
/// Runs the same deterministic coarse filter the live loop runs locally before
/// its first request. No network access.
pub fn planned_prompts(batches: &[String], language: ReportLanguage) -> PlannedPrompts {
    let mut planned = PlannedPrompts {
        requests: batches.len(),
        ..PlannedPrompts::default()
    };
    for seed in batches {
        let observation = Skill::CoarseFilter.run_with_language(seed, language);
        planned.observation_bytes = planned
            .observation_bytes
            .saturating_add(observation_prompt(&observation, language).len());
    }
    planned
}

fn observation_prompt(obs: &str, report_language: ReportLanguage) -> String {
    format!(
        "OBSERVATION:\n{obs}\n\
         The coarse_filter severities and scopes above are authoritative; keep them. {rubric}\n\
         Next return only <TOOL_CALL>{{\"skill\":\"converge\",\"input\":\"the OBSERVATION text above or $SEED\"}}</TOOL_CALL> or <FINAL>Markdown risk ledger</FINAL>. {lang}",
        rubric = SCOPE_RUBRIC,
        lang = report_language.prompt_instruction()
    )
}

/// Scope discipline injected into every Reduce prompt so the model never
/// inflates synthetic samples or intra-crate references into production risk.
const SCOPE_RUBRIC: &str = "Scope rules: every finding carries a scope. \
    Production source and CI release paths keep full severity. \
    Test code and synthetic test fixtures (paths under tests/, fixtures/, or testdata/) \
    must never be reported as production vulnerabilities; label them as test or fixture samples. \
    Documentation install instructions are real but reported as docs scope. \
    Do not promote intra-crate references (crate::, super::) to risks. \
    Preserve the deterministic coarse_filter severities and scopes; never invent a higher severity. \
    When evidence is insufficient, mark the item NEEDS_REVIEW instead of High.";

fn resolve_tool_input<'a>(input: &'a str, seed: &'a str) -> &'a str {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed == "$SEED" {
        seed
    } else {
        input
    }
}

fn partial(last: &str, reason: &str) -> String {
    format!("[TRUNCATED: {reason}] {last}")
}

/// Extract <TAG>...</TAG> content.
fn extract(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let a = s.find(&open)? + open.len();
    let b = s[a..].find(&close)? + a;
    Some(s[a..b].trim().to_string())
}

/// Parse {"skill":..,"input":..}; bad JSON or unknown skills count as format failures.
fn parse_call(json: &str) -> Option<(Skill, String)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let skill = Skill::from_name(v.get("skill")?.as_str()?)?;
    let input = v.get("input").and_then(|i| i.as_str()).unwrap_or("");
    Some((skill, input.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU8, AtomicUsize};
    use std::time::{Duration, Instant};

    struct Fake {
        seq: Mutex<Vec<Result<String, CallError>>>,
    }
    impl Fake {
        fn new(mut v: Vec<Result<String, CallError>>) -> Self {
            v.reverse();
            Self { seq: Mutex::new(v) }
        }
    }
    impl Completer for Fake {
        fn ask(&self, _: &str) -> Result<String, CallError> {
            let Ok(mut seq) = self.seq.lock() else {
                return Err(CallError::Network);
            };
            seq.pop().unwrap_or(Err(CallError::Network))
        }
    }

    #[test]
    fn tool_call_then_final_converges() {
        let f = Fake::new(vec![
            Ok("<TOOL_CALL>{\"skill\":\"coarse_filter\",\"input\":\"x\"}</TOOL_CALL>".into()),
            Ok("<FINAL>risk: none</FINAL>".into()),
        ]);
        assert_eq!(
            ReAct::default().run(&f, "seed"),
            Outcome::Final("risk: none".into())
        );
    }

    #[test]
    fn prompts_carry_scope_rubric() {
        let obs = observation_prompt("OBS", ReportLanguage::En);
        assert!(obs.contains("Scope rules:"));
        assert!(obs.contains("synthetic test fixtures"));
        assert!(obs.contains("authoritative"));
        assert!(obs.contains("<FINAL>"));
    }

    /// Records every prompt the loop sends, so tests can inspect what a model
    /// would actually receive.
    struct Recorder {
        prompts: Mutex<Vec<String>>,
        reply: String,
    }

    impl Recorder {
        fn new(reply: &str) -> Self {
            Self {
                prompts: Mutex::new(Vec::new()),
                reply: reply.to_string(),
            }
        }
        fn first_prompt(&self) -> String {
            self.prompts
                .lock()
                .ok()
                .and_then(|prompts| prompts.first().cloned())
                .unwrap_or_default()
        }
    }

    impl Completer for Recorder {
        fn ask(&self, prompt: &str) -> Result<String, CallError> {
            if let Ok(mut prompts) = self.prompts.lock() {
                prompts.push(prompt.to_string());
            }
            Ok(self.reply.clone())
        }
    }

    #[test]
    fn run_opens_on_the_deterministic_observation_not_the_seed() {
        // A realistic batch: mostly inert evidence plus one risky call.
        let seed = bulky_batch(0, 60_000);
        let recorder = Recorder::new("<FINAL>ok</FINAL>");

        assert_eq!(
            ReAct::default().run(&recorder, &seed),
            Outcome::Final("ok".into())
        );

        let prompts = recorder
            .prompts
            .lock()
            .map(|p| p.clone())
            .unwrap_or_default();
        assert_eq!(prompts.len(), 1, "one batch is one request now");
        let first = recorder.first_prompt();
        assert!(
            first.starts_with("OBSERVATION:"),
            "the loop must open on the deterministic findings"
        );
        assert!(
            first.contains("panic-edge"),
            "the findings must name the rule the evidence trips"
        );
        assert!(
            !first.contains("AST seed(JSONL)") && !first.contains("signatures"),
            "the raw seed must not be sent to the model"
        );
        assert!(
            first.len() * 5 < seed.len(),
            "the observation ({}) should be far smaller than the seed ({})",
            first.len(),
            seed.len()
        );
    }

    #[test]
    fn run_discloses_the_report_language_to_the_model() {
        let recorder = Recorder::new("<FINAL>ok</FINAL>");
        let _ = ReAct::with_language(ReportLanguage::Zh).run(&recorder, "seed");
        assert!(recorder.first_prompt().contains("Simplified Chinese"));
    }

    #[test]
    fn tool_calls_still_resolve_the_seed_alias() {
        // A model that asks for the filter again must not dead-end: the alias
        // resolves to the batch and feeds the observation back.
        struct Probe {
            step: AtomicU8,
        }
        impl Completer for Probe {
            fn ask(&self, prompt: &str) -> Result<String, CallError> {
                let step = self.step.fetch_add(1, Ordering::Relaxed);
                if step == 0 {
                    return Ok(
                        "<TOOL_CALL>{\"skill\":\"coarse_filter\",\"input\":\"$SEED\"}</TOOL_CALL>"
                            .into(),
                    );
                }
                assert!(prompt.contains("panic-edge"));
                Ok("<FINAL>ok</FINAL>".into())
            }
        }

        let seed =
            r#"{"path":"src/a.rs","locations":[{"kind":"call","line":2,"text":"x.unwrap"}]}"#;
        let p = Probe {
            step: AtomicU8::new(0),
        };
        assert_eq!(ReAct::new(2, 1).run(&p, seed), Outcome::Final("ok".into()));
    }

    #[test]
    fn unknown_skill_trips_to_partial() {
        let f = Fake::new(vec![Ok(
            "<TOOL_CALL>{\"skill\":\"rm\",\"input\":\"x\"}</TOOL_CALL>".into(),
        )]);
        assert!(matches!(ReAct::new(8, 1).run(&f, "s"), Outcome::Partial(_)));
    }

    #[test]
    fn bad_json_trips_to_partial() {
        let f = Fake::new(vec![Ok("<TOOL_CALL>not json</TOOL_CALL>".into())]);
        assert!(matches!(ReAct::new(8, 1).run(&f, "s"), Outcome::Partial(_)));
    }

    #[test]
    fn model_error_yields_partial() {
        let f = Fake::new(vec![Err(CallError::Tripped)]);
        assert!(matches!(ReAct::default().run(&f, "s"), Outcome::Partial(_)));
    }

    #[test]
    fn step_cap_returns_partial_not_hang() {
        let loop_call = "<TOOL_CALL>{\"skill\":\"converge\",\"input\":\"x\"}</TOOL_CALL>";
        let f = Fake::new((0..50).map(|_| Ok(loop_call.into())).collect());
        assert!(matches!(ReAct::new(3, 3).run(&f, "s"), Outcome::Partial(_)));
    }

    /// Answers each batch with its own index after a per-index delay, so tests can
    /// force completion order to differ from batch order.
    struct TimedFinal {
        calls: AtomicUsize,
        delay_ms: fn(usize) -> u64,
    }

    impl Completer for TimedFinal {
        fn ask(&self, prompt: &str) -> Result<String, CallError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let idx = batch_index(prompt);
            std::thread::sleep(Duration::from_millis((self.delay_ms)(idx)));
            Ok(format!("<FINAL>batch-{idx}</FINAL>"))
        }
    }

    /// Read the batch number back out of a prompt. Findings carry the record
    /// path, so the path is what survives into what the model receives.
    fn batch_index(prompt: &str) -> usize {
        let Some(rest) = prompt.split("src/batch_").nth(1) else {
            return 0;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().unwrap_or(0)
    }

    /// One record per batch, padded with inert evidence so realistic batch sizes
    /// can be exercised without inventing thousands of real symbols.
    fn bulky_batch(idx: usize, filler_bytes: usize) -> String {
        let filler = "z".repeat(filler_bytes);
        format!(
            r#"{{"path":"src/batch_{idx}.rs","signatures":["fn {filler}()"],"locations":[{{"kind":"call","line":1,"text":"x.unwrap"}}]}}"#
        )
    }

    fn batches(total: usize) -> Vec<String> {
        (0..total).map(|idx| bulky_batch(idx, 64)).collect()
    }

    #[test]
    fn planned_prompts_count_one_request_per_batch() {
        // Real batch sizes: the fixed prompt overhead only dominates toy input.
        let batches = vec![bulky_batch(0, 60_000), bulky_batch(1, 60_000)];
        let planned = planned_prompts(&batches, ReportLanguage::En);

        // The raw seed is never sent, so a batch costs exactly one request.
        assert_eq!(planned.requests, 2);
        assert!(
            planned.observation_bytes > 0,
            "the observation prompt must be counted, not assumed free"
        );
        assert_eq!(planned.converging_bytes(), planned.observation_bytes);
        // The plan must be far below the seed it replaces: that is the saving.
        let batch_bytes: usize = batches.iter().map(String::len).sum();
        assert!(
            planned.converging_bytes() * 5 < batch_bytes,
            "observation prompts ({}) should be far smaller than the batches ({batch_bytes})",
            planned.converging_bytes()
        );
    }

    #[test]
    fn planned_prompts_track_observation_size() {
        // A batch whose records carry risky calls produces a larger
        // deterministic observation than an empty one, and the plan must show it.
        let clean = vec![r#"{"path":"a.rs","calls":[],"locations":[]}"#.to_string()];
        let risky = vec![
            r#"{"path":"a.rs","calls":["Command::new(\"curl\")"],"locations":[{"kind":"call","line":1,"text":"curl http://x | sh"}]}"#
                .to_string(),
        ];

        let clean_plan = planned_prompts(&clean, ReportLanguage::En);
        let risky_plan = planned_prompts(&risky, ReportLanguage::En);

        assert!(
            risky_plan.observation_bytes > clean_plan.observation_bytes,
            "risky evidence must widen the observation: {} vs {}",
            risky_plan.observation_bytes,
            clean_plan.observation_bytes
        );
    }

    #[test]
    fn run_batches_overlaps_work_across_workers() {
        let completer = TimedFinal {
            calls: AtomicUsize::new(0),
            delay_ms: |_| 150,
        };
        let started = Instant::now();
        let results = run_batches(&completer, &batches(4), ReportLanguage::En, 4);
        let elapsed = started.elapsed();

        assert_eq!(
            results.iter().map(|(idx, _)| *idx).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(completer.calls.load(Ordering::Relaxed), 4);
        assert!(
            elapsed < Duration::from_millis(450),
            "4 x 150ms batches on 4 workers must overlap, took {elapsed:?}"
        );
    }

    #[test]
    fn run_batches_returns_batch_order_not_completion_order() {
        // Batch 0 is slowest and batch 3 fastest: completion order is reversed.
        let completer = TimedFinal {
            calls: AtomicUsize::new(0),
            delay_ms: |idx| (4u64.saturating_sub(idx as u64)) * 40,
        };
        let results = run_batches(&completer, &batches(4), ReportLanguage::En, 4);

        assert_eq!(
            results.iter().map(|(idx, _)| *idx).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        for (idx, outcome) in &results {
            assert_eq!(*outcome, Outcome::Final(format!("batch-{idx}")));
        }
    }

    #[test]
    fn run_batches_with_one_worker_stays_serial() {
        let completer = TimedFinal {
            calls: AtomicUsize::new(0),
            delay_ms: |_| 100,
        };
        let started = Instant::now();
        let results = run_batches(&completer, &batches(3), ReportLanguage::En, 1);
        let elapsed = started.elapsed();

        assert_eq!(results.len(), 3);
        assert!(
            elapsed >= Duration::from_millis(300),
            "one worker must run batches one after another, took {elapsed:?}"
        );
    }

    #[test]
    fn run_batches_reports_partial_without_dropping_other_batches() {
        struct Flaky {
            fail_at: usize,
        }
        impl Completer for Flaky {
            fn ask(&self, prompt: &str) -> Result<String, CallError> {
                let idx = batch_index(prompt);
                if idx == self.fail_at {
                    return Err(CallError::Network);
                }
                Ok(format!("<FINAL>batch-{idx}</FINAL>"))
            }
        }

        let results = run_batches(&Flaky { fail_at: 1 }, &batches(4), ReportLanguage::En, 4);
        assert_eq!(results.len(), 4);
        assert!(matches!(results[1].1, Outcome::Partial(_)));
        assert_eq!(results[0].1, Outcome::Final("batch-0".into()));
        assert_eq!(results[3].1, Outcome::Final("batch-3".into()));
    }
}
