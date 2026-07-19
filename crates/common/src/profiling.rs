use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct ProfileContext {
    pub operation: String,
    pub n: usize,
    pub m: usize,
    pub sample: usize,
    pub run_kind: String,
}

#[derive(Clone, Debug)]
pub struct PhaseRecord {
    pub context: ProfileContext,
    pub component: String,
    pub phase: String,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct MetricRecord {
    pub context: ProfileContext,
    pub component: String,
    pub metric: String,
    pub value: u64,
    pub unit: String,
}

thread_local! {
    static CONTEXT: RefCell<ProfileContext> = RefCell::new(ProfileContext::default());
}

static PHASES: OnceLock<Mutex<Vec<PhaseRecord>>> = OnceLock::new();
static METRICS: OnceLock<Mutex<Vec<MetricRecord>>> = OnceLock::new();
static PROBE_OVERHEAD_NS: AtomicU64 = AtomicU64::new(0);

pub fn enabled() -> bool {
    std::env::var("POA_SP1_PROFILE")
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

pub struct ContextGuard(ProfileContext);

impl Drop for ContextGuard {
    fn drop(&mut self) {
        let previous = self.0.clone();
        CONTEXT.with(|slot| *slot.borrow_mut() = previous);
    }
}

pub fn enter_context(context: ProfileContext) -> ContextGuard {
    let previous = CONTEXT.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), context));
    ContextGuard(previous)
}

fn current_context() -> ProfileContext {
    CONTEXT.with(|slot| slot.borrow().clone())
}

pub struct PhaseTimer {
    component: &'static str,
    phase: &'static str,
    start: Option<Instant>,
}

impl PhaseTimer {
    pub fn start(component: &'static str, phase: &'static str) -> Self {
        Self {
            component,
            phase,
            start: enabled().then(Instant::now),
        }
    }

    pub fn finish(mut self) -> Duration {
        let elapsed = self
            .start
            .take()
            .map(|start| start.elapsed())
            .unwrap_or(Duration::ZERO);
        if enabled() {
            record_phase(self.component, self.phase, elapsed);
        }
        elapsed
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        if let Some(start) = self.start.take() {
            record_phase(self.component, self.phase, start.elapsed());
        }
    }
}

pub fn record_phase(component: impl Into<String>, phase: impl Into<String>, elapsed: Duration) {
    if !enabled() {
        return;
    }
    PHASES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("phase profile mutex poisoned")
        .push(PhaseRecord {
            context: current_context(),
            component: component.into(),
            phase: phase.into(),
            elapsed,
        });
}

pub fn record_metric(
    component: impl Into<String>,
    metric: impl Into<String>,
    value: u64,
    unit: impl Into<String>,
) {
    if !enabled() {
        return;
    }
    METRICS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("metric profile mutex poisoned")
        .push(MetricRecord {
            context: current_context(),
            component: component.into(),
            metric: metric.into(),
            value,
            unit: unit.into(),
        });
}

pub fn add_probe_overhead(elapsed: Duration) {
    let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
    PROBE_OVERHEAD_NS.fetch_add(nanos, Ordering::Relaxed);
}

pub fn probe_overhead() -> Duration {
    Duration::from_nanos(PROBE_OVERHEAD_NS.load(Ordering::Relaxed))
}

pub fn write_reports(output_dir: &Path) -> Result<(), String> {
    if !enabled() {
        return Ok(());
    }
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create profile directory {}: {err}", output_dir.display()))?;
    let phases = PHASES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .map_err(|_| "phase profile mutex poisoned".to_string())?
        .clone();
    let metrics = METRICS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .map_err(|_| "metric profile mutex poisoned".to_string())?
        .clone();

    let mut phase_csv =
        String::from("operation,n,m,sample,run_kind,component,phase,elapsed_ns,elapsed_ms\n");
    for record in &phases {
        phase_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{:.3}\n",
            csv(&record.context.operation),
            record.context.n,
            record.context.m,
            record.context.sample,
            csv(&record.context.run_kind),
            csv(&record.component),
            csv(&record.phase),
            record.elapsed.as_nanos(),
            record.elapsed.as_secs_f64() * 1000.0,
        ));
    }
    fs::write(output_dir.join("phase-times.csv"), phase_csv)
        .map_err(|err| format!("write phase-times.csv: {err}"))?;

    let mut metric_csv =
        String::from("operation,n,m,sample,run_kind,component,metric,value,unit\n");
    for record in &metrics {
        metric_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            csv(&record.context.operation),
            record.context.n,
            record.context.m,
            record.context.sample,
            csv(&record.context.run_kind),
            csv(&record.component),
            csv(&record.metric),
            record.value,
            csv(&record.unit),
        ));
    }
    fs::write(output_dir.join("guest-metrics.csv"), metric_csv)
        .map_err(|err| format!("write guest-metrics.csv: {err}"))?;

    let mut readable = String::from(
        "# SP1 phase profile\n\n\
         `sp1-execute` is an extra diagnostic probe and is excluded from the benchmark prover \
         total. Cycle markers are enabled only for that probe; the real proof run has them \
         disabled. Use the normal benchmark mode for publication totals.\n\n",
    );
    for record in &phases {
        readable.push_str(&format!(
            "- {} n={} m={} sample={} {} :: {} / {} = {} ({:.3} ms)\n",
            record.context.operation,
            record.context.n,
            record.context.m,
            record.context.sample,
            record.context.run_kind,
            record.component,
            record.phase,
            human_duration(record.elapsed),
            record.elapsed.as_secs_f64() * 1000.0,
        ));
    }
    readable.push_str("\n## Guest metrics\n\n");
    for record in &metrics {
        readable.push_str(&format!(
            "- {} n={} sample={} {} :: {} / {} = {} {}\n",
            record.context.operation,
            record.context.n,
            record.context.sample,
            record.context.run_kind,
            record.component,
            record.metric,
            record.value,
            record.unit,
        ));
    }
    fs::write(output_dir.join("profile.md"), readable)
        .map_err(|err| format!("write profile.md: {err}"))
}

fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds >= 60.0 {
        format!("{:.2} min", seconds / 60.0)
    } else if seconds >= 1.0 {
        format!("{seconds:.3} s")
    } else if seconds >= 0.001 {
        format!("{:.3} ms", seconds * 1_000.0)
    } else {
        format!("{:.3} us", seconds * 1_000_000.0)
    }
}

fn csv(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
