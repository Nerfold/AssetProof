use std::time::Duration;

use sp1_sdk::ExecutionReport;

pub(crate) fn record_execution(guest: &str, elapsed: Duration, report: &ExecutionReport) {
    common::profiling::add_probe_overhead(elapsed);
    common::profiling::record_phase("sp1-execute", guest, elapsed);
    common::profiling::record_metric(
        guest,
        "total_instructions",
        report.total_instruction_count(),
        "instructions",
    );
    common::profiling::record_metric(
        guest,
        "total_syscalls",
        report.total_syscall_count(),
        "calls",
    );
    common::profiling::record_metric(
        guest,
        "touched_memory_addresses",
        report.touched_memory_addresses,
        "addresses",
    );
    if let Some(gas) = report.gas() {
        common::profiling::record_metric(guest, "sp1_gas", gas, "gas");
    }
    let mut stages = report.cycle_tracker.iter().collect::<Vec<_>>();
    stages.sort_by(|left, right| left.0.cmp(right.0));
    for (stage, cycles) in stages {
        common::profiling::record_metric(guest, format!("guest_stage.{stage}"), *cycles, "cycles");
    }
    for (syscall, count) in report.syscall_counts.iter() {
        if *count != 0 {
            common::profiling::record_metric(
                guest,
                format!("syscall.{syscall:?}"),
                *count,
                "calls",
            );
        }
    }
}
