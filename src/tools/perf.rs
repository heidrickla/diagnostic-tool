//! CPU, disk and memory use per process over a short sample, for "it is slow" with no fault.
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use serde_json::{json, Value};

use super::events::rfc3339;
use super::{Args, Output, Tool};
use crate::clock;

mod sampler;

use sampler::{DiskReading, Proc, Sample};

pub const TOOL: Tool = Tool {
    name: "perf",
    summary: "CPU, disk and memory use per process over a short sample",
    usage: "\
Usage: toolkit perf [--seconds N] [--top N]
  --seconds N       length of the sample in seconds (default 30, 2 to 300)
  --top N           processes listed in each ranking (default 10, 1 to 50)
Samples every process once a second and groups them by executable name.",
    run,
};

fn run(args: &Args) -> Result<Output, String> {
    let seconds = args.number("--seconds", 30, 2, 300)?;
    let top = args.number("--top", 10, 1, 50)? as usize;
    let started = SystemTime::now();
    let samples = sampler::collect(seconds)?;
    let cores = sampler::logical_processors();
    Ok(Output {
        text: report(&samples, cores, top, &clock::local(started).long()),
        data: report_json(&samples, cores, top, started),
    })
}

/// Share of all cores used, in percent, for `busy_100ns` of CPU time over `wall_secs`.
fn cpu_percent(busy_100ns: u64, wall_secs: f64, cores: u32) -> f64 {
    if wall_secs <= 0.0 || cores == 0 {
        return 0.0;
    }
    busy_100ns as f64 / 1e7 / (wall_secs * f64::from(cores)) * 100.0
}

/// System-wide busy share from two GetSystemTimes readings (kernel time includes idle).
fn system_busy_percent(prev: (u64, u64, u64), cur: (u64, u64, u64)) -> Option<f64> {
    let idle = cur.0.saturating_sub(prev.0);
    let total = cur.1.saturating_sub(prev.1) + cur.2.saturating_sub(prev.2);
    if total == 0 {
        return None;
    }
    Some((total.saturating_sub(idle)) as f64 / total as f64 * 100.0)
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Stat {
    avg: f64,
    peak: f64,
}

fn stat(values: &[f64]) -> Option<Stat> {
    if values.is_empty() {
        return None;
    }
    Some(Stat {
        avg: values.iter().sum::<f64>() / values.len() as f64,
        peak: values.iter().cloned().fold(f64::MIN, f64::max),
    })
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Group {
    name: String,
    count: usize,
    cpu_avg: f64,
    cpu_peak: f64,
    io_per_sec: f64,
    private_bytes: u64,
    working_set: u64,
}

#[derive(Debug, Default, PartialEq)]
struct DiskSummary {
    busy: Option<Stat>,
    latency_ms: Option<Stat>,
    queue: Option<Stat>,
    bytes_per_sec: Option<Stat>,
    page_reads_per_sec: Option<Stat>,
}

#[derive(Debug, Default, PartialEq)]
struct Summary {
    cpu: Option<Stat>,
    mem_load: Option<Stat>,
    avail_min: u64,
    total_phys: u64,
    commit_pct: Option<Stat>,
    commit_used: u64,
    commit_limit: u64,
    disk: DiskSummary,
    disk_unavailable: bool,
    opened: usize,
    unopened: usize,
    unattributed_cpu: Option<f64>,
}

/// Sample names are compared case-insensitively; the first spelling seen is shown.
#[derive(Default)]
struct Acc {
    display: String,
    cpu_100ns: u64,
    io_bytes: u64,
    peak: f64,
}

/// Where each name was seen and what it held in the last sample.
#[derive(Default)]
struct Ended {
    seen: HashSet<(u32, u64)>,
    private: u64,
    working_set: u64,
}

fn analyze(samples: &[Sample], cores: u32) -> (Summary, Vec<Group>) {
    let mut summary = Summary::default();
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return (summary, Vec::new());
    };
    let wall = (last.at - first.at).max(0.001);

    let mut busy = Vec::new();
    for pair in samples.windows(2) {
        if let Some(value) = system_busy_percent(pair[0].times, pair[1].times) {
            busy.push(value);
        }
    }
    summary.cpu = stat(&busy);
    if let Some(value) = system_busy_percent(first.times, last.times) {
        if let Some(cpu) = summary.cpu.as_mut() {
            cpu.avg = value;
        }
    }
    let loads: Vec<f64> = samples.iter().map(|s| f64::from(s.mem.load)).collect();
    summary.mem_load = stat(&loads);
    summary.avail_min = samples.iter().map(|s| s.mem.avail).min().unwrap_or(0);
    summary.total_phys = last.mem.total;
    let commits: Vec<f64> = samples
        .iter()
        .filter(|s| s.mem.commit_limit > 0)
        .map(|s| s.mem.commit_used as f64 / s.mem.commit_limit as f64 * 100.0)
        .collect();
    summary.commit_pct = stat(&commits);
    summary.commit_used = last.mem.commit_used;
    summary.commit_limit = last.mem.commit_limit;
    summary.unopened = last.unopened;
    summary.opened = last.procs.len();

    let readings: Vec<&DiskReading> = samples.iter().filter_map(|s| s.disk.as_ref()).collect();
    summary.disk_unavailable = readings.is_empty();
    let pick = |f: fn(&DiskReading) -> Option<f64>| -> Option<Stat> {
        stat(&readings.iter().filter_map(|r| f(r)).collect::<Vec<_>>())
    };
    summary.disk = DiskSummary {
        busy: pick(|r| r.idle_pct.map(|v| (100.0 - v).clamp(0.0, 100.0))),
        latency_ms: {
            let active: Vec<f64> = readings
                .iter()
                .filter(|r| r.bytes_per_sec.is_some_and(|b| b > 0.0))
                .filter_map(|r| r.latency_secs.map(|v| v * 1000.0))
                .collect();
            stat(&active)
        },
        queue: pick(|r| r.queue),
        bytes_per_sec: pick(|r| r.bytes_per_sec),
        page_reads_per_sec: pick(|r| r.page_reads_per_sec),
    };

    // Per-interval deltas for processes present in both samples (same pid and start time).
    let mut accs: HashMap<String, Acc> = HashMap::new();
    let mut ended: HashMap<String, Ended> = HashMap::new();
    for pair in samples.windows(2) {
        let dt = (pair[1].at - pair[0].at).max(0.001);
        let before: HashMap<(u32, u64), &Proc> = pair[0].procs.iter().map(|p| (p.key, p)).collect();
        let mut interval: HashMap<String, u64> = HashMap::new();
        for proc in &pair[1].procs {
            let name = proc.name.to_ascii_lowercase();
            let acc = accs.entry(name.clone()).or_insert_with(|| Acc {
                display: proc.name.clone(),
                ..Acc::default()
            });
            if let Some(old) = before.get(&proc.key) {
                let cpu = proc.cpu.saturating_sub(old.cpu);
                acc.cpu_100ns += cpu;
                acc.io_bytes += proc.io.saturating_sub(old.io);
                *interval.entry(name).or_default() += cpu;
            }
        }
        for (name, cpu) in interval {
            let pct = cpu_percent(cpu, dt, cores);
            if let Some(acc) = accs.get_mut(&name) {
                acc.peak = acc.peak.max(pct);
            }
        }
    }
    let mut seen_total = 0u64;
    for sample in samples {
        for proc in &sample.procs {
            let name = proc.name.to_ascii_lowercase();
            accs.entry(name.clone()).or_insert_with(|| Acc {
                display: proc.name.clone(),
                ..Acc::default()
            });
            ended.entry(name).or_default().seen.insert(proc.key);
        }
    }
    for proc in &last.procs {
        let entry = ended.entry(proc.name.to_ascii_lowercase()).or_default();
        entry.private += proc.private;
        entry.working_set += proc.working_set;
    }
    let mut groups = Vec::new();
    for (name, acc) in accs {
        let Ended {
            seen,
            private: private_bytes,
            working_set,
        } = ended.remove(&name).unwrap_or_default();
        let count = last
            .procs
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(&name))
            .count();
        seen_total += acc.cpu_100ns;
        groups.push(Group {
            name: acc.display,
            count: if count > 0 { count } else { seen.len() },
            cpu_avg: cpu_percent(acc.cpu_100ns, wall, cores),
            cpu_peak: acc.peak,
            io_per_sec: acc.io_bytes as f64 / wall,
            private_bytes,
            working_set,
        });
    }
    if let Some(cpu) = summary.cpu {
        let attributed = cpu_percent(seen_total, wall, cores);
        summary.unattributed_cpu = Some((cpu.avg - attributed).max(0.0));
    }
    (summary, groups)
}

/// Largest `n` groups by `value`, ties by name, entries at zero left out when `skip_zero`.
fn top_by(groups: &[Group], n: usize, skip_zero: bool, value: fn(&Group) -> f64) -> Vec<&Group> {
    let mut list: Vec<&Group> = groups
        .iter()
        .filter(|g| !skip_zero || value(g) > 0.0)
        .collect();
    list.sort_by(|a, b| {
        value(b)
            .partial_cmp(&value(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
    });
    list.truncate(n);
    list
}

/// Findings that cross the stated thresholds.
fn interpret(summary: &Summary, groups: &[Group]) -> Vec<String> {
    let mut flags = Vec::new();
    if let Some(cpu) = summary.cpu {
        if cpu.avg > 80.0 {
            flags.push(format!("CPU averaged {:.0} %, over 80 %.", cpu.avg));
        }
    }
    for group in groups {
        if group.cpu_avg > 50.0 {
            flags.push(format!(
                "{} used {:.0} % of all cores on average, over 50 %.",
                group.name, group.cpu_avg
            ));
        }
    }
    if let Some(load) = summary.mem_load {
        if load.avg > 90.0 {
            flags.push(format!(
                "Memory load averaged {:.0} %, over 90 %.",
                load.avg
            ));
        }
    }
    if let Some(commit) = summary.commit_pct {
        if commit.avg > 90.0 {
            flags.push(format!(
                "Commit averaged {:.0} % of the commit limit, over 90 %.",
                commit.avg
            ));
        }
    }
    if let Some(busy) = summary.disk.busy {
        if busy.avg > 80.0 {
            flags.push(format!(
                "The disks were busy {:.0} % of the time, over 80 %.",
                busy.avg
            ));
        }
    }
    if let Some(latency) = summary.disk.latency_ms {
        if latency.avg > 50.0 {
            flags.push(format!(
                "Disk latency averaged {:.0} ms per transfer, over 50 ms.",
                latency.avg
            ));
        }
    }
    if let (Some(reads), Some(load)) = (summary.disk.page_reads_per_sec, summary.mem_load) {
        if reads.avg > 200.0 && load.avg > 80.0 {
            flags.push(format!(
                "Hard page fault reads averaged {:.0} per second, over 200, with memory load averaging {:.0} %, over 80 %.",
                reads.avg, load.avg
            ));
        }
    }
    flags
}

fn bytes(value: u64) -> String {
    let value = value as f64;
    let (unit, div) = if value >= 1024.0 * 1024.0 * 1024.0 {
        ("GiB", 1024.0 * 1024.0 * 1024.0)
    } else if value >= 1024.0 * 1024.0 {
        ("MiB", 1024.0 * 1024.0)
    } else {
        ("KiB", 1024.0)
    };
    format!("{:.1} {unit}", value / div)
}

fn rate(value: f64) -> String {
    format!("{}/s", bytes(value.max(0.0) as u64))
}

fn stat_line(stat: Option<Stat>, show: impl Fn(f64) -> String) -> String {
    match stat {
        Some(s) => format!("average {}, peak {}", show(s.avg), show(s.peak)),
        None => "unavailable".into(),
    }
}

fn row(group: &Group, detail: String) -> String {
    let count = if group.count > 1 {
        format!(" x{}", group.count)
    } else {
        String::new()
    };
    format!("  {}{count}: {detail}", group.name)
}

fn report(samples: &[Sample], cores: u32, top: usize, started: &str) -> String {
    let (summary, groups) = analyze(samples, cores);
    let mut lines = Vec::new();
    let span = match (samples.first(), samples.last()) {
        (Some(a), Some(b)) => b.at - a.at,
        _ => 0.0,
    };
    lines.push(format!(
        "Performance sample: {span:.0} s, {} readings, {cores} logical processors, started {started}.",
        samples.len()
    ));
    lines.push(String::new());
    lines.push("System".into());
    let pct = |v: f64| format!("{v:.1} %");
    lines.push(format!("  CPU: {}", stat_line(summary.cpu, pct)));
    lines.push(format!(
        "  Memory load: {}; lowest available {} of {}",
        stat_line(summary.mem_load, |v| format!("{v:.0} %")),
        bytes(summary.avail_min),
        bytes(summary.total_phys)
    ));
    lines.push(format!(
        "  Commit: {} of {} limit; {}",
        bytes(summary.commit_used),
        bytes(summary.commit_limit),
        stat_line(summary.commit_pct, |v| format!("{v:.0} %"))
    ));
    if summary.disk_unavailable {
        lines.push(
            "  Disk counters: unavailable (the performance counters could not be read).".into(),
        );
    } else {
        lines.push(format!(
            "  Disk busy: {}",
            stat_line(summary.disk.busy, pct)
        ));
        lines.push(format!(
            "  Disk latency per transfer: {}",
            stat_line(summary.disk.latency_ms, |v| format!("{v:.1} ms"))
        ));
        lines.push(format!(
            "  Disk queue length: {}",
            stat_line(summary.disk.queue, |v| format!("{v:.2}"))
        ));
        lines.push(format!(
            "  Disk throughput: {}",
            stat_line(summary.disk.bytes_per_sec, rate)
        ));
        lines.push(format!(
            "  Hard page fault reads: {}",
            stat_line(summary.disk.page_reads_per_sec, |v| format!("{v:.0}/s"))
        ));
    }
    lines.push(format!(
        "  Processes: {} read, {} could not be opened (protected or another user's).",
        summary.opened, summary.unopened
    ));
    if let Some(value) = summary.unattributed_cpu {
        lines.push(format!(
            "  CPU not attributed to a readable process (unreadable or ended): {value:.1} % average."
        ));
    }
    lines.push(String::new());
    lines.push("Findings".into());
    let flags = interpret(&summary, &groups);
    if flags.is_empty() {
        lines.push("  Nothing crossed a threshold in this sample.".into());
    }
    for flag in flags {
        lines.push(format!("  {flag}"));
    }
    if summary.disk_unavailable {
        lines.push("  Disk findings could not be checked.".into());
    }

    lines.push(String::new());
    lines.push(format!("Top {top} by average CPU (percent of all cores)"));
    let by_cpu = top_by(&groups, top, true, |g| g.cpu_avg);
    for group in &by_cpu {
        lines.push(row(
            group,
            format!(
                "average {:.1} %, peak {:.1} %",
                group.cpu_avg, group.cpu_peak
            ),
        ));
    }
    if by_cpu.is_empty() {
        lines.push("  none measurable".into());
    }
    lines.push(String::new());
    lines.push(format!(
        "Top {top} by disk bytes per second (reads and writes)"
    ));
    let by_io = top_by(&groups, top, true, |g| g.io_per_sec);
    for group in &by_io {
        lines.push(row(group, rate(group.io_per_sec)));
    }
    if by_io.is_empty() {
        lines.push("  none measurable".into());
    }
    lines.push(String::new());
    lines.push(format!("Top {top} by private memory at the end"));
    for group in top_by(&groups, top, false, |g| g.private_bytes as f64) {
        lines.push(row(
            group,
            format!(
                "private {}, working set {}",
                bytes(group.private_bytes),
                bytes(group.working_set)
            ),
        ));
    }
    lines.join("\n")
}

fn stat_json(stat: Option<Stat>) -> Value {
    match stat {
        Some(s) => json!({ "average": s.avg, "peak": s.peak }),
        None => super::events::unavailable("no reading"),
    }
}

fn group_json(group: &Group) -> Value {
    json!({
        "name": group.name,
        "processes": group.count,
        "cpu_average_percent": group.cpu_avg,
        "cpu_peak_percent": group.cpu_peak,
        "io_bytes_per_second": group.io_per_sec,
        "private_bytes": group.private_bytes,
        "working_set_bytes": group.working_set,
    })
}

/// The same readings, findings and rankings as `report`, as JSON.
fn report_json(samples: &[Sample], cores: u32, top: usize, started: SystemTime) -> Value {
    let (summary, groups) = analyze(samples, cores);
    let span = match (samples.first(), samples.last()) {
        (Some(a), Some(b)) => b.at - a.at,
        _ => 0.0,
    };
    let disk = if summary.disk_unavailable {
        super::events::unavailable("the performance counters could not be read")
    } else {
        json!({
            "busy_percent": stat_json(summary.disk.busy),
            "latency_ms_per_transfer": stat_json(summary.disk.latency_ms),
            "queue_length": stat_json(summary.disk.queue),
            "throughput_bytes_per_second": stat_json(summary.disk.bytes_per_sec),
            "hard_page_fault_reads_per_second": stat_json(summary.disk.page_reads_per_sec),
        })
    };
    let ranked = |value: fn(&Group) -> f64, skip_zero: bool| {
        top_by(&groups, top, skip_zero, value)
            .into_iter()
            .map(group_json)
            .collect::<Vec<_>>()
    };
    json!({
        "tool": "perf",
        "started": rfc3339(started),
        "seconds": span,
        "readings": samples.len(),
        "logical_processors": cores,
        "system": {
            "cpu_percent": stat_json(summary.cpu),
            "memory_load_percent": stat_json(summary.mem_load),
            "memory_lowest_available_bytes": summary.avail_min,
            "memory_total_bytes": summary.total_phys,
            "commit_used_bytes": summary.commit_used,
            "commit_limit_bytes": summary.commit_limit,
            "commit_percent": stat_json(summary.commit_pct),
            "disk": disk,
            "processes_read": summary.opened,
            "processes_not_opened": summary.unopened,
            "cpu_unattributed_percent": summary.unattributed_cpu,
        },
        "findings": interpret(&summary, &groups),
        "disk_findings_checked": !summary.disk_unavailable,
        "top": top,
        "by_cpu": ranked(|g| g.cpu_avg, true),
        "by_disk_bytes_per_second": ranked(|g| g.io_per_sec, true),
        "by_private_memory": ranked(|g| g.private_bytes as f64, false),
    })
}

#[cfg(test)]
mod tests;
