use super::sampler::{DiskReading, MemReading, Proc, Sample};
use super::*;
use std::time::{Duration, Instant};

fn proc(pid: u32, name: &str, cpu: u64, io: u64, private: u64) -> Proc {
    Proc {
        key: (pid, 1),
        name: name.into(),
        cpu,
        io,
        private,
        working_set: private / 2,
    }
}

fn sample(at: f64, busy: u64, procs: Vec<Proc>) -> Sample {
    // One second is 10_000_000 ticks per core; the fixture uses two cores of total time.
    let total = (at * 2e7) as u64;
    Sample {
        at,
        times: (total - busy, total, 0),
        mem: MemReading {
            load: 50,
            avail: 1 << 30,
            total: 2 << 30,
            commit_used: 1 << 30,
            commit_limit: 4 << 30,
        },
        disk: None,
        procs,
        unopened: 2,
    }
}

fn group(name: &str, cpu: f64, io: f64, private: u64) -> Group {
    Group {
        name: name.into(),
        count: 1,
        cpu_avg: cpu,
        cpu_peak: cpu,
        io_per_sec: io,
        private_bytes: private,
        working_set: private,
    }
}

#[test]
fn cpu_percent_spreads_busy_time_over_the_cores() {
    // 20 s of CPU time over 10 s wall on 4 cores is 50 % of all cores.
    assert!((cpu_percent(200_000_000, 10.0, 4) - 50.0).abs() < 1e-9);
    assert!((cpu_percent(10_000_000, 1.0, 1) - 100.0).abs() < 1e-9);
    assert_eq!(cpu_percent(5, 0.0, 4), 0.0);
    assert_eq!(cpu_percent(5, 1.0, 0), 0.0);
}

#[test]
fn system_busy_uses_kernel_time_that_includes_idle() {
    let busy = system_busy_percent((0, 0, 0), (60, 100, 0)).unwrap();
    assert!((busy - 40.0).abs() < 1e-9);
    assert_eq!(system_busy_percent((5, 5, 5), (5, 5, 5)), None);
}

#[test]
fn processes_group_by_name_ignoring_case() {
    let first = sample(
        0.0,
        0,
        vec![
            proc(1, "chrome.exe", 0, 0, 100),
            proc(2, "Chrome.exe", 0, 0, 100),
            proc(3, "calc.exe", 0, 0, 10),
        ],
    );
    let second = sample(
        2.0,
        0,
        vec![
            proc(1, "chrome.exe", 20_000_000, 2048, 200),
            proc(2, "Chrome.exe", 10_000_000, 2048, 300),
            proc(3, "calc.exe", 0, 0, 10),
        ],
    );
    let (_, groups) = analyze(&[first, second], 2);
    assert_eq!(groups.len(), 2);
    let chrome = groups.iter().find(|g| g.name == "chrome.exe").unwrap();
    assert_eq!(chrome.count, 2);
    // 3 s of CPU time over 2 s wall on 2 cores is 75 %.
    assert!((chrome.cpu_avg - 75.0).abs() < 1e-9);
    assert!((chrome.io_per_sec - 2048.0).abs() < 1e-9);
    assert_eq!(chrome.private_bytes, 500);
}

#[test]
fn a_reused_process_id_is_not_the_same_process() {
    let mut old = proc(1, "a.exe", 900_000_000, 0, 1);
    old.key = (1, 1);
    let mut new = proc(1, "a.exe", 10_000_000, 0, 1);
    new.key = (1, 2);
    let (_, groups) = analyze(&[sample(0.0, 0, vec![old]), sample(1.0, 0, vec![new])], 1);
    assert_eq!(groups[0].cpu_avg, 0.0);
}

#[test]
fn peak_is_the_busiest_second() {
    let samples = [
        sample(0.0, 0, vec![proc(1, "a.exe", 0, 0, 1)]),
        sample(1.0, 0, vec![proc(1, "a.exe", 2_000_000, 0, 1)]),
        sample(2.0, 0, vec![proc(1, "a.exe", 10_000_000, 0, 1)]),
    ];
    let (_, groups) = analyze(&samples, 1);
    assert!((groups[0].cpu_peak - 80.0).abs() < 1e-9);
    assert!((groups[0].cpu_avg - 50.0).abs() < 1e-9);
}

#[test]
fn ranking_orders_by_value_then_name_and_caps() {
    let groups = vec![
        group("b.exe", 5.0, 0.0, 1),
        group("A.exe", 5.0, 0.0, 1),
        group("c.exe", 9.0, 0.0, 1),
        group("idle.exe", 0.0, 0.0, 1),
    ];
    let top = top_by(&groups, 3, true, |g| g.cpu_avg);
    let names: Vec<&str> = top.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["c.exe", "A.exe", "b.exe"]);
    assert_eq!(top_by(&groups, 10, true, |g| g.cpu_avg).len(), 3);
    assert_eq!(top_by(&groups, 10, false, |g| g.cpu_avg).len(), 4);
    assert_eq!(top_by(&groups, 1, false, |g| g.cpu_avg).len(), 1);
}

#[test]
fn system_summary_reports_average_peak_and_unattributed_cpu() {
    let samples = [
        sample(0.0, 0, vec![]),
        sample(1.0, 10_000_000, vec![]),
        sample(2.0, 40_000_000, vec![]),
    ];
    let (summary, _) = analyze(&samples, 2);
    let cpu = summary.cpu.unwrap();
    assert!((cpu.avg - 100.0).abs() < 1e-9);
    assert!(cpu.peak > 0.0);
    assert_eq!(summary.unopened, 2);
    assert!((summary.commit_pct.unwrap().avg - 25.0).abs() < 1e-9);
    assert!(summary.disk_unavailable);
    assert!(summary.unattributed_cpu.unwrap() > 0.0);
}

#[test]
fn disk_figures_come_from_the_counters_and_latency_ignores_idle_seconds() {
    let mut a = sample(0.0, 0, vec![]);
    let mut b = sample(1.0, 0, vec![]);
    a.disk = Some(DiskReading {
        idle_pct: Some(90.0),
        latency_secs: Some(0.0),
        queue: Some(0.0),
        bytes_per_sec: Some(0.0),
        page_reads_per_sec: Some(10.0),
    });
    b.disk = Some(DiskReading {
        idle_pct: Some(10.0),
        latency_secs: Some(0.1),
        queue: Some(3.0),
        bytes_per_sec: Some(1e6),
        page_reads_per_sec: None,
    });
    let (summary, _) = analyze(&[a, b], 2);
    assert!(!summary.disk_unavailable);
    assert!((summary.disk.busy.unwrap().avg - 50.0).abs() < 1e-9);
    assert!((summary.disk.latency_ms.unwrap().avg - 100.0).abs() < 1e-9);
    assert!((summary.disk.page_reads_per_sec.unwrap().avg - 10.0).abs() < 1e-9);
}

fn stat1(v: f64) -> Option<Stat> {
    Some(Stat { avg: v, peak: v })
}

#[test]
fn interpretation_flags_each_threshold_and_stays_quiet_below() {
    assert!(interpret(&Summary::default(), &[]).is_empty());
    let calm = Summary {
        cpu: stat1(80.0),
        mem_load: stat1(90.0),
        commit_pct: stat1(90.0),
        disk: DiskSummary {
            busy: stat1(80.0),
            latency_ms: stat1(50.0),
            page_reads_per_sec: stat1(200.0),
            ..DiskSummary::default()
        },
        ..Summary::default()
    };
    assert!(interpret(&calm, &[group("x.exe", 50.0, 0.0, 0)]).is_empty());
    let loud = Summary {
        cpu: stat1(80.1),
        mem_load: stat1(90.1),
        commit_pct: stat1(90.1),
        disk: DiskSummary {
            busy: stat1(80.1),
            latency_ms: stat1(50.1),
            page_reads_per_sec: stat1(200.1),
            ..DiskSummary::default()
        },
        ..Summary::default()
    };
    let flags = interpret(&loud, &[group("x.exe", 50.1, 0.0, 0)]);
    assert_eq!(flags.len(), 7);
    assert!(flags.iter().any(|f| f.starts_with("x.exe used")));
}

#[test]
fn the_report_says_when_disk_counters_are_unavailable() {
    let samples = [
        sample(0.0, 0, vec![proc(1, "a.exe", 0, 0, 1 << 20)]),
        sample(1.0, 0, vec![proc(1, "a.exe", 5_000_000, 0, 1 << 20)]),
    ];
    let text = report(&samples, 2, 5, "now");
    assert!(text.contains("Disk counters: unavailable"));
    assert!(text.contains("Disk findings could not be checked"));
    assert!(text.contains("a.exe"));
    assert!(!text.contains("Nothing crossed a threshold") || text.contains("unavailable"));
}

#[test]
fn a_live_two_second_sample_runs() {
    let started = Instant::now();
    let args = Args::parse(
        &["--seconds".into(), "2".into(), "--top".into(), "3".into()],
        TOOL.usage,
    )
    .unwrap();
    let output = run(&args).unwrap();
    let text = output.text;
    assert!(started.elapsed() < Duration::from_secs(15));
    let parsed: Value = serde_json::from_str(&output.data.to_string()).unwrap();
    assert_eq!(parsed["tool"], "perf");
    assert_eq!(parsed["top"], 3);
    assert!(parsed["by_private_memory"].as_array().unwrap().len() <= 3);
    assert!(text.contains("Performance sample"));
    assert!(text.contains("CPU: average"));
    assert!(text.contains("by private memory"));
}

#[test]
fn options_are_bounded() {
    let bad = |a: &[&str]| {
        let a: Vec<String> = a.iter().map(|s| s.to_string()).collect();
        run(&Args::parse(&a, TOOL.usage).unwrap()).is_err()
    };
    assert!(bad(&["--seconds", "1"]));
    assert!(bad(&["--seconds", "301"]));
    assert!(bad(&["--top", "0"]));
    assert!(bad(&["--top", "51"]));
}

#[test]
fn page_fault_reads_alone_are_not_flagged() {
    let reads_only = Summary {
        mem_load: stat1(60.0),
        disk: DiskSummary {
            page_reads_per_sec: stat1(5000.0),
            ..DiskSummary::default()
        },
        ..Summary::default()
    };
    assert!(interpret(&reads_only, &[]).is_empty());
    let pressed = Summary {
        mem_load: stat1(80.1),
        ..reads_only
    };
    let flags = interpret(&pressed, &[]);
    assert_eq!(flags.len(), 1);
    assert!(flags[0].starts_with("Hard page fault reads"));
}

#[test]
fn json_agrees_with_the_text_on_the_rankings_and_findings() {
    let samples = [
        sample(0.0, 0, vec![proc(1, "a.exe", 0, 0, 1 << 20)]),
        sample(
            1.0,
            2e7 as u64,
            vec![proc(1, "a.exe", 2e7 as u64, 4 << 20, 1 << 20)],
        ),
    ];
    let started = std::time::UNIX_EPOCH + Duration::from_secs(1_772_719_389);
    let data = report_json(&samples, 2, 5, started);
    let text = report(&samples, 2, 5, "now");
    assert_eq!(data["started"], "2026-03-05T14:03:09Z");
    assert_eq!(data["logical_processors"], 2);
    assert_eq!(data["by_cpu"][0]["name"], "a.exe");
    let cpu = data["by_cpu"][0]["cpu_average_percent"].as_f64().unwrap();
    assert!((cpu - 100.0).abs() < 0.01, "{cpu}");
    assert!(text.contains("a.exe: average 100.0 %, peak 100.0 %"));
    assert_eq!(data["by_private_memory"][0]["private_bytes"], 1u64 << 20);
    assert_eq!(data["system"]["memory_total_bytes"], 2u64 << 30);
    assert_eq!(data["system"]["processes_not_opened"], 2);
    assert_eq!(
        data["system"]["disk"]["unavailable"],
        "the performance counters could not be read"
    );
    assert_eq!(data["disk_findings_checked"], false);
    assert!(text.contains("Disk counters: unavailable"));
    assert_eq!(data["findings"].as_array().unwrap().len(), 2);
    for finding in data["findings"].as_array().unwrap() {
        assert!(text.contains(finding.as_str().unwrap()));
    }
}
