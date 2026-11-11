//! Whether the link, the router, DNS, a proxy or the hosts file is behind a slow or
//! dropping connection. Gathering is in the submodules; `interpret` turns readings into flags.
mod adapters;
mod dns;
mod hosts;
mod icmp;
mod proxy;
mod wifi;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use super::events::rfc3339;
use super::{Args, Output, Tool};
use crate::events::{self, Query};
use adapters::{Adapter, Kind};
use dns::{Outcome, Resolved, ServerResult};
use icmp::Reach;

pub const TOOL: Tool = Tool {
    name: "network",
    summary: "adapter, gateway, DNS, proxy, hosts file and Wi-Fi signal",
    usage: "\
Usage: toolkit network [--quick]
  --quick   3 echoes per target instead of 10 and shorter waits (about 10 s at most)",
    run,
};

const CLOUDFLARE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const GOOGLE: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const NAMES: [&str; 2] = ["www.microsoft.com", "www.google.com"];
const QUERY_NAME: &str = "www.microsoft.com";
const MAX_SERVERS: usize = 6;
/// Names the hosts section prints; the rest of the well-known ones are counted.
const MAX_HOST_NAMES: usize = 40;
const LOSS_LIMIT: f64 = 2.0;
const WIFI_LOG: &str = "Microsoft-Windows-WLAN-AutoConfig/Operational";

#[derive(Debug, Default)]
struct Disconnects {
    week: usize,
    day: usize,
}

#[derive(Debug, Default)]
struct Report {
    adapters: Option<Result<Vec<Adapter>, String>>,
    /// Gateway address, the kind of adapter it is on, and the echoes sent to it.
    gateway: Option<(Ipv4Addr, Kind, Reach)>,
    internet: Vec<(Ipv4Addr, Reach)>,
    resolved: Vec<Resolved>,
    /// Queries to the configured DNS servers.
    servers: Vec<ServerResult>,
    cloudflare: Option<ServerResult>,
    proxy: proxy::Proxy,
    hosts: Option<Result<hosts::Hosts, String>>,
    machine: String,
    wifi: wifi::Wifi,
    /// Disconnect events; None when the log was not read.
    disconnects: Option<Result<Disconnects, String>>,
    quick: bool,
    checked_at: Option<SystemTime>,
}

fn run(args: &Args) -> Result<Output, String> {
    let report = gather(args.switch("--quick"));
    Ok(Output {
        text: render(&report).join("\n"),
        data: report_json(&report),
    })
}

fn gather(quick: bool) -> Report {
    let mut report = Report {
        quick,
        checked_at: Some(SystemTime::now()),
        machine: std::env::var("COMPUTERNAME").unwrap_or_default(),
        ..Report::default()
    };
    let adapters = adapters::read();
    let up: &[Adapter] = adapters.as_deref().unwrap_or(&[]);
    let gateway = adapters::default_gateway(up);
    let mut servers: Vec<IpAddr> = Vec::new();
    // Adapters without a gateway (Hyper-V and WSL switches) carry placeholder DNS entries
    // that nothing uses, so only adapters that can reach out are tested.
    for adapter in up.iter().filter(|a| !a.gateways.is_empty()) {
        for ip in &adapter.dns {
            if !servers.contains(ip) {
                servers.push(*ip);
            }
        }
    }
    servers.truncate(MAX_SERVERS);
    let (count, gap, resolve_limit) = if quick {
        (3, Duration::from_millis(100), Duration::from_secs(4))
    } else {
        (10, Duration::from_millis(250), Duration::from_secs(8))
    };
    let events_limit = Duration::from_secs(if quick { 6 } else { 12 });

    std::thread::scope(|scope| {
        let gateway_echo = gateway.map(|(ip, _)| scope.spawn(move || icmp::ping(ip, count, gap)));
        let internet: Vec<_> = [CLOUDFLARE, GOOGLE]
            .into_iter()
            .map(|ip| (ip, scope.spawn(move || icmp::ping(ip, count, gap))))
            .collect();
        let resolvers = scope.spawn(move || {
            NAMES
                .iter()
                .map(|name| dns::resolve(name, resolve_limit))
                .collect::<Vec<_>>()
        });
        let queries: Vec<_> = servers
            .iter()
            .map(|&ip| scope.spawn(move || dns::query_server(ip, QUERY_NAME)))
            .collect();
        let cloudflare = scope.spawn(|| dns::query_server(IpAddr::V4(CLOUDFLARE), QUERY_NAME));
        let wifi_thread = scope.spawn(wifi::read);
        let proxy_thread = scope.spawn(proxy::read);
        let hosts_thread = scope.spawn(hosts::read);

        let wifi = wifi_thread.join().unwrap_or_default();
        let disconnects = (wifi.interfaces > 0).then(|| disconnects(events_limit));
        report.wifi = wifi;
        report.disconnects = disconnects;
        report.proxy = proxy_thread.join().unwrap_or_default();
        report.hosts = Some(
            hosts_thread
                .join()
                .unwrap_or_else(|_| Err("the reader stopped unexpectedly".into())),
        );
        report.gateway = gateway
            .zip(gateway_echo)
            .map(|((ip, kind), echo)| (ip, kind, echo.join().unwrap_or_default()));
        report.internet = internet
            .into_iter()
            .map(|(ip, echo)| (ip, echo.join().unwrap_or_default()))
            .collect();
        report.resolved = resolvers.join().unwrap_or_default();
        report.servers = queries.into_iter().filter_map(|q| q.join().ok()).collect();
        report.cloudflare = cloudflare.join().ok();
    });
    report.adapters = Some(adapters);
    report
}

/// Counts Wi-Fi disconnect events (id 8003) over 7 days and over the last 24 hours.
fn disconnects(limit: Duration) -> Result<Disconnects, String> {
    let query = Query {
        logs: vec![WIFI_LOG.into()],
        levels: Vec::new(),
        providers: Vec::new(),
        ids: vec![8003],
        since: Duration::from_secs(7 * 24 * 3600),
        include_noise: true,
        per_log_limit: 5000,
        messages: false,
    };
    let cancelled = AtomicBool::new(false);
    let (found, reads) = events::read_events(&query, Instant::now() + limit, &cancelled)
        .map_err(super::events::message)?;
    if let Some(reason) = reads.iter().find_map(|r| r.unavailable.clone()) {
        return Err(reason);
    }
    let now = SystemTime::now();
    let day = found
        .iter()
        .filter(|e| {
            now.duration_since(e.time)
                .is_ok_and(|age| age <= Duration::from_secs(24 * 3600))
        })
        .count();
    Ok(Disconnects {
        week: found.len(),
        day,
    })
}

fn echo_line(label: &str, reach: &Reach) -> String {
    match (reach.loss_percent(), reach.average(), reach.maximum()) {
        (Some(loss), Some(avg), Some(max)) => format!(
            "  {label}: {} of {} echoes answered, loss {loss:.0} %, average {avg:.1} ms, maximum {max} ms",
            reach.received, reach.sent
        ),
        (Some(loss), _, _) => format!(
            "  {label}: no echo answered ({} sent, loss {loss:.0} %){}",
            reach.sent,
            reach
                .error
                .as_ref()
                .map_or(String::new(), |e| format!(", last result: {e}"))
        ),
        _ => format!(
            "  {label}: unavailable, {}",
            reach.error.as_deref().unwrap_or("no echo was sent")
        ),
    }
}

fn server_line(label: &str, result: &ServerResult) -> String {
    match &result.outcome {
        Outcome::Answered(p) => format!(
            "  {label}: answered in {:.0} ms ({}, {} address records{})",
            result.millis,
            match p.rcode {
                0 => "no error".to_string(),
                3 => "name does not exist".to_string(),
                other => format!("response code {other}"),
            },
            p.answers,
            if p.truncated { ", reply truncated" } else { "" }
        ),
        Outcome::NoAnswer => format!("  {label}: no answer within 2 s"),
        Outcome::Failed(reason) => format!("  {label}: failed, {reason}"),
        Outcome::NotQueried(reason) => format!("  {label}: not queried, {reason}"),
    }
}

fn render(report: &Report) -> Vec<String> {
    let mut lines = vec![format!(
        "Network check at {}{}",
        crate::clock::local(report.checked_at.unwrap_or_else(SystemTime::now)).long(),
        if report.quick {
            " (quick: 3 echoes per target)"
        } else {
            ""
        }
    )];
    let findings = interpret(report);
    lines.push(String::new());
    lines.push("Findings:".into());
    if findings.is_empty() {
        lines.push("  Nothing flagged by the readings below.".into());
    }
    lines.extend(findings.iter().map(|f| format!("  - {f}")));

    lines.push(String::new());
    lines.push("Adapters that are up:".into());
    match &report.adapters {
        Some(Ok(list)) if !list.is_empty() => {
            for adapter in list {
                lines.extend(adapter_lines(adapter));
            }
        }
        Some(Ok(_)) => lines.push("  none".into()),
        Some(Err(e)) => lines.push(format!("  unavailable: {e}")),
        None => {}
    }

    lines.push(String::new());
    lines.push("Reachability (ICMP echo):".into());
    match &report.gateway {
        Some((ip, kind, reach)) => {
            let shown = match adapters::classify4(*ip) {
                adapters::Class::Public => "public address".to_string(),
                _ => ip.to_string(),
            };
            let label = format!("default gateway {shown} ({})", kind.label());
            lines.push(echo_line(&label, reach));
        }
        None => lines.push("  default gateway: none found, so not tested".into()),
    }
    for (ip, reach) in &report.internet {
        lines.push(echo_line(&ip.to_string(), reach));
    }
    if report.quick {
        lines.push("  Quick run: 3 echoes each, so loss is coarse.".into());
    } else {
        lines.push(
            "  An average of 0 ms means under 1 ms; echoes are timed in whole milliseconds.".into(),
        );
    }

    lines.push(String::new());
    lines.push("DNS:".into());
    for resolved in &report.resolved {
        lines.push(match &resolved.result {
            Ok(count) => format!(
                "  system resolver, {}: {count} addresses in {:.0} ms",
                resolved.name, resolved.millis
            ),
            Err(e) => format!(
                "  system resolver, {}: failed after {:.0} ms, {e}",
                resolved.name, resolved.millis
            ),
        });
    }
    if report.servers.is_empty() {
        lines.push("  configured DNS servers: none found".into());
    }
    for result in &report.servers {
        lines.push(server_line(
            &format!("configured server {}", result.server),
            result,
        ));
    }
    if let Some(result) = &report.cloudflare {
        lines.push(server_line("1.1.1.1 (comparison)", result));
    }

    lines.push(String::new());
    lines.push("Proxy:".into());
    match &report.proxy.winhttp {
        Some(Ok(None)) => lines.push("  WinHTTP default: no proxy".into()),
        Some(Ok(Some(server))) => lines.push(format!("  WinHTTP default: proxy {server}")),
        Some(Err(e)) => lines.push(format!("  WinHTTP default: unavailable, {e}")),
        None => {}
    }
    match report.proxy.enabled {
        Some(true) => lines.push(format!(
            "  user proxy: on, server {}",
            report.proxy.server.as_deref().unwrap_or("(none listed)")
        )),
        Some(false) => lines.push(format!(
            "  user proxy: off{}",
            report
                .proxy
                .server
                .as_deref()
                .map_or(String::new(), |s| format!(" (a server is stored: {s})"))
        )),
        None => lines.push("  user proxy: unavailable".into()),
    }
    lines.push(
        match report.proxy.pac.as_deref().filter(|p| !p.is_empty()) {
            Some(pac) => format!("  automatic configuration script: {pac}"),
            None => "  automatic configuration script: none".into(),
        },
    );
    if let Some(e) = &report.proxy.registry_error {
        lines.push(format!("  some user settings could not be read: {e}"));
    }

    lines.push(String::new());
    lines.push("Hosts file:".into());
    match &report.hosts {
        Some(Ok(hosts)) => {
            let summary = host_summary(hosts);
            let count = summary.active;
            lines.push(format!(
                "  {count} active {}",
                if count == 1 { "entry" } else { "entries" }
            ));
            if !summary.listed.is_empty() {
                let shown: Vec<String> = summary
                    .listed
                    .iter()
                    .take(MAX_HOST_NAMES)
                    .map(|item| format!("{} -> {} ({})", item.name, item.address, item.reason))
                    .collect();
                lines.push(format!("  names of interest: {}", shown.join(", ")));
                let more = summary.listed.len().saturating_sub(MAX_HOST_NAMES);
                if more > 0 {
                    lines.push(format!("  {more} more names of interest not listed"));
                }
            }
            if summary.others > 0 {
                lines.push(format!("  {} other names", summary.others));
            }
            if hosts.cut_short {
                lines.push("  the file is larger than 1 MiB; only the start was read".into());
            }
        }
        Some(Err(e)) => lines.push(format!("  unavailable: {e}")),
        None => {}
    }

    lines.push(String::new());
    lines.push("Wi-Fi:".into());
    wifi_lines(report, &mut lines);
    lines
}

/// The hosts file as the output shows it: well-known or public-address names, and a count
/// of the rest.
fn host_summary(hosts: &hosts::Hosts) -> hosts::Summary {
    let local = events::local_names();
    hosts::summarize(&hosts.entries, &|name| events::redact(name, &local))
}

fn echo_json(reach: &Reach) -> Value {
    json!({
        "sent": reach.sent,
        "received": reach.received,
        "loss_percent": reach.loss_percent(),
        "average_ms": reach.average(),
        "maximum_ms": reach.maximum(),
        "error": reach.error,
    })
}

fn server_json(result: &ServerResult) -> Value {
    let (outcome, detail) = match &result.outcome {
        Outcome::Answered(p) => (
            "answered",
            json!({
                "response_code": p.rcode,
                "address_records": p.answers,
                "reply_truncated": p.truncated,
                "resolved": result.resolved(),
            }),
        ),
        Outcome::NoAnswer => ("no_answer", json!({ "waited_seconds": 2 })),
        Outcome::Failed(reason) => ("failed", json!({ "reason": reason })),
        Outcome::NotQueried(reason) => ("not_queried", json!({ "reason": reason })),
    };
    json!({
        "server": result.server.to_string(),
        "outcome": outcome,
        "millis": result.millis,
        "detail": detail,
    })
}

fn adapter_json(adapter: &Adapter) -> Value {
    json!({
        "name": adapter.name,
        "description": adapter.description,
        "kind": adapter.kind.label(),
        "link_speed_mbps": adapter.speed_mbps,
        "dhcp": adapter.dhcp,
        "interface_metric_ipv4": adapter.metric4,
        "interface_metric_ipv6": adapter.metric6,
        "ipv4": adapter.v4.iter().map(|ip| adapters::describe_own(IpAddr::V4(*ip))).collect::<Vec<_>>(),
        "ipv6": adapter.v6.iter().map(|ip| adapters::describe_own(IpAddr::V6(*ip))).collect::<Vec<_>>(),
        "gateways": adapter.gateways.iter().map(|ip| adapters::describe_own(*ip)).collect::<Vec<_>>(),
        "dns_servers": adapter.dns.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
    })
}

/// The same readings and findings as `render`, as JSON.
fn report_json(report: &Report) -> Value {
    let unavailable = super::events::unavailable;
    let adapters_json = match &report.adapters {
        Some(Ok(list)) => json!(list.iter().map(adapter_json).collect::<Vec<_>>()),
        Some(Err(e)) => unavailable(e),
        None => unavailable("not read"),
    };
    let gateway = report.gateway.as_ref().map(|(ip, kind, reach)| {
        json!({
            "address": match adapters::classify4(*ip) {
                adapters::Class::Public => "public address".to_string(),
                _ => ip.to_string(),
            },
            "adapter_kind": kind.label(),
            "echo": echo_json(reach),
        })
    });
    let winhttp = match &report.proxy.winhttp {
        Some(Ok(server)) => json!({ "proxy": server }),
        Some(Err(e)) => unavailable(e),
        None => unavailable("not read"),
    };
    let hosts_json = match &report.hosts {
        Some(Ok(hosts)) => {
            let summary = host_summary(hosts);
            json!({
                "active_entries": summary.active,
                "names_of_interest": summary.listed.iter().take(MAX_HOST_NAMES).map(|item| json!({
                    "name": item.name,
                    "address": item.address,
                    "reason": item.reason,
                })).collect::<Vec<_>>(),
                "names_of_interest_not_listed": summary.listed.len().saturating_sub(MAX_HOST_NAMES),
                "other_names": summary.others,
                "file_larger_than_1_mib_only_start_read": hosts.cut_short,
            })
        }
        Some(Err(e)) => unavailable(e),
        None => unavailable("not read"),
    };
    let wifi = &report.wifi;
    let wifi_json = if let Some(reason) = &wifi.unavailable {
        unavailable(reason)
    } else {
        json!({
            "interfaces": wifi.interfaces,
            "connected": wifi.links.len(),
            "links": wifi.links.iter().map(|link| json!({
                "signal_quality_percent": link.quality,
                "rssi_dbm": link.rssi,
                "standard": link.phy,
                "receive_mbps": link.rx_mbps,
                "transmit_mbps": link.tx_mbps,
                "band": link.band,
                "channel": link.channel,
            })).collect::<Vec<_>>(),
            "disconnect_events_8003": match &report.disconnects {
                Some(Ok(d)) => json!({ "last_24_hours": d.day, "last_7_days": d.week }),
                Some(Err(e)) => unavailable(e),
                None => Value::Null,
            },
        })
    };
    json!({
        "tool": "network",
        "checked_at": report.checked_at.map(rfc3339),
        "quick": report.quick,
        "findings": interpret(report),
        "adapters_up": adapters_json,
        "reachability": {
            "default_gateway": gateway,
            "internet": report.internet.iter().map(|(ip, reach)| json!({
                "address": ip.to_string(),
                "echo": echo_json(reach),
            })).collect::<Vec<_>>(),
        },
        "dns": {
            "system_resolver": report.resolved.iter().map(|resolved| match &resolved.result {
                Ok(count) => json!({ "name": resolved.name, "addresses": count, "millis": resolved.millis }),
                Err(e) => json!({ "name": resolved.name, "failed": e, "millis": resolved.millis }),
            }).collect::<Vec<_>>(),
            "configured_servers": report.servers.iter().map(server_json).collect::<Vec<_>>(),
            "comparison_1_1_1_1": report.cloudflare.as_ref().map(server_json),
        },
        "proxy": {
            "winhttp_default": winhttp,
            "user_proxy_enabled": report.proxy.enabled,
            "user_proxy_server": report.proxy.server,
            "automatic_configuration_script": report.proxy.pac.as_deref().filter(|p| !p.is_empty()),
            "registry_error": report.proxy.registry_error,
        },
        "hosts_file": hosts_json,
        "wifi": wifi_json,
    })
}

fn adapter_lines(adapter: &Adapter) -> Vec<String> {
    let mut lines = vec![format!(
        "  {} - {} [{}]",
        adapter.name,
        adapter.description,
        adapter.kind.label()
    )];
    lines.push(format!(
        "    link speed: {}; DHCP {}; interface metric IPv4 {}, IPv6 {}",
        adapter
            .speed_mbps
            .map_or("unknown".to_string(), |m| format!("{m} Mbit/s")),
        if adapter.dhcp { "on" } else { "off" },
        adapter.metric4,
        adapter.metric6
    ));
    let list = |label: &str, items: Vec<String>| {
        format!(
            "    {label}: {}",
            if items.is_empty() {
                "none".to_string()
            } else {
                items.join(", ")
            }
        )
    };
    lines.push(list(
        "IPv4",
        adapter
            .v4
            .iter()
            .map(|ip| adapters::describe_own(IpAddr::V4(*ip)))
            .collect(),
    ));
    lines.push(list(
        "IPv6",
        adapter
            .v6
            .iter()
            .map(|ip| adapters::describe_own(IpAddr::V6(*ip)))
            .collect(),
    ));
    lines.push(list(
        "gateway",
        adapter
            .gateways
            .iter()
            .map(|ip| adapters::describe_own(*ip))
            .collect(),
    ));
    lines.push(list(
        "DNS servers",
        adapter.dns.iter().map(IpAddr::to_string).collect(),
    ));
    lines
}

fn wifi_lines(report: &Report, lines: &mut Vec<String>) {
    let wifi = &report.wifi;
    if let Some(reason) = &wifi.unavailable {
        lines.push(format!("  not present or not readable: {reason}"));
        return;
    }
    if wifi.interfaces == 0 {
        lines.push("  no Wi-Fi interface".into());
        return;
    }
    lines.push(format!(
        "  {} Wi-Fi interface(s), {} connected{}",
        wifi.interfaces,
        wifi.links.len(),
        if wifi.links.is_empty() {
            " (nothing to read)"
        } else {
            ""
        }
    ));
    for link in &wifi.links {
        lines.push(format!(
            "  signal quality {} %, RSSI {}, {}, receive {} Mbit/s, transmit {} Mbit/s, band {}, channel {}",
            link.quality,
            link.rssi
                .map_or("unavailable".to_string(), |r| format!("{r} dBm")),
            link.phy,
            link.rx_mbps,
            link.tx_mbps,
            link.band.unwrap_or("unavailable"),
            link.channel
                .map_or("unavailable".to_string(), |c| c.to_string()),
        ));
    }
    match &report.disconnects {
        Some(Ok(d)) => lines.push(format!(
            "  disconnect events (id 8003): {} in the last 24 hours, {} in 7 days",
            d.day, d.week
        )),
        Some(Err(e)) => lines.push(format!("  disconnect events: unavailable, {e}")),
        None => {}
    }
}

/// Turns the readings into plain-language findings. Empty means nothing was flagged.
fn interpret(report: &Report) -> Vec<String> {
    let mut found = Vec::new();
    match &report.adapters {
        Some(Ok(list)) if list.is_empty() => found.push("No network adapter is up.".into()),
        Some(Ok(_)) if report.gateway.is_none() => found.push(
            "No up adapter has an IPv4 default gateway, so the router was not tested.".into(),
        ),
        _ => {}
    }

    let mut gateway_clean = None;
    if let Some((_, kind, reach)) = &report.gateway {
        if let Some(loss) = reach.loss_percent() {
            gateway_clean = Some(loss <= LOSS_LIMIT);
            if loss > LOSS_LIMIT {
                found.push(format!(
                    "The router (default gateway) dropped {loss:.0} % of echoes: the cable or Wi-Fi link to it, or the router, is unreliable."
                ));
            }
        } else if let Some(e) = &reach.error {
            found.push(format!("The router could not be tested: {e}."));
        }
        let limit = if *kind == Kind::WiFi { 30.0 } else { 10.0 };
        if let Some(avg) = reach.average().filter(|avg| *avg > limit) {
            found.push(format!(
                "The router answers slowly: average {avg:.1} ms over {} (limit {limit:.0} ms).",
                kind.label()
            ));
        }
    }

    let lossy: Vec<String> = report
        .internet
        .iter()
        .filter(|(_, reach)| reach.loss_percent().is_some_and(|l| l > LOSS_LIMIT))
        .map(|(ip, reach)| format!("{ip} ({:.0} %)", reach.loss_percent().unwrap_or(0.0)))
        .collect();
    if !lossy.is_empty() {
        let all_lost = report
            .internet
            .iter()
            .all(|(_, r)| r.loss_percent().is_some_and(|l| l >= 100.0));
        let dns_reached = report
            .cloudflare
            .as_ref()
            .is_some_and(ServerResult::resolved);
        let mut text = format!("Echoes to {} were lost", lossy.join(" and "));
        text.push_str(match gateway_clean {
            Some(true) => " while the router answered cleanly: the problem is past the router (modem, ISP or beyond).",
            Some(false) => ", along with the router's: start with the link to the router.",
            None => ".",
        });
        if all_lost && dns_reached {
            text.push_str(" DNS to 1.1.1.1 still answered, so ICMP may be filtered rather than the line being down.");
        }
        found.push(text);
    }

    for resolved in &report.resolved {
        match &resolved.result {
            Err(e) => found.push(format!(
                "The system resolver could not resolve {}: {e}.",
                resolved.name
            )),
            Ok(_) if resolved.millis > 1000.0 => found.push(format!(
                "The system resolver was slow for {}: {:.0} ms.",
                resolved.name, resolved.millis
            )),
            Ok(_) => {}
        }
    }
    let cloudflare_alive = report
        .cloudflare
        .as_ref()
        .is_some_and(ServerResult::resolved);
    for server in report.servers.iter().filter(|s| !s.resolved()) {
        if matches!(server.outcome, Outcome::NotQueried(_)) {
            continue;
        }
        found.push(if cloudflare_alive {
            format!(
                "Configured DNS server {} did not give a usable answer while 1.1.1.1 did: the DNS setting or that server is at fault.",
                server.server
            )
        } else {
            format!(
                "Configured DNS server {} did not give a usable answer, and neither did 1.1.1.1: DNS queries may be blocked or the line is down.",
                server.server
            )
        });
    }

    found.extend(
        report
            .proxy
            .active()
            .into_iter()
            .map(|p| format!("Proxy: {p}.")),
    );
    if let Some(Ok(hosts)) = &report.hosts {
        let local = events::local_names();
        for odd in hosts::odd(&hosts.entries, &report.machine) {
            found.push(format!(
                "Hosts file: {} - {} maps to {}.",
                odd.reason,
                events::redact(&odd.name, &local),
                odd.address
            ));
        }
    }

    for link in &report.wifi.links {
        if link.quality < 50 {
            found.push(format!(
                "Wi-Fi signal quality is {} %{}: move closer to the access point or check for interference.",
                link.quality,
                link.rssi.map_or(String::new(), |r| format!(" ({r} dBm)"))
            ));
        }
    }
    if let Some(Ok(d)) = &report.disconnects {
        if d.day > 5 {
            found.push(format!(
                "Wi-Fi disconnected {} times in the last 24 hours.",
                d.day
            ));
        } else if d.week > 35 {
            found.push(format!(
                "Wi-Fi disconnected {} times in 7 days, more than 5 a day on average.",
                d.week
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reach(sent: u32, received: u32, rtt: u32) -> Reach {
        Reach {
            sent,
            received,
            rtts: vec![rtt; received as usize],
            error: None,
        }
    }

    fn answered(server: &str) -> ServerResult {
        ServerResult {
            server: server.parse().unwrap(),
            outcome: Outcome::Answered(dns::Parsed {
                rcode: 0,
                truncated: false,
                answers: 1,
            }),
            millis: 12.0,
        }
    }

    fn silent(server: &str) -> ServerResult {
        ServerResult {
            server: server.parse().unwrap(),
            outcome: Outcome::NoAnswer,
            millis: 2000.0,
        }
    }

    fn gateway(kind: Kind, reach: Reach) -> Option<(Ipv4Addr, Kind, Reach)> {
        Some(("10.0.0.1".parse().unwrap(), kind, reach))
    }

    fn healthy() -> Report {
        Report {
            adapters: Some(Ok(vec![Adapter {
                name: "Ethernet".into(),
                description: "Test NIC".into(),
                kind: Kind::Ethernet,
                speed_mbps: Some(1000),
                v4: vec!["10.0.0.5".parse().unwrap()],
                v6: vec![],
                gateways: vec!["10.0.0.1".parse().unwrap()],
                dns: vec!["10.0.0.1".parse().unwrap()],
                dhcp: true,
                metric4: 25,
                metric6: 25,
            }])),
            gateway: gateway(Kind::Ethernet, reach(10, 10, 1)),
            internet: vec![(CLOUDFLARE, reach(10, 10, 9)), (GOOGLE, reach(10, 10, 11))],
            resolved: vec![Resolved {
                name: "www.microsoft.com".into(),
                millis: 20.0,
                result: Ok(2),
            }],
            servers: vec![answered("10.0.0.1")],
            cloudflare: Some(answered("1.1.1.1")),
            proxy: proxy::Proxy {
                winhttp: Some(Ok(None)),
                enabled: Some(false),
                ..proxy::Proxy::default()
            },
            hosts: Some(Ok(hosts::Hosts {
                entries: hosts::parse("127.0.0.1 localhost\n"),
                cut_short: false,
            })),
            machine: "MYPC".into(),
            ..Report::default()
        }
    }

    fn has(findings: &[String], text: &str) -> bool {
        findings.iter().any(|f| f.contains(text))
    }

    #[test]
    fn a_healthy_report_flags_nothing() {
        assert_eq!(interpret(&healthy()), Vec::<String>::new());
        assert!(render(&healthy()).join("\n").contains("Nothing flagged"));
    }

    #[test]
    fn gateway_loss_and_latency_use_the_adapter_kind() {
        let mut report = healthy();
        report.gateway = gateway(Kind::Ethernet, reach(10, 9, 1));
        assert!(has(&interpret(&report), "dropped 10 %"));
        report.gateway = gateway(Kind::Ethernet, reach(10, 10, 15));
        assert!(has(&interpret(&report), "answers slowly"));
        report.gateway = gateway(Kind::WiFi, reach(10, 10, 15));
        assert!(interpret(&report).is_empty());
        report.gateway = gateway(Kind::WiFi, reach(10, 10, 40));
        assert!(has(&interpret(&report), "answers slowly"));
        report.gateway = gateway(Kind::Ethernet, reach(50, 49, 1));
        assert!(
            interpret(&report).is_empty(),
            "2 % exactly is within the limit"
        );
    }

    #[test]
    fn internet_loss_with_a_clean_router_points_past_it() {
        let mut report = healthy();
        report.internet = vec![(CLOUDFLARE, reach(10, 0, 0)), (GOOGLE, reach(10, 0, 0))];
        let findings = interpret(&report);
        assert!(has(&findings, "past the router"), "{findings:?}");
        assert!(has(&findings, "ICMP may be filtered"), "{findings:?}");
        report.gateway = gateway(Kind::Ethernet, reach(10, 5, 1));
        assert!(has(&interpret(&report), "along with the router's"));
    }

    #[test]
    fn a_failing_configured_server_is_told_from_a_dead_line() {
        let mut report = healthy();
        report.servers = vec![silent("10.0.0.1")];
        assert!(has(&interpret(&report), "1.1.1.1 did"));
        report.cloudflare = Some(silent("1.1.1.1"));
        assert!(has(&interpret(&report), "neither did 1.1.1.1"));
        report.resolved[0].result = Err("no answer within 8 s".into());
        assert!(has(&interpret(&report), "could not resolve"));
    }

    #[test]
    fn proxies_and_odd_hosts_entries_are_flagged() {
        let mut report = healthy();
        report.proxy.enabled = Some(true);
        report.proxy.server = Some("10.9.9.9:8080".into());
        assert!(has(
            &interpret(&report),
            "Proxy: the user's proxy is turned on"
        ));
        report.hosts = Some(Ok(hosts::Hosts {
            entries: hosts::parse("0.0.0.0 www.microsoft.com\n10.0.0.9 mypc\n"),
            cut_short: false,
        }));
        let findings = interpret(&report);
        assert!(has(&findings, "www.microsoft.com maps to 0.0.0.0"));
        assert!(has(&findings, "own name points elsewhere"));
    }

    #[test]
    fn weak_wifi_and_frequent_disconnects_are_flagged() {
        let mut report = healthy();
        report.wifi.links = vec![wifi::Link {
            quality: 40,
            rssi: Some(-78),
            phy: "802.11ax (Wi-Fi 6)".into(),
            rx_mbps: 100,
            tx_mbps: 100,
            band: Some("5 GHz"),
            channel: Some(36),
        }];
        report.disconnects = Some(Ok(Disconnects { week: 12, day: 6 }));
        let findings = interpret(&report);
        assert!(has(&findings, "quality is 40 %"));
        assert!(has(&findings, "6 times in the last 24 hours"));
        report.disconnects = Some(Ok(Disconnects { week: 40, day: 1 }));
        assert!(has(&interpret(&report), "40 times in 7 days"));
        report.disconnects = Some(Ok(Disconnects { week: 35, day: 5 }));
        report.wifi.links[0].quality = 50;
        assert!(interpret(&report).is_empty());
    }

    #[test]
    fn unavailable_readings_are_not_shown_as_healthy() {
        let report = Report {
            adapters: Some(Err("GetAdaptersAddresses returned error 5".into())),
            hosts: Some(Err("access to the hosts file was denied".into())),
            ..Report::default()
        };
        let text = render(&report).join("\n");
        assert!(text.contains("unavailable: GetAdaptersAddresses"));
        assert!(text.contains("unavailable: access to the hosts file"));
        assert!(text.contains("none found, so not tested"));
        let mut offline = healthy();
        offline.gateway = gateway(
            Kind::Ethernet,
            Reach {
                error: Some("the ICMP handle could not be opened".into()),
                ..Reach::default()
            },
        );
        let findings = interpret(&offline);
        assert!(has(&findings, "could not be tested"), "{findings:?}");
    }

    #[test]
    fn json_agrees_with_the_text_and_the_hosts_file_names_only_what_matters() {
        let mut report = healthy();
        report.checked_at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_772_719_389));
        report.gateway = gateway(Kind::Ethernet, reach(10, 9, 1));
        report.servers = vec![silent("10.0.0.1")];
        report.hosts = Some(Ok(hosts::Hosts {
            entries: hosts::parse(
                "127.0.0.1 localhost\n0.0.0.0 www.microsoft.com\n10.0.0.9 nas.lan\n10.0.0.10 diary.example.org\n",
            ),
            cut_short: false,
        }));
        let data = report_json(&report);
        let text = render(&report).join("\n");
        assert_eq!(data["checked_at"], "2026-03-05T14:03:09Z");
        let finding = data["findings"][0].as_str().unwrap();
        assert!(finding.contains("dropped 10 %") && text.contains(finding));
        assert_eq!(
            data["reachability"]["default_gateway"]["echo"]["received"],
            9
        );
        assert_eq!(
            data["reachability"]["default_gateway"]["address"],
            "10.0.0.1"
        );
        assert!(text.contains("9 of 10 echoes answered, loss 10 %"));
        assert_eq!(data["dns"]["configured_servers"][0]["outcome"], "no_answer");
        assert!(text.contains("configured server 10.0.0.1: no answer within 2 s"));
        assert_eq!(data["adapters_up"][0]["link_speed_mbps"], 1000);
        assert_eq!(data["hosts_file"]["active_entries"], 4);
        assert_eq!(
            data["hosts_file"]["names_of_interest"][0]["name"],
            "www.microsoft.com"
        );
        assert_eq!(data["hosts_file"]["other_names"], 3);
        assert!(text.contains("4 active entries"));
        assert!(text.contains("www.microsoft.com -> 0.0.0.0 (well-known domain)"));
        assert!(text.contains("3 other names"));
        assert!(!text.contains("diary.example.org") && !text.contains("nas.lan"));
        assert!(!data.to_string().contains("diary.example.org"));
    }

    #[test]
    fn json_says_unavailable_readings_and_never_omits_them() {
        let report = Report {
            adapters: Some(Err("GetAdaptersAddresses returned error 5".into())),
            hosts: Some(Err("access to the hosts file was denied".into())),
            ..Report::default()
        };
        let data = report_json(&report);
        assert_eq!(
            data["adapters_up"]["unavailable"],
            "GetAdaptersAddresses returned error 5"
        );
        assert_eq!(
            data["hosts_file"]["unavailable"],
            "access to the hosts file was denied"
        );
        assert!(data["reachability"]["default_gateway"].is_null());
        assert_eq!(data["wifi"]["interfaces"], 0);
    }

    #[test]
    fn the_live_run_finishes_and_never_prints_a_hardware_address() {
        let start = Instant::now();
        let output = run(&Args::parse(&["--quick".to_string()], TOOL.usage).unwrap()).unwrap();
        let text = output.text;
        let json = output.data.to_string();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["tool"], "network");
        assert!(parsed["hosts_file"]["active_entries"].is_u64());
        let mac_in_json = json
            .split(|c: char| !(c.is_ascii_hexdigit() || c == '-' || c == ':'))
            .any(|w| w.len() == 17 && w.matches(['-', ':']).count() == 5);
        assert!(!mac_in_json, "a hardware address appears in the JSON");
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "{:?}",
            start.elapsed()
        );
        assert!(text.starts_with("Network check at"));
        for heading in [
            "Findings:",
            "Adapters that are up:",
            "Reachability",
            "DNS:",
            "Proxy:",
            "Hosts file:",
            "Wi-Fi:",
        ] {
            assert!(text.contains(heading), "missing {heading}");
        }
        let mac = text
            .split(|c: char| !(c.is_ascii_hexdigit() || c == '-' || c == ':'))
            .any(|w| w.len() == 17 && w.matches(['-', ':']).count() == 5);
        assert!(!mac, "a hardware address appears:\n{text}");
    }
}
