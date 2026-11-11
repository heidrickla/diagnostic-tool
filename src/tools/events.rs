//! Follow-up queries on the event log engine (`crate::events`).
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::{Args, Output, Tool};
use crate::events::{self, Group, Limit, LogRead, Query, ReadError, Summary, Tier};

pub const TOOL: Tool = Tool {
    name: "events",
    summary: "event log kinds ranked by significance, or one kind's message",
    usage: "\
Usage: toolkit events [options]
  --log NAME        log to read; repeat for more (default System and Application)
  --source NAME     only this event source; repeatable
  --id N            only this event id (0 to 65535); repeatable
  --level NAME      critical, error, warning, information or verbose; repeatable
                    (default critical, error and warning)
  --hours N         time range in hours, 1 to 8760, or
  --days N          time range in days (default 7, at most 365)
  --noise           also list kinds the noise table hides
  --top N           kinds to list, 1 to 10000 (default 30)
  --limit N         newest events read per log, 1 to 100000 (default 5000)
  --excerpt         print the newest message of one kind instead; needs one
                    --log, one --source and one --id",
    run,
};

fn run(args: &Args) -> Result<Output, String> {
    let mut query = Query::survey();
    query.logs = args.all("--log").to_vec();
    query.providers = args.all("--source").to_vec();
    query.ids = args
        .all("--id")
        .iter()
        .map(|id| id.parse().map_err(|_| format!("not an event id: {id}")))
        .collect::<Result<_, _>>()?;
    query.levels = args
        .all("--level")
        .iter()
        .map(|name| level(name))
        .collect::<Result<_, _>>()?;
    query.since = match args.value("--hours") {
        Some(_) => Duration::from_secs(3600 * args.number("--hours", 24, 1, 365 * 24)?),
        None => Duration::from_secs(24 * 3600 * args.number("--days", 7, 1, 365)?),
    };
    query.include_noise = args.switch("--noise");
    query.per_log_limit = args.number("--limit", 5000, 1, 100_000)? as usize;
    let top = args.number("--top", 30, 1, 10_000)? as usize;
    let cancelled = AtomicBool::new(false);
    if args.switch("--excerpt") {
        let ([log], [source], [id]) = (&query.logs[..], &query.providers[..], &query.ids[..])
        else {
            return Err("--excerpt needs one --log, one --source and one --id".into());
        };
        return match events::excerpt(log, source, *id, query.since, &cancelled) {
            Ok(found) => Ok(excerpt_output(log, source, *id, found)),
            Err(error) => Err(message(error)),
        };
    }
    if query.logs.is_empty() {
        query.logs = vec!["System".into(), "Application".into()];
    }
    if query.levels.is_empty() {
        query.levels = vec![1, 2, 3];
    }
    let summary = events::read(&query, Instant::now() + Duration::from_secs(60), &cancelled)
        .map_err(message)?;
    Ok(Output {
        text: events::report_lines(&query, &summary, top).join("\n"),
        data: survey_json(&query, &summary, top),
    })
}

fn excerpt_output(log: &str, source: &str, id: u32, found: Option<String>) -> Output {
    let text = match &found {
        Some(text) => text.clone(),
        None => format!("No {source} event {id} in {log} in that time range."),
    };
    Output {
        text,
        data: json!({
            "tool": "events",
            "mode": "excerpt",
            "log": log,
            "source": source,
            "id": id,
            "message": found,
        }),
    }
}

fn group_json(rank: usize, group: &Group) -> Value {
    let tier = group.tier().map(|tier| match tier {
        Tier::Serious => "serious",
        Tier::Notable => "notable",
    });
    json!({
        "rank": rank,
        "log": group.log,
        "source": group.provider,
        "id": group.id,
        "level": events::level_name(group.level),
        "count": group.count,
        "first": rfc3339(group.first),
        "last": rfc3339(group.last),
        "known_tier": tier,
        "known_label": group.known.map(|kind| kind.short),
        "meaning": group.known.map(|kind| kind.meaning),
        "routine_reason": group.noise.map(|rule| rule.reason),
    })
}

/// The ranked kinds and how each log was read, with the same cut-offs as the text.
fn survey_json(query: &Query, summary: &Summary, listed: usize) -> Value {
    let rest = &summary.groups[summary.groups.len().min(listed)..];
    json!({
        "tool": "events",
        "mode": "survey",
        "logs": query.logs,
        "levels": query.levels.iter().map(|&l| events::level_name(l)).collect::<Vec<_>>(),
        "since_seconds": query.since.as_secs(),
        "kinds": summary
            .groups
            .iter()
            .take(listed)
            .enumerate()
            .map(|(index, group)| group_json(index + 1, group))
            .collect::<Vec<_>>(),
        "not_listed": { "kinds": rest.len(), "events": rest.iter().map(|g| g.count).sum::<usize>() },
        "hidden_as_routine": {
            "kinds": summary.noise_kinds,
            "events": summary.noise_events,
            "noise_rules_version": events::NOISE_VERSION,
        },
        "logs_read": summary.reads.iter().map(read_json).collect::<Vec<_>>(),
    })
}

/// One log's read: how many events, and why it stopped short or was unavailable.
pub(crate) fn read_json(read: &LogRead) -> Value {
    json!({
        "log": read.log,
        "events_read": read.events,
        "unreadable": read.unreadable,
        "stopped_at_limit": read.limit.map(limit_name),
        "unavailable": read.unavailable,
    })
}

pub(crate) fn limit_name(limit: Limit) -> &'static str {
    match limit {
        Limit::Count => "event_count",
        Limit::Time => "time",
    }
}

/// An RFC 3339 UTC time such as `2026-11-05T14:03:09Z`.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (days, rest) = ((seconds / 86_400) as i64, seconds % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// A reading the tool could not take, with the reason, never left out.
pub(crate) fn unavailable(reason: &str) -> Value {
    json!({ "unavailable": reason })
}

fn level(text: &str) -> Result<u8, String> {
    Ok(match text.to_ascii_lowercase().as_str() {
        "critical" => 1,
        "error" => 2,
        "warning" => 3,
        "information" => 4,
        "verbose" => 5,
        _ => return Err(format!("not a level: {text}")),
    })
}

pub(crate) fn message(error: ReadError) -> String {
    match error {
        ReadError::Cancelled => "Canceled".into(),
        ReadError::Invalid(reason) => format!("Refused: {reason}"),
        ReadError::Unavailable(reason) => format!("Unavailable: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::summarize;

    fn event(provider: &str, id: u32, level: u8, secs: u64) -> events::Event {
        events::Event {
            log: "System".into(),
            provider: provider.into(),
            id,
            level,
            time: UNIX_EPOCH + Duration::from_secs(secs),
            message: None,
        }
    }

    #[test]
    fn times_are_rfc_3339_utc() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let time = UNIX_EPOCH + Duration::from_secs(1_772_719_389);
        assert_eq!(rfc3339(time), "2026-03-05T14:03:09Z");
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_164_800 + 86_399);
        assert_eq!(rfc3339(leap), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn survey_json_agrees_with_the_text() {
        let now = SystemTime::now();
        let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let found = vec![
            event("Microsoft-Windows-Kernel-Power", 41, 1, secs - 100),
            event("Microsoft-Windows-Kernel-Power", 41, 1, secs - 50),
            event("Microsoft-Windows-DistributedCOM", 10016, 3, secs - 10),
            event("Odd", 7, 2, secs - 5),
        ];
        let reads = vec![
            LogRead {
                log: "System".into(),
                events: 4,
                unreadable: 1,
                limit: Some(Limit::Count),
                unavailable: None,
            },
            LogRead {
                log: "Application".into(),
                events: 0,
                unreadable: 0,
                limit: None,
                unavailable: Some("needs administrator rights".into()),
            },
        ];
        let summary = summarize(&found, now, false, reads);
        let mut query = Query::survey();
        query.logs = vec!["System".into(), "Application".into()];
        query.levels = vec![1, 2, 3];
        let data = survey_json(&query, &summary, 1);
        let text = events::report_lines(&query, &summary, 1).join("\n");
        assert_eq!(data["kinds"][0]["id"], 41);
        assert_eq!(data["kinds"][0]["count"], 2);
        assert_eq!(data["kinds"][0]["known_tier"], "serious");
        assert!(text.contains("Kernel-Power event 41") && text.contains("twice"));
        assert_eq!(data["not_listed"]["kinds"], 1);
        assert!(text.contains("Not listed: 1 more kind, 1 event"));
        assert_eq!(data["hidden_as_routine"]["events"], 1);
        assert!(text.contains("Hidden as routine: 1 event of 1 kind"));
        assert_eq!(data["logs_read"][0]["stopped_at_limit"], "event_count");
        assert_eq!(
            data["logs_read"][1]["unavailable"],
            "needs administrator rights"
        );
        assert!(text.contains("Application: unavailable, needs administrator rights."));
        let parsed: Value = serde_json::from_str(&serde_json::to_string(&data).unwrap()).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn json_output_of_a_live_run_parses() {
        let args = ["--hours", "1", "--limit", "50", "--json"].map(String::from);
        let text = crate::tools::run("events", &args).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["tool"], "events");
        assert!(parsed["logs_read"].as_array().unwrap().len() == 2);
        assert!(parsed["kinds"].is_array());
    }

    #[test]
    fn excerpt_json_names_a_missing_event() {
        let output = excerpt_output("System", "disk", 7, None);
        assert!(output.text.starts_with("No disk event 7"));
        assert!(output.data["message"].is_null());
        let output = excerpt_output("System", "disk", 7, Some("text".into()));
        assert_eq!(output.data["message"], "text");
        assert_eq!(output.text, "text");
    }
}
