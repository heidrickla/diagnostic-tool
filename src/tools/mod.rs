//! The toolkit: read-only tools for a technician and an AI model to use while fixing a PC, so a
//! repair does not depend on what the PC happens to have installed. Each tool takes
//! command-line style arguments and returns plain text for people and, with `--json`, the
//! same readings as JSON for the AI model; `toolkit` runs them from a console.
use std::collections::{HashMap, HashSet};

pub mod battery;
pub mod cleanup;
pub mod cpu_memory;
pub mod crash_dumps;
pub mod crashes;
pub mod drivers;
pub mod drives;
pub mod events;
pub mod hash;
pub mod network;
pub mod perf;
pub mod space;
pub mod space_map;
pub mod startup;
pub mod timeline;
pub mod updates;

pub struct Tool {
    pub name: &'static str,
    /// One line for `toolkit help`.
    pub summary: &'static str,
    /// Usage text shown by `toolkit <name> --help`.
    pub usage: &'static str,
    pub run: fn(&Args) -> Result<Output, String>,
}

/// One tool's result: text for people and the same readings as JSON for the AI model.
#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    pub text: String,
    /// `Value::Null` until the tool has a JSON form.
    pub data: serde_json::Value,
}

impl Output {
    pub fn text(text: String) -> Self {
        Self {
            text,
            data: serde_json::Value::Null,
        }
    }
}

/// In the order they were built, after the event engine they build on.
pub const TOOLS: &[Tool] = &[
    events::TOOL,
    timeline::TOOL,
    crashes::TOOL,
    drives::TOOL,
    startup::TOOL,
    network::TOOL,
    perf::TOOL,
    battery::TOOL,
    space::TOOL,
    hash::TOOL,
    drivers::TOOL,
    updates::TOOL,
];

pub fn find(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|tool| tool.name == name)
}

/// Runs a tool by name. `--help` prints its usage; `--json`, accepted by every tool,
/// prints the readings as JSON instead of text.
pub fn run(name: &str, args: &[String]) -> Result<String, String> {
    let tool = find(name).ok_or_else(|| format!("no tool named {name}\n{}", list()))?;
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(tool.usage.into());
    }
    let json = args.iter().any(|arg| arg == "--json");
    let rest: Vec<String> = args
        .iter()
        .filter(|arg| *arg != "--json")
        .cloned()
        .collect();
    let output = (tool.run)(&Args::parse(&rest, tool.usage)?)?;
    if !json {
        return Ok(output.text);
    }
    if output.data.is_null() {
        return Err(format!("{name} has no JSON output yet"));
    }
    serde_json::to_string_pretty(&output.data).map_err(|error| error.to_string())
}

pub fn list() -> String {
    let mut text = String::from("Tools:\n");
    for tool in TOOLS {
        text.push_str(&format!("  {:<10} {}\n", tool.name, tool.summary));
    }
    text.push_str("Run `toolkit <tool> --help` for a tool's options; `--json` gives JSON.");
    text
}

/// Parsed `--flag value` and `--switch` arguments. A flag takes a value when the tool's
/// usage text shows it as `--flag N` or `--flag NAME` (an upper-case word after it).
#[derive(Debug, Default, PartialEq)]
pub struct Args {
    values: HashMap<String, Vec<String>>,
    switches: HashSet<String>,
}

impl Args {
    pub fn parse(args: &[String], usage: &str) -> Result<Self, String> {
        let known = flags(usage);
        let mut parsed = Self::default();
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            match known.get(flag.as_str()) {
                Some(true) => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{flag} needs a value\n{usage}"))?;
                    parsed
                        .values
                        .entry(flag.clone())
                        .or_default()
                        .push(value.clone());
                }
                Some(false) => {
                    parsed.switches.insert(flag.clone());
                }
                None => return Err(format!("unknown option {flag}\n{usage}")),
            }
        }
        Ok(parsed)
    }

    pub fn switch(&self, flag: &str) -> bool {
        self.switches.contains(flag)
    }

    /// Every value given for a repeatable flag, in order.
    pub fn all(&self, flag: &str) -> &[String] {
        self.values.get(flag).map_or(&[], Vec::as_slice)
    }

    /// The last value given for a flag.
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.all(flag).last().map(String::as_str)
    }

    /// A whole number within `min..=max`, or `default` when the flag is absent.
    pub fn number(&self, flag: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
        let Some(text) = self.value(flag) else {
            return Ok(default);
        };
        let value: u64 = text
            .parse()
            .map_err(|_| format!("{flag} takes a whole number, not {text}"))?;
        if !(min..=max).contains(&value) {
            return Err(format!("{flag} must be from {min} to {max}"));
        }
        Ok(value)
    }
}

/// Most arguments, and longest argument, a live session's request may carry.
pub const REMOTE_ARGS: usize = 16;
pub const REMOTE_ARG_CHARS: usize = 64;

/// Checks a live session's arguments before the request is accepted: plain tokens only,
/// flags from the tool's usage, and whole numbers within any range the usage states.
pub fn check_remote(tool: &Tool, args: &[String]) -> Result<(), String> {
    if args.len() > REMOTE_ARGS {
        return Err(format!("at most {REMOTE_ARGS} arguments"));
    }
    for arg in args {
        let plain = arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '\\'));
        if arg.is_empty() || arg.chars().count() > REMOTE_ARG_CHARS || !plain {
            return Err(format!(
                "an argument is not a plain token (letters, digits and ._:-\\, 1 to {REMOTE_ARG_CHARS} characters)"
            ));
        }
    }
    let parsed = Args::parse(args, tool.usage)
        .map_err(|error| error.lines().next().unwrap_or_default().to_owned())?;
    for (flag, range) in numeric_flags(tool.usage) {
        for text in parsed.all(flag) {
            let value: u64 = text
                .parse()
                .map_err(|_| format!("{flag} takes a whole number, not {text}"))?;
            if let Some((min, max)) = range {
                if value < min || value > max {
                    return Err(format!("{flag} must be from {min} to {max}"));
                }
            }
        }
    }
    Ok(())
}

/// Flags whose usage placeholder is `N`, with the range their option line states
/// ("1 to 365", "at most 365"), if it states one.
fn numeric_flags(usage: &str) -> HashMap<&str, Option<(u64, u64)>> {
    let trim = |word: &str| -> String {
        word.trim_matches(|c: char| matches!(c, '[' | ']' | '|' | ',' | ';' | '(' | ')' | '.'))
            .to_owned()
    };
    let mut numeric = HashMap::new();
    let words: Vec<&str> = usage.split_whitespace().collect();
    for pair in words.windows(2) {
        let flag = pair[0].trim_matches(|c: char| matches!(c, '[' | ']' | '|' | ',' | '(' | ')'));
        if flag.starts_with("--") && trim(pair[1]) == "N" {
            numeric.insert(flag, None);
        }
    }
    for line in usage.lines() {
        let words: Vec<String> = line.split_whitespace().map(trim).collect();
        let Some(entry) = words
            .first()
            .and_then(|flag| numeric.get_mut(flag.as_str()))
        else {
            continue;
        };
        let number = |index: usize| words.get(index).and_then(|w| w.parse::<u64>().ok());
        for index in 1..words.len() {
            if words[index] == "to" {
                if let (Some(min), Some(max)) = (number(index - 1), number(index + 1)) {
                    *entry = Some((min, max));
                }
            } else if words[index] == "at" && words.get(index + 1).is_some_and(|w| w == "most") {
                if let Some(max) = number(index + 2) {
                    *entry = Some((0, max));
                }
            }
        }
    }
    numeric
}

/// Flags named in a usage text, and whether each takes a value.
fn flags(usage: &str) -> HashMap<&str, bool> {
    let mut known = HashMap::new();
    let words: Vec<&str> = usage.split_whitespace().collect();
    for (index, word) in words.iter().enumerate() {
        let word = word.trim_matches(|c: char| matches!(c, '[' | ']' | '|' | ',' | '(' | ')'));
        if let Some(name) = word.strip_prefix("--") {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                continue;
            }
            let takes = words.get(index + 1).is_some_and(|next| {
                let next = next.trim_matches(|c: char| matches!(c, '[' | ']' | ',' | '.'));
                !next.is_empty() && next.chars().all(|c| c.is_ascii_uppercase())
            });
            let entry = known.entry(word).or_insert(false);
            *entry |= takes;
        }
    }
    known
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn flags_take_values_only_where_the_usage_shows_one() {
        let usage = "Usage: toolkit x [--log NAME]... [--days N] --noise | --top N";
        let args = Args::parse(
            &strings(&["--log", "System", "--noise", "--log", "Setup"]),
            usage,
        )
        .unwrap();
        assert_eq!(args.all("--log"), ["System", "Setup"]);
        assert!(args.switch("--noise"));
        assert_eq!(args.number("--days", 7, 1, 90), Ok(7));
        assert!(Args::parse(&strings(&["--bogus"]), usage).is_err());
        assert!(Args::parse(&strings(&["--days"]), usage).is_err());
        let days = Args::parse(&strings(&["--days", "200"]), usage).unwrap();
        assert!(days.number("--days", 7, 1, 90).is_err());
    }

    #[test]
    fn remote_arguments_are_plain_known_and_within_the_stated_range() {
        let tool = find("crashes").unwrap();
        assert_eq!(check_remote(tool, &strings(&["--days", "30"])), Ok(()));
        assert_eq!(check_remote(tool, &[]), Ok(()));
        let range = check_remote(tool, &strings(&["--days", "366"])).unwrap_err();
        assert!(range.contains("1 to 365"), "{range}");
        assert!(check_remote(tool, &strings(&["--days", "0"])).is_err());
        assert!(check_remote(tool, &strings(&["--days", "ten"])).is_err());
        assert!(check_remote(tool, &strings(&["--bogus"])).is_err());
        assert!(check_remote(tool, &strings(&["--json"])).is_err());
        assert!(check_remote(tool, &strings(&["--help"])).is_err());
        let events = find("events").unwrap();
        assert!(check_remote(events, &strings(&["--days", "400"])).is_err());
        for (flag, over) in [
            ("--hours", "8761"),
            ("--top", "10001"),
            ("--limit", "100001"),
            ("--id", "65536"),
        ] {
            assert!(
                check_remote(events, &strings(&[flag, over])).is_err(),
                "{flag}"
            );
        }
        assert_eq!(
            check_remote(events, &strings(&["--id", "41", "--top", "10000"])),
            Ok(())
        );
        assert_eq!(
            check_remote(
                events,
                &strings(&["--source", "Microsoft-Windows-Kernel-Power"])
            ),
            Ok(())
        );
        for bad in ["System;x", "a b", "a/b", "$(x)", "", "é"] {
            assert!(
                check_remote(events, &strings(&["--log", bad])).is_err(),
                "{bad}"
            );
        }
        assert!(check_remote(events, &strings(&["--log", &"L".repeat(65)])).is_err());
        let many: Vec<String> = (0..9).flat_map(|_| strings(&["--log", "System"])).collect();
        assert!(check_remote(events, &many).is_err());
    }

    #[test]
    fn every_tool_is_listed_once_with_usage() {
        let mut names = HashSet::new();
        for tool in TOOLS {
            assert!(names.insert(tool.name), "{} twice", tool.name);
            assert!(
                tool.usage.contains(tool.name),
                "{} usage does not name it",
                tool.name
            );
            assert!(!tool.summary.is_empty());
        }
    }
}
