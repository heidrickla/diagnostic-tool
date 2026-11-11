//! In-memory protocol model. `fixture` identities and pairing codes are test data,
//! not authentication credentials or a network transport.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::tools::{self, Tool};

pub const PAIR_TTL_SECONDS: u64 = 120;
pub const SESSION_TTL_SECONDS: u64 = 300;
pub const COMMAND_TTL_SECONDS: u64 = 12;
pub const OUTPUT_LIMIT_BYTES: usize = 4096;
static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureIdentity {
    id: u64,
    role: Role,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Operator,
    Friend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Diagnostics,
    Inventory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    pub operator_display: String,
    pub expires_at: u64,
    pub scope: Vec<Scope>,
    fixture_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    pub command_id: &'static str,
    pub deadline: u64,
    pub output_limit: usize,
}

#[derive(Clone)]
pub struct Dispatch {
    pub request: Request,
    /// Typed arguments, checked against the command before the request was accepted.
    pub args: Vec<String>,
    pub cancel: Arc<AtomicBool>,
}

impl Dispatch {
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongIdentity,
    Expired,
    InvalidPairing,
    NoConsent,
    WrongScope,
    Replay,
    Busy,
    NotPending,
    OutputLimit,
    InvalidOutput,
    Disconnected,
    InvalidArguments,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub at: u64,
    pub action: &'static str,
    pub request_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    pub paired: bool,
    pub disconnected: bool,
    pub expires_at: u64,
    pub pending_request: Option<u64>,
}

struct Pending {
    dispatch: Dispatch,
    claimed: bool,
}

pub struct FixtureBroker {
    operator: FixtureIdentity,
    friend: FixtureIdentity,
    invitation: Invitation,
    session_expires: u64,
    paired: bool,
    disconnected: bool,
    seen: HashSet<u64>,
    results: HashMap<u64, String>,
    pending: Option<Pending>,
    audit: Vec<AuditEvent>,
}

/// A fixture constructor. The caller supplies a known test code; a production
/// implementation must use authenticated TLS identities and a CSPRNG ticket.
pub fn fixture(
    now: u64,
    code: &str,
) -> (FixtureBroker, FixtureIdentity, FixtureIdentity, Invitation) {
    let base = FIXTURE_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .saturating_mul(2);
    let operator = FixtureIdentity {
        id: base,
        role: Role::Operator,
    };
    let friend = FixtureIdentity {
        id: base + 1,
        role: Role::Friend,
    };
    let invitation = Invitation {
        operator_display: "Fixture Operator (fixture identity)".into(),
        expires_at: now.saturating_add(PAIR_TTL_SECONDS),
        scope: vec![Scope::Diagnostics, Scope::Inventory],
        fixture_code: code.into(),
    };
    let broker = FixtureBroker {
        operator: operator.clone(),
        friend: friend.clone(),
        invitation: invitation.clone(),
        session_expires: now.saturating_add(SESSION_TTL_SECONDS),
        paired: false,
        disconnected: false,
        seen: HashSet::new(),
        results: HashMap::new(),
        pending: None,
        audit: vec![AuditEvent {
            at: now,
            action: "invitation_created",
            request_id: None,
        }],
    };
    (broker, operator, friend, invitation)
}

pub const TOOLKIT_PREFIX: &str = "toolkit.";

/// The toolkit tool a `toolkit.<name>` command runs.
pub fn toolkit_tool(command_id: &str) -> Option<&'static Tool> {
    command_id
        .strip_prefix(TOOLKIT_PREFIX)
        .and_then(tools::find)
}

/// `toolkit.<name>` for every tool in `tools::TOOLS`, built once.
pub fn toolkit_commands() -> &'static [&'static str] {
    static IDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| {
        tools::TOOLS
            .iter()
            .map(|tool| &*Box::leak(format!("{TOOLKIT_PREFIX}{}", tool.name).into_boxed_str()))
            .collect()
    })
}

/// How long a toolkit tool may take, from its own time bound.
#[derive(Clone, Copy, Debug)]
pub enum Bound {
    Fixed(u64),
    /// The value of a `--seconds`-style flag, or its default.
    Flag(&'static str, u64),
    /// One bound with the switch, another without.
    Switch(&'static str, u64, u64),
}

/// Seconds added to every toolkit bound for start-up, rendering and upload.
pub const TOOLKIT_MARGIN_SECONDS: u64 = 5;

/// Each toolkit tool's time bound, from the limit in its code or usage.
pub const TOOLKIT_BOUNDS: &[(&str, Bound)] = &[
    ("events", Bound::Fixed(60)),
    ("timeline", Bound::Fixed(30)),
    ("crashes", Bound::Fixed(20)),
    ("drives", Bound::Fixed(20)),
    ("startup", Bound::Fixed(30)),
    ("network", Bound::Switch("--quick", 10, 30)),
    ("perf", Bound::Flag("--seconds", 30)),
    ("battery", Bound::Fixed(5)),
    ("space", Bound::Flag("--seconds", 60)),
    ("hash", Bound::Fixed(30)),
    ("drivers", Bound::Fixed(25)),
    ("updates", Bound::Fixed(28)),
];

fn bound(name: &str) -> Option<Bound> {
    TOOLKIT_BOUNDS
        .iter()
        .find(|(tool, _)| *tool == name)
        .map(|(_, bound)| *bound)
}

/// A command's own deadline in seconds: a toolkit tool's bound for these arguments, or
/// the inventory's, plus the margin. `None` for the other fixed diagnostics, which keep
/// the relay's 15 seconds.
pub fn toolkit_seconds(command_id: &str, args: &[String]) -> Option<u64> {
    if command_id == "hardware.inventory" {
        return Some(crate::runner::INVENTORY_TIME.as_secs() + TOOLKIT_MARGIN_SECONDS);
    }
    let tool = toolkit_tool(command_id)?;
    let parsed = tools::Args::parse(args, tool.usage).ok()?;
    let seconds = match bound(tool.name)? {
        Bound::Fixed(seconds) => seconds,
        Bound::Flag(flag, default) => parsed
            .value(flag)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default),
        Bound::Switch(flag, on, off) => {
            if parsed.switch(flag) {
                on
            } else {
                off
            }
        }
    };
    Some(seconds.saturating_add(TOOLKIT_MARGIN_SECONDS))
}

/// The deadline as the operator's catalog states it.
pub fn toolkit_deadline_text(name: &str) -> Option<String> {
    let margin = TOOLKIT_MARGIN_SECONDS;
    Some(match bound(name)? {
        Bound::Fixed(seconds) => format!("deadline {} s", seconds + margin),
        Bound::Flag(flag, default) => format!(
            "deadline the {flag} value plus {margin} s ({} s by default)",
            default + margin
        ),
        Bound::Switch(flag, on, off) => format!(
            "deadline {} s, or {} s with {flag}",
            off + margin,
            on + margin
        ),
    })
}

/// Checks a command's typed arguments: a toolkit tool's against its usage flags; the
/// fixed diagnostics take none.
pub fn check_arguments(command_id: &str, args: &[String]) -> Result<(), String> {
    match toolkit_tool(command_id) {
        Some(tool) => tools::check_remote(tool, args),
        None if args.is_empty() => Ok(()),
        None => Err(format!("{command_id} takes no arguments")),
    }
}

/// A toolkit result as uploaded: text lines, no other control characters.
pub fn toolkit_output_valid(output: &str) -> bool {
    !output.trim().is_empty()
        && output
            .chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\t')
}

fn required_scope(command_id: &str) -> Option<Scope> {
    match command_id {
        "os.version" | "memory.total" | "disk.free" => Some(Scope::Diagnostics),
        "hardware.inventory" => Some(Scope::Inventory),
        id if toolkit_tool(id).is_some() => Some(Scope::Diagnostics),
        _ => None,
    }
}

impl FixtureBroker {
    fn live(&mut self, now: u64) -> Result<(), Refusal> {
        if self.disconnected {
            return Err(Refusal::Disconnected);
        }
        if now >= self.session_expires {
            self.disconnect_internal(now);
            return Err(Refusal::Expired);
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.dispatch.request.deadline)
        {
            if let Some(expired) = self.pending.take() {
                expired.dispatch.cancel.store(true, Ordering::SeqCst);
                self.audit.push(AuditEvent {
                    at: now,
                    action: "command_expired",
                    request_id: Some(expired.dispatch.request.id),
                });
            }
        }
        Ok(())
    }

    fn disconnect_internal(&mut self, now: u64) {
        self.disconnected = true;
        if let Some(pending) = self.pending.take() {
            pending.dispatch.cancel.store(true, Ordering::SeqCst);
        }
        self.results.clear();
        self.audit.push(AuditEvent {
            at: now,
            action: "disconnected",
            request_id: None,
        });
    }

    pub fn pair(&mut self, peer: &FixtureIdentity, code: &str, now: u64) -> Result<(), Refusal> {
        self.live(now)?;
        if peer != &self.friend {
            return Err(Refusal::WrongIdentity);
        }
        if self.paired || now >= self.invitation.expires_at || code != self.invitation.fixture_code
        {
            return Err(Refusal::InvalidPairing);
        }
        self.paired = true;
        self.audit.push(AuditEvent {
            at: now,
            action: "friend_consented",
            request_id: None,
        });
        Ok(())
    }

    pub fn operator_request(
        &mut self,
        peer: &FixtureIdentity,
        request: Request,
        now: u64,
    ) -> Result<(), Refusal> {
        self.operator_request_with_args(peer, request, Vec::new(), now)
    }

    /// A request with typed arguments, refused unless they fit the command's usage.
    pub fn operator_request_with_args(
        &mut self,
        peer: &FixtureIdentity,
        request: Request,
        args: Vec<String>,
        now: u64,
    ) -> Result<(), Refusal> {
        self.live(now)?;
        if peer != &self.operator {
            return Err(Refusal::WrongIdentity);
        }
        if !self.paired {
            return Err(Refusal::NoConsent);
        }
        let needed = required_scope(request.command_id).ok_or(Refusal::WrongScope)?;
        if !self.invitation.scope.contains(&needed) {
            return Err(Refusal::WrongScope);
        }
        check_arguments(request.command_id, &args).map_err(|_| Refusal::InvalidArguments)?;
        let ttl = toolkit_seconds(request.command_id, &args).unwrap_or(COMMAND_TTL_SECONDS);
        if request.deadline <= now
            || request.deadline > now.saturating_add(ttl)
            || request.deadline > self.session_expires
            || request.output_limit == 0
            || request.output_limit > OUTPUT_LIMIT_BYTES
        {
            return Err(Refusal::Expired);
        }
        if self.seen.contains(&request.id) {
            return Err(Refusal::Replay);
        }
        if self.pending.is_some() {
            return Err(Refusal::Busy);
        }
        self.seen.insert(request.id);
        self.audit.push(AuditEvent {
            at: now,
            action: "command_requested",
            request_id: Some(request.id),
        });
        self.pending = Some(Pending {
            dispatch: Dispatch {
                request,
                args,
                cancel: Arc::new(AtomicBool::new(false)),
            },
            claimed: false,
        });
        Ok(())
    }

    pub fn client_claim(&mut self, peer: &FixtureIdentity, now: u64) -> Result<Dispatch, Refusal> {
        self.live(now)?;
        if peer != &self.friend {
            return Err(Refusal::WrongIdentity);
        }
        if !self.paired {
            return Err(Refusal::NoConsent);
        }
        let pending = self.pending.as_mut().ok_or(Refusal::NotPending)?;
        if pending.claimed {
            return Err(Refusal::Replay);
        }
        if now >= pending.dispatch.request.deadline {
            pending.dispatch.cancel.store(true, Ordering::SeqCst);
            return Err(Refusal::Expired);
        }
        pending.claimed = true;
        self.audit.push(AuditEvent {
            at: now,
            action: "client_claimed",
            request_id: Some(pending.dispatch.request.id),
        });
        Ok(pending.dispatch.clone())
    }

    pub fn client_result(
        &mut self,
        peer: &FixtureIdentity,
        request_id: u64,
        output: &str,
        now: u64,
    ) -> Result<(), Refusal> {
        self.live(now)?;
        if peer != &self.friend {
            return Err(Refusal::WrongIdentity);
        }
        let pending = self.pending.as_ref().ok_or(Refusal::NotPending)?;
        if !pending.claimed || pending.dispatch.request.id != request_id {
            return Err(Refusal::NotPending);
        }
        if pending.dispatch.is_cancelled() || now >= pending.dispatch.request.deadline {
            return Err(Refusal::Expired);
        }
        if output.len() > pending.dispatch.request.output_limit {
            return Err(Refusal::OutputLimit);
        }
        let normalized = if toolkit_tool(pending.dispatch.request.command_id).is_some() {
            if !toolkit_output_valid(output) {
                return Err(Refusal::InvalidOutput);
            }
            output.to_string()
        } else if pending.dispatch.request.command_id == "hardware.inventory" {
            crate::checks::parse_inventory(output)
                .map_err(|_| Refusal::InvalidOutput)?
                .into_iter()
                .map(|(key, value)| format!("{key}={value}\n"))
                .collect()
        } else {
            let value = output.trim();
            if value.is_empty()
                || value.len() > 80
                || !value.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
            {
                return Err(Refusal::InvalidOutput);
            }
            value.to_string()
        };
        self.results.insert(request_id, normalized);
        self.pending = None;
        self.audit.push(AuditEvent {
            at: now,
            action: "result_accepted",
            request_id: Some(request_id),
        });
        Ok(())
    }

    pub fn cancel(
        &mut self,
        peer: &FixtureIdentity,
        request_id: u64,
        now: u64,
    ) -> Result<(), Refusal> {
        self.live(now)?;
        if peer != &self.operator && peer != &self.friend {
            return Err(Refusal::WrongIdentity);
        }
        let pending = self.pending.take().ok_or(Refusal::NotPending)?;
        if pending.dispatch.request.id != request_id {
            self.pending = Some(pending);
            return Err(Refusal::NotPending);
        }
        pending.dispatch.cancel.store(true, Ordering::SeqCst);
        self.audit.push(AuditEvent {
            at: now,
            action: "command_cancelled",
            request_id: Some(request_id),
        });
        Ok(())
    }

    pub fn disconnect(&mut self, peer: &FixtureIdentity, now: u64) -> Result<(), Refusal> {
        if peer != &self.friend {
            return Err(Refusal::WrongIdentity);
        }
        self.disconnect_internal(now);
        Ok(())
    }

    pub fn operator_end_session(
        &mut self,
        peer: &FixtureIdentity,
        now: u64,
    ) -> Result<(), Refusal> {
        if peer != &self.operator {
            return Err(Refusal::WrongIdentity);
        }
        self.disconnect_internal(now);
        Ok(())
    }

    pub fn status(&self, peer: &FixtureIdentity) -> Result<SessionStatus, Refusal> {
        if peer != &self.operator && peer != &self.friend {
            return Err(Refusal::WrongIdentity);
        }
        Ok(SessionStatus {
            paired: self.paired,
            disconnected: self.disconnected,
            expires_at: self.session_expires,
            pending_request: self
                .pending
                .as_ref()
                .map(|pending| pending.dispatch.request.id),
        })
    }

    pub fn audit(&self) -> &[AuditEvent] {
        &self.audit
    }

    pub fn operator_result(
        &mut self,
        peer: &FixtureIdentity,
        request_id: u64,
        now: u64,
    ) -> Result<Option<&str>, Refusal> {
        self.live(now)?;
        if peer != &self.operator {
            return Err(Refusal::WrongIdentity);
        }
        Ok(self.results.get(&request_id).map(String::as_str))
    }
}

/// Operator-side MCP adapter shape. There is no socket or MCP registration here.
pub struct FixtureOperatorAdapter<'a> {
    broker: &'a mut FixtureBroker,
    operator: FixtureIdentity,
}
impl<'a> FixtureOperatorAdapter<'a> {
    pub fn new(broker: &'a mut FixtureBroker, operator: FixtureIdentity) -> Self {
        Self { broker, operator }
    }
    /// The fixed diagnostics, then `toolkit.<name>` for every toolkit tool.
    pub fn command_catalog(&self) -> &'static [&'static str] {
        static CATALOG: OnceLock<Vec<&'static str>> = OnceLock::new();
        CATALOG.get_or_init(|| {
            let fixed = [
                "os.version",
                "memory.total",
                "disk.free",
                "hardware.inventory",
            ];
            fixed
                .into_iter()
                .chain(toolkit_commands().iter().copied())
                .collect()
        })
    }
    pub fn request_command(&mut self, request: Request, now: u64) -> Result<(), Refusal> {
        self.broker.operator_request(&self.operator, request, now)
    }
    pub fn request_tool(
        &mut self,
        request: Request,
        args: Vec<String>,
        now: u64,
    ) -> Result<(), Refusal> {
        self.broker
            .operator_request_with_args(&self.operator, request, args, now)
    }
    pub fn cancel_command(&mut self, request_id: u64, now: u64) -> Result<(), Refusal> {
        self.broker.cancel(&self.operator, request_id, now)
    }
    pub fn activity_log(&self) -> &[AuditEvent] {
        self.broker.audit()
    }
    pub fn command_result(&mut self, request_id: u64, now: u64) -> Result<Option<&str>, Refusal> {
        self.broker.operator_result(&self.operator, request_id, now)
    }
    pub fn session_status(&self) -> Result<SessionStatus, Refusal> {
        self.broker.status(&self.operator)
    }
    pub fn end_session(&mut self, now: u64) -> Result<(), Refusal> {
        self.broker.operator_end_session(&self.operator, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(id: u64, command_id: &'static str) -> Request {
        Request {
            id,
            command_id,
            deadline: 10,
            output_limit: 128,
        }
    }

    #[test]
    fn pairing_binds_friend_and_expires_or_replays() {
        let (mut broker, operator, friend, _) = fixture(0, "fixture-code");
        assert_eq!(
            broker.pair(&operator, "fixture-code", 1),
            Err(Refusal::WrongIdentity)
        );
        assert_eq!(
            broker.pair(&friend, "wrong", 1),
            Err(Refusal::InvalidPairing)
        );
        assert_eq!(
            broker.pair(&friend, "fixture-code", 120),
            Err(Refusal::InvalidPairing)
        );
        let (mut broker, _, friend, _) = fixture(0, "fixture-code");
        assert_eq!(broker.pair(&friend, "fixture-code", 1), Ok(()));
        assert_eq!(
            broker.pair(&friend, "fixture-code", 2),
            Err(Refusal::InvalidPairing)
        );
    }

    #[test]
    fn fixture_identity_from_another_session_cannot_cross_bind() {
        let (mut broker_a, operator_a, friend_a, _) = fixture(0, "same-code");
        let (_, operator_b, friend_b, _) = fixture(0, "same-code");
        assert_eq!(
            broker_a.pair(&friend_b, "same-code", 1),
            Err(Refusal::WrongIdentity)
        );
        broker_a.pair(&friend_a, "same-code", 1).unwrap();
        assert_eq!(
            broker_a.operator_request(&operator_b, req(1, "os.version"), 2),
            Err(Refusal::WrongIdentity)
        );
        broker_a
            .operator_request(&operator_a, req(1, "os.version"), 2)
            .unwrap();
    }

    #[test]
    fn operator_and_client_roles_scope_and_replay_are_enforced() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        assert_eq!(
            broker.operator_request(&operator, req(1, "os.version"), 1),
            Err(Refusal::NoConsent)
        );
        broker.pair(&friend, "code", 1).unwrap();
        assert_eq!(
            broker.operator_request(&friend, req(1, "os.version"), 2),
            Err(Refusal::WrongIdentity)
        );
        assert_eq!(
            broker.operator_request(&operator, req(1, "screen.capture"), 2),
            Err(Refusal::WrongScope)
        );
        broker
            .operator_request(&operator, req(1, "os.version"), 2)
            .unwrap();
        assert_eq!(
            broker.operator_request(&operator, req(1, "os.version"), 3),
            Err(Refusal::Replay)
        );
        assert_eq!(
            broker.client_claim(&operator, 3).err(),
            Some(Refusal::WrongIdentity)
        );
        let dispatch = broker.client_claim(&friend, 3).unwrap();
        assert_eq!(dispatch.request.id, 1);
        assert_eq!(broker.client_claim(&friend, 4).err(), Some(Refusal::Replay));
        broker.client_result(&friend, 1, "10.0", 4).unwrap();
        assert_eq!(
            broker.client_result(&friend, 1, "10.0", 5),
            Err(Refusal::NotPending)
        );
    }

    #[test]
    fn disconnect_cancels_pending_and_rejects_late_result() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        broker
            .operator_request(&operator, req(3, "disk.free"), 2)
            .unwrap();
        let dispatch = broker.client_claim(&friend, 3).unwrap();
        broker.disconnect(&friend, 4).unwrap();
        assert!(dispatch.is_cancelled());
        assert_eq!(
            broker.client_result(&friend, 3, "42", 5),
            Err(Refusal::Disconnected)
        );
        assert_eq!(
            broker.operator_request(&operator, req(4, "disk.free"), 5),
            Err(Refusal::Disconnected)
        );
    }

    #[test]
    fn deadlines_caps_and_session_expiry_fail_closed() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        assert_eq!(
            broker.operator_request(
                &operator,
                Request {
                    id: 1,
                    deadline: 30,
                    ..req(1, "os.version")
                },
                2
            ),
            Err(Refusal::Expired)
        );
        assert_eq!(
            broker.operator_request(
                &operator,
                Request {
                    id: 1,
                    output_limit: 5000,
                    ..req(1, "os.version")
                },
                2
            ),
            Err(Refusal::Expired)
        );
        broker
            .operator_request(&operator, req(1, "os.version"), 2)
            .unwrap();
        broker.client_claim(&friend, 3).unwrap();
        assert_eq!(
            broker.client_result(&friend, 1, &"X".repeat(129), 4),
            Err(Refusal::OutputLimit)
        );
        assert_eq!(
            broker.operator_request(&operator, req(2, "disk.free"), 300),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn expired_request_is_cancelled_and_does_not_block_next_request() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        broker
            .operator_request(&operator, req(1, "disk.free"), 2)
            .unwrap();
        let dispatch = broker.client_claim(&friend, 3).unwrap();
        let next = Request {
            id: 2,
            deadline: 23,
            ..req(2, "os.version")
        };
        broker.operator_request(&operator, next, 11).unwrap();
        assert!(dispatch.is_cancelled());
        assert!(broker
            .audit()
            .iter()
            .any(|event| event.action == "command_expired"));
    }

    #[test]
    fn adapter_exposes_only_catalog_and_records_audit() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        let mut adapter = FixtureOperatorAdapter::new(&mut broker, operator);
        assert!(!adapter.command_catalog().contains(&"screen.capture"));
        adapter
            .request_command(req(10, "hardware.inventory"), 2)
            .unwrap();
        assert_eq!(adapter.session_status().unwrap().pending_request, Some(10));
        assert!(adapter
            .activity_log()
            .iter()
            .any(|event| event.action == "command_requested"));
        adapter.cancel_command(10, 3).unwrap();
        adapter.end_session(4).unwrap();
        assert!(adapter.session_status().unwrap().disconnected);
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn toolkit_requests_refuse_unknown_tools_flags_ranges_and_characters() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        assert_eq!(
            broker.operator_request_with_args(&operator, req(1, "toolkit.shell"), vec![], 2),
            Err(Refusal::WrongScope)
        );
        let refused = [
            ("toolkit.crashes", strings(&["--bogus"])),
            ("toolkit.crashes", strings(&["--days", "366"])),
            ("toolkit.crashes", strings(&["--days", "30;calc"])),
            ("toolkit.events", strings(&["--log", "System Application"])),
            ("toolkit.events", strings(&["--log", "C:/Windows"])),
            ("toolkit.crashes", strings(&["--json"])),
            ("os.version", strings(&["--days", "3"])),
        ];
        for (command_id, args) in refused {
            assert_eq!(
                broker.operator_request_with_args(&operator, req(1, command_id), args.clone(), 2),
                Err(Refusal::InvalidArguments),
                "{command_id} {args:?}"
            );
        }
        // A refused request neither consumes its id nor leaves anything pending.
        assert_eq!(broker.status(&operator).unwrap().pending_request, None);
        broker
            .operator_request_with_args(&operator, req(1, "toolkit.battery"), vec![], 2)
            .unwrap();
    }

    #[test]
    fn typed_toolkit_request_reaches_client_as_its_argument_list() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        let args = strings(&["--log", "System", "--id", "41", "--days", "3", "--noise"]);
        let mut adapter = FixtureOperatorAdapter::new(&mut broker, operator.clone());
        adapter
            .request_tool(req(5, "toolkit.events"), args.clone(), 2)
            .unwrap();
        let dispatch = broker.client_claim(&friend, 3).unwrap();
        assert_eq!(dispatch.request.command_id, "toolkit.events");
        assert_eq!(dispatch.args, args);
        assert_eq!(
            broker.client_result(&friend, 5, "bad\u{1b}[2J", 4),
            Err(Refusal::InvalidOutput)
        );
        broker
            .client_result(&friend, 5, "Kinds: 2\n  Kernel-Power 41", 4)
            .unwrap();
        assert_eq!(
            broker.operator_result(&operator, 5, 5).unwrap(),
            Some("Kinds: 2\n  Kernel-Power 41")
        );
    }

    #[test]
    fn every_toolkit_tool_has_a_deadline_from_its_own_bound() {
        for tool in tools::TOOLS {
            assert!(
                bound(tool.name).is_some(),
                "{} has no row in TOOLKIT_BOUNDS",
                tool.name
            );
            assert!(toolkit_deadline_text(tool.name).is_some());
        }
        let secs = |id: &str, args: &[&str]| toolkit_seconds(id, &strings(args));
        assert_eq!(secs("hardware.inventory", &[]), Some(35));
        assert_eq!(secs("os.version", &[]), None);
        assert_eq!(secs("toolkit.perf", &[]), Some(35));
        assert_eq!(secs("toolkit.perf", &["--seconds", "120"]), Some(125));
        assert_eq!(secs("toolkit.space", &[]), Some(65));
        assert_eq!(secs("toolkit.network", &["--quick"]), Some(15));
        assert_eq!(secs("toolkit.network", &[]), Some(35));
        assert_eq!(secs("toolkit.events", &["--days", "3"]), Some(65));
        assert_eq!(secs("os.version", &[]), None);

        // The fixture broker accepts a toolkit deadline up to that bound, not past it.
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        let long = |id, deadline| Request {
            deadline,
            ..req(id, "toolkit.perf")
        };
        let args = strings(&["--seconds", "60"]);
        assert_eq!(
            broker.operator_request_with_args(&operator, long(1, 68), args.clone(), 2),
            Err(Refusal::Expired)
        );
        broker
            .operator_request_with_args(&operator, long(1, 67), args, 2)
            .unwrap();
        assert_eq!(
            broker.operator_request(
                &operator,
                Request {
                    deadline: 30,
                    ..req(2, "os.version")
                },
                3
            ),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn catalog_lists_every_toolkit_tool() {
        let (mut broker, operator, _, _) = fixture(0, "code");
        let adapter = FixtureOperatorAdapter::new(&mut broker, operator);
        let catalog = adapter.command_catalog();
        for tool in tools::TOOLS {
            let id = format!("toolkit.{}", tool.name);
            assert!(catalog.contains(&id.as_str()), "{id}");
            assert_eq!(toolkit_tool(&id).map(|t| t.name), Some(tool.name));
        }
        assert!(catalog.contains(&"os.version"));
        assert_eq!(toolkit_commands().len(), tools::TOOLS.len());
    }

    #[test]
    fn local_runner_result_reaches_only_bound_operator() {
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        broker
            .operator_request(&operator, req(1, "os.version"), 2)
            .unwrap();
        let dispatch = broker.client_claim(&friend, 3).unwrap();
        let output = crate::run_catalog(dispatch.request.command_id, dispatch.cancel).unwrap();
        broker.client_result(&friend, 1, &output, 4).unwrap();
        assert_eq!(
            broker.operator_result(&friend, 1, 5).err(),
            Some(Refusal::WrongIdentity)
        );
        assert_eq!(
            broker.operator_result(&operator, 1, 5).unwrap(),
            Some(output.as_str())
        );
        broker.disconnect(&friend, 6).unwrap();
        assert_eq!(
            broker.operator_result(&operator, 1, 7).err(),
            Some(Refusal::Disconnected)
        );
    }

    #[test]
    fn disconnect_cancels_bounded_process_fixture() {
        use std::thread;
        use std::time::{Duration, Instant};
        let (mut broker, operator, friend, _) = fixture(0, "code");
        broker.pair(&friend, "code", 1).unwrap();
        broker
            .operator_request(&operator, req(2, "os.version"), 2)
            .unwrap();
        let dispatch = broker.client_claim(&friend, 3).unwrap();
        let worker = thread::spawn(move || {
            crate::runner::run_process(
                "Start-Sleep -Seconds 10; '1'",
                Instant::now() + Duration::from_secs(12),
                dispatch.cancel,
            )
        });
        thread::sleep(Duration::from_millis(250));
        broker.disconnect(&friend, 4).unwrap();
        assert_eq!(
            worker.join().unwrap(),
            Err(crate::runner::RunError::Cancelled)
        );
    }
}
