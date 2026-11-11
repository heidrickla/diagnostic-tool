//! A disabled HTTP relay. Constructing this router opens no socket. It accepts
//! only a configured RS256 operator trust anchor, fixed diagnostic IDs and the
//! catalogued read-only toolkit tools with typed arguments checked against their usage.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};

const OUTPUT_LIMIT: usize = 4096;
const PAIR_LIFETIME: Duration = Duration::from_secs(120);
const SESSION_LIFETIME: Duration = Duration::from_secs(300);
/// How long a requested fixed command stays pending; toolkit commands take their tool's
/// bound (`protocol::toolkit_seconds`). The client's wait never exceeds either.
pub const COMMAND_LIFETIME: Duration = Duration::from_secs(15);

/// The longest a command may run on the client: its toolkit bound, else 15 seconds.
pub fn command_lifetime(command_id: &str, args: &[String]) -> Duration {
    crate::protocol::toolkit_seconds(command_id, args).map_or(COMMAND_LIFETIME, Duration::from_secs)
}
/// Escaped JSON size a toolkit result may take, so the upload fits the 8 KiB body limit.
const UPLOAD_ESCAPED_LIMIT: usize = 7680;

#[derive(Clone)]
pub struct OperatorVerifier {
    key: Arc<DecodingKey>,
    validation: Validation,
    email: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: usize,
    email: String,
}

impl OperatorVerifier {
    pub fn from_rsa_pem(
        pem: &[u8],
        issuer: &str,
        audience: &str,
        email: &str,
    ) -> Result<Self, String> {
        if issuer.is_empty() || audience.is_empty() || email.is_empty() {
            return Err("operator trust configuration missing".into());
        }
        let key = DecodingKey::from_rsa_pem(pem).map_err(|_| "invalid operator key")?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.required_spec_claims = ["iss", "aud", "exp"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        Ok(Self {
            key: Arc::new(key),
            validation,
            email: email.to_owned(),
        })
    }

    fn check(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let claims = decode::<Claims>(token, &self.key, &self.validation)
            .map_err(|_| StatusCode::UNAUTHORIZED)?
            .claims;
        if claims.email != self.email {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Relay {
    verifier: OperatorVerifier,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    bad_matches: Arc<Mutex<u8>>,
    pair_lifetime: Duration,
    session_lifetime: Duration,
    command_lifetime: Duration,
}

struct Session {
    token: String,
    code: String,
    pair_until: Instant,
    until: Instant,
    paired: bool,
    ended: bool,
    pending: Option<Pending>,
    pending_until: Option<Instant>,
    seen: HashSet<u64>,
    results: HashMap<u64, String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Command {
    pub request_id: u64,
    pub command_id: String,
}
#[derive(Clone)]
struct Pending {
    command: Command,
    args: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Start {
    pub consent: bool,
}
#[derive(Serialize, Deserialize)]
pub struct Started {
    pub session: String,
    pub friend_token: String,
    pub display_code: String,
}
#[derive(Serialize, Deserialize)]
pub struct Match {
    pub display_code: String,
}
#[derive(Serialize, Deserialize)]
pub struct Matched {
    pub session: String,
}
#[derive(Serialize, Deserialize)]
pub struct Friend {
    pub session: String,
    pub friend_token: String,
}
#[derive(Serialize, Deserialize)]
pub struct Polled {
    pub operator: Option<String>,
    pub command: Option<Command>,
    /// The pending command's typed arguments, checked by the relay when it was requested.
    #[serde(default)]
    pub args: Vec<String>,
    /// Milliseconds left before the pending command's deadline.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}
#[derive(Serialize, Deserialize)]
pub struct Requested {
    pub session: String,
    pub command: Command,
}
/// A request with typed arguments; `/operator/request` also accepts `Requested`.
#[derive(Serialize, Deserialize)]
pub struct RequestedTool {
    pub session: String,
    pub command: Command,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Completed {
    pub session: String,
    pub friend_token: String,
    pub request_id: u64,
    pub output: String,
}
#[derive(Serialize, Deserialize)]
pub struct ResultForOperator {
    pub session: String,
    pub request_id: u64,
}
#[derive(Serialize, Deserialize)]
pub struct ResultValue {
    pub output: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub struct OperatorSession {
    pub session: String,
}

fn ticket() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn allowed(id: &str) -> bool {
    matches!(id, "os.version" | "memory.total" | "disk.free")
        || crate::protocol::toolkit_tool(id).is_some()
}

impl Relay {
    pub fn new(verifier: OperatorVerifier) -> Self {
        Self {
            verifier,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            bad_matches: Arc::new(Mutex::new(0)),
            pair_lifetime: PAIR_LIFETIME,
            session_lifetime: SESSION_LIFETIME,
            command_lifetime: COMMAND_LIFETIME,
        }
    }
    #[cfg(debug_assertions)]
    pub fn fixture_lifetimes(
        verifier: OperatorVerifier,
        pair_lifetime: Duration,
        session_lifetime: Duration,
        command_lifetime: Duration,
    ) -> Self {
        Self {
            pair_lifetime,
            session_lifetime,
            command_lifetime,
            ..Self::new(verifier)
        }
    }
    pub fn router(self) -> Router {
        Router::new()
            .route("/friend/start", post(start))
            .route("/friend/poll", post(poll))
            .route("/friend/result", post(complete))
            .route("/friend/disconnect", post(disconnect))
            .route("/operator/match", post(pair))
            .route("/operator/request", post(request))
            .route("/operator/result", post(result))
            .route("/operator/end", post(operator_end))
            .layer(DefaultBodyLimit::max(8192))
            .with_state(self)
    }
}

fn friend<'a>(
    all: &'a mut HashMap<String, Session>,
    session: &str,
    token: &str,
) -> Result<&'a mut Session, StatusCode> {
    let item = all.get_mut(session).ok_or(StatusCode::NOT_FOUND)?;
    if item.token != token {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if item.ended || Instant::now() >= item.until {
        item.ended = true;
        item.pending = None;
        item.pending_until = None;
        item.results.clear();
        return Err(StatusCode::GONE);
    }
    Ok(item)
}

async fn start(
    State(relay): State<Relay>,
    Json(body): Json<Start>,
) -> Result<Json<Started>, StatusCode> {
    if !body.consent {
        return Err(StatusCode::FORBIDDEN);
    }
    let session = ticket();
    let friend_token = ticket();
    let now = Instant::now();
    let mut all = relay.sessions.lock().unwrap();
    all.retain(|_, item| !item.ended && now < item.until);
    if all.len() >= 8 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let display_code = (0..16)
        .map(|_| format!("{:08}", rand::rng().random_range(0..100_000_000u32)))
        .find(|candidate| !all.values().any(|item| item.code == *candidate))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    all.insert(
        session.clone(),
        Session {
            token: friend_token.clone(),
            code: display_code.clone(),
            pair_until: now + relay.pair_lifetime,
            until: now + relay.session_lifetime,
            paired: false,
            ended: false,
            pending: None,
            pending_until: None,
            seen: HashSet::new(),
            results: HashMap::new(),
        },
    );
    Ok(Json(Started {
        session,
        friend_token,
        display_code,
    }))
}

async fn pair(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Json(body): Json<Match>,
) -> Result<Json<Matched>, StatusCode> {
    relay.verifier.check(&headers)?;
    let mut bad = relay.bad_matches.lock().unwrap();
    if *bad >= 5 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let mut all = relay.sessions.lock().unwrap();
    if let Some((id, item)) = all.iter_mut().find(|(_, s)| {
        !s.paired
            && !s.ended
            && Instant::now() < s.pair_until
            && Instant::now() < s.until
            && s.code == body.display_code
    }) {
        item.paired = true;
        item.code.clear();
        Ok(Json(Matched {
            session: id.clone(),
        }))
    } else {
        *bad += 1;
        Err(StatusCode::NOT_FOUND)
    }
}

async fn poll(
    State(relay): State<Relay>,
    Json(body): Json<Friend>,
) -> Result<Json<Polled>, StatusCode> {
    let mut all = relay.sessions.lock().unwrap();
    let item = friend(&mut all, &body.session, &body.friend_token)?;
    if item
        .pending_until
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        item.pending = None;
        item.pending_until = None;
    }
    let pending = item.pending.clone();
    Ok(Json(Polled {
        operator: item.paired.then(|| relay.verifier.email.clone()),
        command: pending.as_ref().map(|pending| pending.command.clone()),
        args: pending.map(|pending| pending.args).unwrap_or_default(),
        deadline_ms: item.pending_until.map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64
        }),
    }))
}

async fn request(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Json(body): Json<RequestedTool>,
) -> Result<StatusCode, StatusCode> {
    relay.verifier.check(&headers)?;
    if !allowed(&body.command.command_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    if crate::protocol::check_arguments(&body.command.command_id, &body.args).is_err() {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let mut all = relay.sessions.lock().unwrap();
    let item = all.get_mut(&body.session).ok_or(StatusCode::NOT_FOUND)?;
    if item.ended || Instant::now() >= item.until {
        return Err(StatusCode::GONE);
    }
    if !item.paired {
        return Err(StatusCode::FORBIDDEN);
    }
    if item.pending.is_some() || !item.seen.insert(body.command.request_id) {
        return Err(StatusCode::CONFLICT);
    }
    let lifetime = crate::protocol::toolkit_seconds(&body.command.command_id, &body.args)
        .map_or(relay.command_lifetime, Duration::from_secs);
    item.pending = Some(Pending {
        command: body.command,
        args: body.args,
    });
    item.pending_until = Some((Instant::now() + lifetime).min(item.until));
    Ok(StatusCode::ACCEPTED)
}

async fn complete(
    State(relay): State<Relay>,
    Json(body): Json<Completed>,
) -> Result<StatusCode, StatusCode> {
    if body.output.len() > OUTPUT_LIMIT {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let single_value = !body.output.is_empty()
        && body.output.len() <= 80
        && body.output.chars().all(|c| c.is_ascii_digit() || c == '.');
    if !single_value && !crate::protocol::toolkit_output_valid(&body.output) {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let mut all = relay.sessions.lock().unwrap();
    let item = friend(&mut all, &body.session, &body.friend_token)?;
    if !item.paired
        || item.pending.as_ref().map(|p| p.command.request_id) != Some(body.request_id)
        || item
            .pending_until
            .is_none_or(|deadline| Instant::now() >= deadline)
    {
        return Err(StatusCode::CONFLICT);
    }
    let toolkit = item
        .pending
        .as_ref()
        .is_some_and(|p| crate::protocol::toolkit_tool(&p.command.command_id).is_some());
    // Only a toolkit command may answer with text; the fixed ones keep their single value.
    if !single_value && !toolkit {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    item.pending = None;
    item.pending_until = None;
    item.results.insert(body.request_id, body.output);
    Ok(StatusCode::ACCEPTED)
}

async fn result(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Json(body): Json<ResultForOperator>,
) -> Result<Json<ResultValue>, StatusCode> {
    relay.verifier.check(&headers)?;
    let mut all = relay.sessions.lock().unwrap();
    let item = all.get_mut(&body.session).ok_or(StatusCode::NOT_FOUND)?;
    if item.ended || Instant::now() >= item.until || !item.paired {
        return Err(StatusCode::GONE);
    }
    Ok(Json(ResultValue {
        output: item.results.remove(&body.request_id),
    }))
}

async fn disconnect(
    State(relay): State<Relay>,
    Json(body): Json<Friend>,
) -> Result<StatusCode, StatusCode> {
    let mut all = relay.sessions.lock().unwrap();
    let item = friend(&mut all, &body.session, &body.friend_token)?;
    item.ended = true;
    item.pending = None;
    item.pending_until = None;
    item.results.clear();
    Ok(StatusCode::NO_CONTENT)
}

async fn operator_end(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Json(body): Json<OperatorSession>,
) -> Result<StatusCode, StatusCode> {
    relay.verifier.check(&headers)?;
    let mut all = relay.sessions.lock().unwrap();
    let item = all.get_mut(&body.session).ok_or(StatusCode::NOT_FOUND)?;
    item.ended = true;
    item.pending = None;
    item.pending_until = None;
    item.results.clear();
    Ok(StatusCode::NO_CONTENT)
}

/// Friend-side execution hook. The GUI must supply live local consent and its
/// cancellation flag; a remote request cannot create either of those.
pub fn execute_consented(
    command: &Command,
    consent: bool,
    cancelled: Arc<AtomicBool>,
) -> Result<String, String> {
    let deadline = Instant::now() + command_lifetime(&command.command_id, &[]);
    match execute_typed(command, &[], consent, cancelled, deadline)? {
        Ran::Output(text) => Ok(text),
        other => Err(other.outcome()),
    }
}

/// The friend-side hook for a command with typed arguments. A toolkit tool's arguments
/// are checked again here before it runs.
pub fn execute_typed(
    command: &Command,
    args: &[String],
    consent: bool,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Ran, String> {
    if !consent || cancelled.load(Ordering::SeqCst) || !allowed(&command.command_id) {
        return Err("command not consented".into());
    }
    crate::protocol::check_arguments(&command.command_id, args)?;
    match crate::protocol::toolkit_tool(&command.command_id) {
        Some(tool) => Ok(run_toolkit(tool, args, cancelled, deadline)),
        None => crate::run_catalog(&command.command_id, cancelled).map(Ran::Output),
    }
}

/// What became of a command the client ran.
#[derive(Debug, PartialEq, Eq)]
pub enum Ran {
    /// The redacted, capped result to upload.
    Output(String),
    /// The tool reported an error; its redacted message is uploaded instead.
    Failed(String),
    /// A tool abandoned by an earlier Stop or deadline has not finished yet.
    Busy,
    Cancelled,
    DeadlinePassed,
}

impl Ran {
    /// The text the client uploads, if any: nothing once stopped or past the deadline.
    pub fn upload(&self) -> Option<String> {
        match self {
            Ran::Output(text) => Some(text.clone()),
            Ran::Failed(message) => Some(cap_output(&format!("Unavailable: {message}"))),
            Ran::Busy => Some(
                "Unavailable: the previous toolkit tool is still finishing; ask again shortly."
                    .into(),
            ),
            Ran::Cancelled | Ran::DeadlinePassed => None,
        }
    }

    /// One phrase for the activity record.
    pub fn outcome(&self) -> String {
        match self {
            Ran::Output(text) => format!("finished, {} bytes", text.len()),
            Ran::Failed(message) => format!("failed: {message}"),
            Ran::Busy => "refused: the previous tool is still finishing".into(),
            Ran::Cancelled => "stopped before it finished".into(),
            Ran::DeadlinePassed => "deadline passed before it finished".into(),
        }
    }
}

/// One toolkit tool at a time, including one abandoned by Stop or a deadline.
static TOOL_GATE: Mutex<()> = Mutex::new(());

/// Runs a toolkit tool in-process and waits until it finishes, the deadline passes or
/// `cancelled` is set. Tools take no cancellation flag, so Stop, Disconnect and the
/// deadline end the wait, not the tool: it runs on to its own time limit and its result
/// is dropped, and the gate refuses another tool until then.
pub fn run_toolkit(
    tool: &'static crate::tools::Tool,
    args: &[String],
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) -> Ran {
    if cancelled.load(Ordering::SeqCst) {
        return Ran::Cancelled;
    }
    let parsed = match crate::tools::Args::parse(args, tool.usage) {
        Ok(parsed) => parsed,
        Err(error) => return Ran::Failed(redact_text(error.lines().next().unwrap_or_default())),
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _held = match TOOL_GATE.try_lock() {
            Ok(held) => held,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                let _ = sender.send(None);
                return;
            }
        };
        let _ = sender.send(Some((tool.run)(&parsed)));
    });
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Ran::Cancelled;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ran::DeadlinePassed;
        }
        match receiver.recv_timeout(left.min(Duration::from_millis(100))) {
            Ok(None) => return Ran::Busy,
            Ok(Some(Ok(output))) => return Ran::Output(render(&output)),
            Ok(Some(Err(message))) => return Ran::Failed(redact_text(&message)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ran::Failed("the tool stopped unexpectedly".into())
            }
        }
    }
}

/// The JSON readings when the tool has them, else its text; redacted and capped.
fn render(output: &crate::tools::Output) -> String {
    if output.data.is_null() && output.text.trim().is_empty() {
        return "The tool returned no output.".into();
    }
    if output.data.is_null() {
        return cap_output(&redact_text(&output.text));
    }
    let mut data = output.data.clone();
    redact_value(&mut data, &crate::events::local_names());
    cap_output(&serde_json::to_string(&data).unwrap_or_default())
}

/// `events::redact` line by line, keeping each line's indent.
fn redact_text(text: &str) -> String {
    let names = crate::events::local_names();
    text.lines()
        .map(|line| {
            let body = line.trim_start();
            let indent = &line[..line.len() - body.len()];
            if body.is_empty() {
                String::new()
            } else {
                format!("{indent}{}", crate::events::redact(body, &names))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_value(value: &mut serde_json::Value, names: &[String]) {
    match value {
        serde_json::Value::String(text) => *text = crate::events::redact(text, names),
        serde_json::Value::Array(items) => items.iter_mut().for_each(|v| redact_value(v, names)),
        serde_json::Value::Object(map) => map.values_mut().for_each(|v| redact_value(v, names)),
        _ => {}
    }
}

/// Caps a result to the output limit, and to what fits the upload once JSON-escaped,
/// dropping control characters other than newline and tab; says when it cut.
pub fn cap_output(text: &str) -> String {
    const NOTE: &str = "\n[Cut short at the output limit.]";
    let escaped = |c: char| match c {
        '"' | '\\' | '\n' | '\t' => 2,
        c => c.len_utf8(),
    };
    let kept: String = text
        .chars()
        .filter(|&c| !c.is_control() || c == '\n' || c == '\t')
        .collect();
    let fits = |text: &str| {
        text.len() <= OUTPUT_LIMIT
            && text.chars().map(escaped).sum::<usize>() <= UPLOAD_ESCAPED_LIMIT
    };
    if fits(&kept) {
        return kept;
    }
    let (mut raw, mut wide) = (NOTE.len(), NOTE.chars().map(escaped).sum::<usize>());
    let mut cut = String::new();
    for c in kept.chars() {
        raw += c.len_utf8();
        wide += escaped(c);
        if raw > OUTPUT_LIMIT || wide > UPLOAD_ESCAPED_LIMIT {
            break;
        }
        cut.push(c);
    }
    cut + NOTE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{Args, Output, Tool};
    use axum::body::{to_bytes, Body};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use tower::ServiceExt;

    const ISSUER: &str = "https://access.fixture.invalid";
    const AUDIENCE: &str = "friend-support-fixture";
    const EMAIL: &str = "operator@fixture.invalid";

    /// Tests that run a toolkit tool share the one-tool gate, so they take turns.
    static SERIAL: Mutex<()> = Mutex::new(());
    /// Held by a test to keep the fixture tool running.
    static HOLD: Mutex<()> = Mutex::new(());

    fn held() -> Result<Output, String> {
        drop(HOLD.lock().unwrap_or_else(|p| p.into_inner()));
        Ok(Output::text("released".into()))
    }
    static SLOW: Tool = Tool {
        name: "slow",
        summary: "fixture",
        usage: "Usage: toolkit slow",
        run: |_: &Args| held(),
    };

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    async fn call<T: Serialize>(
        router: &Router,
        path: &str,
        bearer: Option<&str>,
        body: &T,
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let reply = router.clone().oneshot(request).await.unwrap();
        let status = reply.status();
        let bytes = to_bytes(reply.into_body(), 16 * 1024).await.unwrap();
        (status, bytes.to_vec())
    }

    #[tokio::test]
    async fn relay_checks_typed_arguments_and_carries_them_to_the_client() {
        let private = rsa::RsaPrivateKey::new(&mut rand08::thread_rng(), 2048).unwrap();
        let public = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 300;
        let token = encode(
            &Header::new(Algorithm::RS256),
            &Claims {
                iss: ISSUER.into(),
                aud: AUDIENCE.into(),
                exp,
                email: EMAIL.into(),
            },
            &EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
        let verifier =
            OperatorVerifier::from_rsa_pem(public.as_bytes(), ISSUER, AUDIENCE, EMAIL).unwrap();
        let router = Relay::new(verifier).router();
        let (_, bytes) = call(&router, "/friend/start", None, &Start { consent: true }).await;
        let started: Started = serde_json::from_slice(&bytes).unwrap();
        let matched = Match {
            display_code: started.display_code.clone(),
        };
        let (status, _) = call(&router, "/operator/match", Some(&token), &matched).await;
        assert_eq!(status, StatusCode::OK);
        let ask = |id: u64, command_id: &str, args: &[&str]| RequestedTool {
            session: started.session.clone(),
            command: Command {
                request_id: id,
                command_id: command_id.into(),
            },
            args: strings(args),
        };

        let (status, _) = call(
            &router,
            "/operator/request",
            Some(&token),
            &ask(1, "toolkit.shell", &[]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let refused: [(&str, &[&str]); 5] = [
            ("toolkit.events", &["--bogus"]),
            ("toolkit.crashes", &["--days", "999"]),
            ("toolkit.events", &["--log", "System|calc"]),
            ("toolkit.events", &["--source", "a b"]),
            ("os.version", &["--days", "3"]),
        ];
        for (command_id, args) in refused {
            let (status, _) = call(
                &router,
                "/operator/request",
                Some(&token),
                &ask(1, command_id, args),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{command_id} {args:?}"
            );
        }
        let args = ["--log", "System", "--id", "41", "--days", "3"];
        let (status, _) = call(
            &router,
            "/operator/request",
            Some(&token),
            &ask(1, "toolkit.events", &args),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let friend = Friend {
            session: started.session.clone(),
            friend_token: started.friend_token.clone(),
        };
        let (_, bytes) = call(&router, "/friend/poll", None, &friend).await;
        let polled: Polled = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(polled.command.unwrap().command_id, "toolkit.events");
        assert_eq!(polled.args, strings(&args));
        // events' own bound is 60 s plus the margin, not the fixed commands' 15 s.
        assert!(polled
            .deadline_ms
            .is_some_and(|ms| ms > 15_000 && ms <= 65_000));

        let text = Completed {
            session: started.session.clone(),
            friend_token: started.friend_token.clone(),
            request_id: 1,
            output: "Kinds: 1\n  Kernel-Power 41 \"unclean\"".into(),
        };
        let (status, _) = call(&router, "/friend/result", None, &text).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_, bytes) = call(
            &router,
            "/operator/result",
            Some(&token),
            &ResultForOperator {
                session: started.session.clone(),
                request_id: 1,
            },
        )
        .await;
        let value: ResultValue = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.output.as_deref(), Some(text.output.as_str()));

        // A fixed command still takes only its single value.
        let (status, _) = call(
            &router,
            "/operator/request",
            Some(&token),
            &ask(2, "os.version", &[]),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let words = Completed {
            request_id: 2,
            output: "Kinds: 1".into(),
            ..text
        };
        let (status, _) = call(&router, "/friend/result", None, &words).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn stop_and_deadline_end_the_wait_and_the_gate_holds_until_the_tool_ends() {
        let _serial = serial();
        let cancelled = Arc::new(AtomicBool::new(true));
        let far = Instant::now() + Duration::from_secs(10);
        assert_eq!(run_toolkit(&SLOW, &[], cancelled, far), Ran::Cancelled);

        let hold = HOLD.lock().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopper = cancelled.clone();
        let started = Instant::now();
        let stop = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            stopper.store(true, Ordering::SeqCst);
        });
        assert_eq!(run_toolkit(&SLOW, &[], cancelled, far), Ran::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
        stop.join().unwrap();

        let fresh = Arc::new(AtomicBool::new(false));
        assert_eq!(run_toolkit(&SLOW, &[], fresh.clone(), far), Ran::Busy);
        drop(hold);
        drop(TOOL_GATE.lock().unwrap_or_else(|p| p.into_inner()));

        let hold = HOLD.lock().unwrap();
        let soon = Instant::now() + Duration::from_millis(150);
        assert_eq!(
            run_toolkit(&SLOW, &[], fresh.clone(), soon),
            Ran::DeadlinePassed
        );
        drop(hold);
        drop(TOOL_GATE.lock().unwrap_or_else(|p| p.into_inner()));
        assert_eq!(
            run_toolkit(&SLOW, &[], fresh, far),
            Ran::Output("released".into())
        );
    }

    #[test]
    fn a_live_toolkit_command_runs_in_process_capped_and_uploadable() {
        let _serial = serial();
        let command = Command {
            request_id: 1,
            command_id: "toolkit.battery".into(),
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + command_lifetime("toolkit.battery", &[]);
        assert!(execute_typed(&command, &[], false, cancelled.clone(), deadline).is_err());
        assert!(execute_typed(
            &command,
            &strings(&["--all"]),
            true,
            cancelled.clone(),
            deadline
        )
        .is_err());
        let ran = execute_typed(&command, &[], true, cancelled, deadline).unwrap();
        let upload = ran.upload().expect("battery answers within the deadline");
        assert!(upload.len() <= OUTPUT_LIMIT);
        assert!(crate::protocol::toolkit_output_valid(&upload), "{upload}");
    }

    #[test]
    fn results_are_capped_to_the_limit_and_the_upload_body() {
        let short = "Drive C: 120 GB free\n\tok\u{7}";
        assert_eq!(cap_output(short), "Drive C: 120 GB free\n\tok");
        let long = cap_output(&"x".repeat(10_000));
        assert!(long.len() <= OUTPUT_LIMIT && long.ends_with("[Cut short at the output limit.]"));
        let quotes = cap_output(&"\"".repeat(4_000));
        assert!(serde_json::to_string(&quotes).unwrap().len() <= UPLOAD_ESCAPED_LIMIT + 2);
        assert!(quotes.ends_with("limit.]"));
        let wide = cap_output(&"é".repeat(3_000));
        assert!(wide.len() <= OUTPUT_LIMIT && wide.is_char_boundary(wide.len()));
    }

    #[test]
    fn results_are_redacted_keeping_lines_and_json_shape() {
        let text = redact_text("Owner: someone@example.com\n  Gateway 192.168.1.1\n\nend");
        assert_eq!(text, "Owner: [email]\n  Gateway [address]\n\nend");
        let mut data = serde_json::json!({
            "path": "C:\\Users\\someone\\AppData\\x.exe",
            "items": [{"mac": "00-11-22-33-44-55"}],
            "count": 3
        });
        redact_value(&mut data, &[]);
        assert_eq!(data["path"], "C:\\Users\\[user]\\AppData\\x.exe");
        assert_eq!(data["items"][0]["mac"], "[hardware address]");
        assert_eq!(data["count"], 3);
    }
}
