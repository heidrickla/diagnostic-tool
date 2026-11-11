//! Outbound HTTPS clients. No default endpoint or embedded credential exists.
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::support_transport::{
    command_lifetime, execute_typed, Completed, Friend, Match, Matched, OperatorSession, Polled,
    Requested, RequestedTool, ResultForOperator, ResultValue, Start, Started,
};

/// Entries the client's activity record keeps, newest last.
const ACTIVITY_ENTRIES: usize = 64;

/// One command the client ran, for the activity record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executed {
    pub command_id: String,
    pub args: Vec<String>,
    pub duration: Duration,
    pub outcome: String,
}

impl Executed {
    pub fn line(&self) -> String {
        let mut command = self.command_id.clone();
        for arg in &self.args {
            command.push(' ');
            command.push_str(arg);
        }
        format!(
            "{command}: {} after {:.1} s",
            self.outcome,
            self.duration.as_secs_f64()
        )
    }
}

fn validate_base(base: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(base).map_err(|_| "invalid endpoint")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("endpoint must be an HTTPS origin".into());
    }
    Ok(base.trim_end_matches('/').to_owned())
}

fn http_client() -> Result<Client, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err("TLS provider unavailable".into());
    }
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "HTTP client unavailable".into())
}

async fn post<T: Serialize, R: DeserializeOwned>(
    client: &Client,
    base: &str,
    path: &str,
    bearer: Option<&str>,
    body: &T,
) -> Result<R, String> {
    let mut request = client.post(format!("{base}{path}")).json(body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .await
        .map_err(|_| "support connection failed")?
        .error_for_status()
        .map_err(|_| "support request refused")?
        .json::<R>()
        .await
        .map_err(|_| "invalid support reply".into())
}

#[derive(Clone)]
pub struct FriendClient {
    http: Client,
    base: String,
    pub session: String,
    token: String,
    expected_operator: String,
    pub local_consent: Arc<AtomicBool>,
    pub disconnected: Arc<AtomicBool>,
    pub cancel_current: Arc<AtomicBool>,
    seen: Arc<Mutex<HashSet<u64>>>,
    activity: Arc<Mutex<VecDeque<Executed>>>,
}

impl FriendClient {
    pub async fn start(
        base: &str,
        expected_operator: &str,
        local_consent: Arc<AtomicBool>,
        cancel_current: Arc<AtomicBool>,
        disconnected: Arc<AtomicBool>,
    ) -> Result<(Self, String), String> {
        Self::start_with_client(
            http_client()?,
            base,
            expected_operator,
            local_consent,
            cancel_current,
            disconnected,
        )
        .await
    }

    async fn start_with_client(
        http: Client,
        base: &str,
        expected_operator: &str,
        local_consent: Arc<AtomicBool>,
        cancel_current: Arc<AtomicBool>,
        disconnected: Arc<AtomicBool>,
    ) -> Result<(Self, String), String> {
        let base = validate_base(base)?;
        if expected_operator.is_empty() || !local_consent.load(Ordering::SeqCst) {
            return Err("local consent or operator identity missing".into());
        }
        let started: Started = post(
            &http,
            &base,
            "/friend/start",
            None,
            &Start { consent: true },
        )
        .await?;
        let client = Self {
            http,
            base,
            session: started.session,
            token: started.friend_token,
            expected_operator: expected_operator.to_owned(),
            local_consent,
            disconnected,
            cancel_current,
            seen: Arc::new(Mutex::new(HashSet::new())),
            activity: Arc::new(Mutex::new(VecDeque::new())),
        };
        Ok((client, started.display_code))
    }

    fn friend(&self) -> Friend {
        Friend {
            session: self.session.clone(),
            friend_token: self.token.clone(),
        }
    }

    pub async fn poll(&self) -> Result<Polled, String> {
        if self.disconnected.load(Ordering::SeqCst) || !self.local_consent.load(Ordering::SeqCst) {
            return Err("session stopped locally".into());
        }
        post(&self.http, &self.base, "/friend/poll", None, &self.friend()).await
    }

    /// The commands this session ran, oldest first, capped at the newest 64.
    pub fn activity(&self) -> Vec<Executed> {
        self.activity.lock().unwrap().iter().cloned().collect()
    }

    fn record(&self, executed: &Executed) {
        let mut activity = self.activity.lock().unwrap();
        if activity.len() == ACTIVITY_ENTRIES {
            activity.pop_front();
        }
        activity.push_back(executed.clone());
    }

    /// Runs the pending command, if any, and uploads its result. Returns what it ran.
    pub async fn execute_one(&self) -> Result<Option<Executed>, String> {
        let poll = self.poll().await?;
        if poll.operator.as_deref() != Some(&self.expected_operator) {
            return Ok(None);
        }
        let Some(command) = poll.command else {
            return Ok(None);
        };
        if !self.seen.lock().unwrap().insert(command.request_id) {
            return Ok(None);
        }
        let request_id = command.request_id;
        let consent = self.local_consent.load(Ordering::SeqCst);
        let cancelled = self.cancel_current.clone();
        let args = poll.args;
        let bound = command_lifetime(&command.command_id, &args);
        let wait = poll
            .deadline_ms
            .map_or(bound, Duration::from_millis)
            .min(bound);
        let deadline = Instant::now() + wait;
        let started = Instant::now();
        let mut executed = Executed {
            command_id: command.command_id.clone(),
            args: args.clone(),
            duration: Duration::ZERO,
            outcome: String::new(),
        };
        let ran = tokio::task::spawn_blocking(move || {
            execute_typed(&command, &args, consent, cancelled, deadline)
        })
        .await
        .map_err(|_| "diagnostic worker failed")?;
        executed.duration = started.elapsed();
        executed.outcome = match &ran {
            Ok(ran) => ran.outcome(),
            Err(error) => format!("failed: {error}"),
        };
        self.record(&executed);
        let ran = ran?;
        if self.disconnected.load(Ordering::SeqCst) || !self.local_consent.load(Ordering::SeqCst) {
            return Err("session stopped locally".into());
        }
        let Some(output) = ran.upload() else {
            return Ok(Some(executed));
        };
        let completed = Completed {
            session: self.session.clone(),
            friend_token: self.token.clone(),
            request_id,
            output,
        };
        let response = self
            .http
            .post(format!("{}/friend/result", self.base))
            .json(&completed)
            .send()
            .await
            .map_err(|_| "support connection failed")?;
        if !response.status().is_success() {
            return Err("support result refused".into());
        }
        Ok(Some(executed))
    }

    pub async fn disconnect(&self) -> Result<(), String> {
        self.disconnected.store(true, Ordering::SeqCst);
        self.cancel_current.store(true, Ordering::SeqCst);
        self.local_consent.store(false, Ordering::SeqCst);
        let response = self
            .http
            .post(format!("{}/friend/disconnect", self.base))
            .json(&self.friend())
            .send()
            .await
            .map_err(|_| "disconnect delivery failed")?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err("disconnect not acknowledged".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct OperatorClient {
    http: Client,
    base: String,
    jwt: String,
}
impl OperatorClient {
    pub fn new(base: &str, jwt: String) -> Result<Self, String> {
        if jwt.is_empty() {
            return Err("operator token missing".into());
        }
        let base = validate_base(base)?;
        Ok(Self {
            http: http_client()?,
            base,
            jwt,
        })
    }
    pub async fn match_code(&self, code: String) -> Result<Matched, String> {
        post(
            &self.http,
            &self.base,
            "/operator/match",
            Some(&self.jwt),
            &Match { display_code: code },
        )
        .await
    }
    pub async fn request(&self, body: Requested) -> Result<(), String> {
        self.request_tool(RequestedTool {
            session: body.session,
            command: body.command,
            args: Vec::new(),
        })
        .await
    }
    /// A request with typed arguments; the relay refuses arguments outside the tool's usage.
    pub async fn request_tool(&self, body: RequestedTool) -> Result<(), String> {
        let response = self
            .http
            .post(format!("{}/operator/request", self.base))
            .bearer_auth(&self.jwt)
            .json(&body)
            .send()
            .await
            .map_err(|_| "support connection failed")?;
        if response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Err("arguments refused".into());
        }
        if response.status() != reqwest::StatusCode::ACCEPTED {
            return Err("command refused".into());
        }
        Ok(())
    }
    pub async fn result(&self, body: ResultForOperator) -> Result<ResultValue, String> {
        post(
            &self.http,
            &self.base,
            "/operator/result",
            Some(&self.jwt),
            &body,
        )
        .await
    }
    pub async fn end(&self, session: String) -> Result<(), String> {
        let response = self
            .http
            .post(format!("{}/operator/end", self.base))
            .bearer_auth(&self.jwt)
            .json(&OperatorSession { session })
            .send()
            .await
            .map_err(|_| "support connection failed")?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err("end session refused".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::OperatorClient;

    #[test]
    fn outbound_client_has_no_insecure_or_default_endpoint() {
        assert!(OperatorClient::new("http://relay.fixture.invalid", "fake".into()).is_err());
        assert!(OperatorClient::new("https://relay.fixture.invalid/path", "fake".into()).is_err());
        assert!(OperatorClient::new("https://relay.fixture.invalid", String::new()).is_err());
    }

    /// Every endpoint the build accepts is one the client accepts, and the examples the
    /// client refuses here are refused by the build rule too.
    #[test]
    fn the_build_rule_and_the_client_agree_on_endpoints() {
        use crate::site_rules::check_support_endpoint;
        for good in [
            "https://support.example.com",
            "https://relay.fixture.invalid",
            "https://a-b.c1.example.org",
            "https://localhost",
        ] {
            assert!(check_support_endpoint(good).is_ok(), "{good}");
            assert!(super::validate_base(good).is_ok(), "{good}");
        }
        for bad in [
            "http://relay.fixture.invalid",
            "https://relay.fixture.invalid/path",
            "https://relay.fixture.invalid/",
            "https://relay.fixture.invalid:8443",
            "https://relay.fixture.invalid?x=1",
            "https:///relay",
        ] {
            assert!(check_support_endpoint(bad).is_err(), "{bad}");
        }
    }
}
