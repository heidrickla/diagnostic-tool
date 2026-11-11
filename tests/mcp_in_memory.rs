//! Full MCP tool calls over an in-memory stdio-equivalent stream. The backend
//! calls actual relay HTTP handlers with a fixture-signed JWT, no listener.
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use diagnostics::operator_tools::{OperatorBackend, SupportTools, ToolFuture};
use diagnostics::support_transport::{
    execute_consented, Command, Completed, Friend, Match, Matched, OperatorSession,
    OperatorVerifier, Polled, Relay, Requested, ResultForOperator, ResultValue, Start, Started,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand08::thread_rng;
use rmcp::{model::CallToolRequestParams, ServiceExt};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::{json, Map};
use tower::ServiceExt as TowerServiceExt;

const ISSUER: &str = "https://access.fixture.invalid";
const AUDIENCE: &str = "friend-support-fixture";
const EMAIL: &str = "operator@fixture.invalid";

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: usize,
    email: &'a str,
}

async fn post<T: Serialize>(
    router: &Router,
    path: &str,
    jwt: Option<&str>,
    body: &T,
) -> Result<(StatusCode, Vec<u8>), String> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(jwt) = jwt {
        builder = builder.header("authorization", format!("Bearer {jwt}"));
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let response = router
        .clone()
        .oneshot(request)
        .await
        .map_err(|_| "handler failed")?;
    let status = response.status();
    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .map_err(|_| "body failed")?
        .to_vec();
    Ok((status, body))
}

struct HandlerBackend {
    router: Router,
    jwt: String,
}
impl OperatorBackend for HandlerBackend {
    fn pair<'a>(&'a self, code: String) -> ToolFuture<'a, String> {
        Box::pin(async move {
            let (status, body) = post(
                &self.router,
                "/operator/match",
                Some(&self.jwt),
                &Match { display_code: code },
            )
            .await?;
            if status != StatusCode::OK {
                return Err(format!("HTTP {status}"));
            }
            Ok(serde_json::from_slice::<Matched>(&body)
                .map_err(|_| "invalid pair reply")?
                .session)
        })
    }
    fn request<'a>(&'a self, session: String, command: Command) -> ToolFuture<'a, ()> {
        Box::pin(async move {
            let (status, _) = post(
                &self.router,
                "/operator/request",
                Some(&self.jwt),
                &Requested { session, command },
            )
            .await?;
            if status == StatusCode::ACCEPTED {
                Ok(())
            } else {
                Err(format!("HTTP {status}"))
            }
        })
    }
    fn result<'a>(&'a self, session: String, request_id: u64) -> ToolFuture<'a, Option<String>> {
        Box::pin(async move {
            let (status, body) = post(
                &self.router,
                "/operator/result",
                Some(&self.jwt),
                &ResultForOperator {
                    session,
                    request_id,
                },
            )
            .await?;
            if status != StatusCode::OK {
                return Err(format!("HTTP {status}"));
            }
            Ok(serde_json::from_slice::<ResultValue>(&body)
                .map_err(|_| "invalid result reply")?
                .output)
        })
    }
    fn end<'a>(&'a self, session: String) -> ToolFuture<'a, ()> {
        Box::pin(async move {
            let (status, _) = post(
                &self.router,
                "/operator/end",
                Some(&self.jwt),
                &OperatorSession { session },
            )
            .await?;
            if status == StatusCode::NO_CONTENT {
                Ok(())
            } else {
                Err(format!("HTTP {status}"))
            }
        })
    }
}

fn args(
    pairs: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> Map<String, serde_json::Value> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

#[tokio::test]
async fn mcp_tools_reach_verified_handler_and_real_executor() {
    let private = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
    let public = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let signing = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &Claims {
            iss: ISSUER,
            aud: AUDIENCE,
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize
                + 300,
            email: EMAIL,
        },
        &EncodingKey::from_rsa_pem(signing.as_bytes()).unwrap(),
    )
    .unwrap();
    let router = Relay::new(
        OperatorVerifier::from_rsa_pem(public.as_bytes(), ISSUER, AUDIENCE, EMAIL).unwrap(),
    )
    .router();
    let (_, body) = post(&router, "/friend/start", None, &Start { consent: true })
        .await
        .unwrap();
    let started: Started = serde_json::from_slice(&body).unwrap();
    let backend = HandlerBackend {
        router: router.clone(),
        jwt,
    };

    let (client_stream, server_stream) = tokio::io::duplex(65536);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_task = tokio::spawn(async move {
        let server = SupportTools::new(Arc::new(backend))
            .serve((server_read, server_write))
            .await
            .unwrap();
        let _ = server.waiting().await;
    });
    let (client_read, client_write) = tokio::io::split(client_stream);
    let client = ().serve((client_read, client_write)).await.unwrap();
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert!(names.contains(&"pair"));
    assert!(!names.contains(&"shell"));

    let pair = client
        .call_tool(
            CallToolRequestParams::new("pair")
                .with_arguments(args([("code", json!(started.display_code))])),
        )
        .await
        .unwrap();
    assert!(format!("{pair:?}").contains(&started.session));
    let denied = client
        .call_tool(
            CallToolRequestParams::new("request_diagnostic").with_arguments(args([
                ("session", json!(started.session)),
                ("command_id", json!("arbitrary.shell")),
                ("request_id", json!(4)),
            ])),
        )
        .await
        .unwrap();
    assert!(format!("{denied:?}").contains("outside the reviewed catalog"));
    let requested = client
        .call_tool(
            CallToolRequestParams::new("request_diagnostic").with_arguments(args([
                ("session", json!(started.session)),
                ("command_id", json!("os.version")),
                ("request_id", json!(5)),
            ])),
        )
        .await
        .unwrap();
    assert!(format!("{requested:?}").contains("Diagnostic requested"));

    let friend = Friend {
        session: started.session.clone(),
        friend_token: started.friend_token.clone(),
    };
    let (_, body) = post(&router, "/friend/poll", None, &friend).await.unwrap();
    let polled: Polled = serde_json::from_slice(&body).unwrap();
    let command = polled.command.unwrap();
    let output = execute_consented(&command, true, Arc::new(AtomicBool::new(false))).unwrap();
    let (status, _) = post(
        &router,
        "/friend/result",
        None,
        &Completed {
            session: started.session.clone(),
            friend_token: started.friend_token,
            request_id: 5,
            output: output.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::ACCEPTED);
    let result = client
        .call_tool(
            CallToolRequestParams::new("read_result").with_arguments(args([
                ("session", json!(started.session)),
                ("request_id", json!(5)),
            ])),
        )
        .await
        .unwrap();
    assert!(format!("{result:?}").contains(&output));
    let ended = client
        .call_tool(
            CallToolRequestParams::new("end_session")
                .with_arguments(args([("session", json!(started.session))])),
        )
        .await
        .unwrap();
    assert!(format!("{ended:?}").contains("Session ended"));
    let (status, _) = post(&router, "/friend/poll", None, &friend).await.unwrap();
    assert_eq!(status, StatusCode::GONE);
    let _ = client.cancel().await;
    server_task.abort();
}
