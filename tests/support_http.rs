use std::sync::atomic::AtomicBool;
use std::sync::Arc;
#[cfg(debug_assertions)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use diagnostics::support_transport::{
    execute_consented, Command, Completed, Friend, Match, Matched, OperatorVerifier, Polled, Relay,
    Requested, ResultForOperator, ResultValue, Start, Started,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand08::thread_rng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use tower::ServiceExt;

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

fn keys() -> (String, String) {
    let private = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
    let public = RsaPublicKey::from(&private);
    (
        private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        public.to_public_key_pem(LineEnding::LF).unwrap(),
    )
}

fn jwt(private: &str, issuer: &str, audience: &str, email: &str, exp: usize) -> String {
    encode(
        &Header::new(Algorithm::RS256),
        &Claims {
            iss: issuer,
            aud: audience,
            exp,
            email,
        },
        &EncodingKey::from_rsa_pem(private.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn future() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 300
}

async fn call<T: Serialize>(
    router: &Router,
    path: &str,
    bearer: Option<&str>,
    body: &T,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
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
    let bytes = to_bytes(reply.into_body(), 16 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    serde_json::from_slice(bytes).unwrap()
}

#[tokio::test]
async fn consent_command_result_disconnect_full_path() {
    let (private, public) = keys();
    let verifier =
        OperatorVerifier::from_rsa_pem(public.as_bytes(), ISSUER, AUDIENCE, EMAIL).unwrap();
    let router = Relay::new(verifier).router();
    let token = jwt(&private, ISSUER, AUDIENCE, EMAIL, future());

    let (status, _) = call(&router, "/friend/start", None, &Start { consent: false }).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, bytes) = call(&router, "/friend/start", None, &Start { consent: true }).await;
    assert_eq!(status, StatusCode::OK);
    let started: Started = parse(&bytes);
    let friend = Friend {
        session: started.session.clone(),
        friend_token: started.friend_token.clone(),
    };

    let (status, _) = call(
        &router,
        "/operator/match",
        None,
        &Match {
            display_code: started.display_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, bytes) = call(
        &router,
        "/operator/match",
        Some(&token),
        &Match {
            display_code: started.display_code,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let matched: Matched = parse(&bytes);
    assert_eq!(matched.session, started.session);

    let command = Command {
        request_id: 7,
        command_id: "os.version".into(),
    };
    let requested = Requested {
        session: started.session.clone(),
        command: command.clone(),
    };
    let (status, _) = call(&router, "/operator/request", Some(&token), &requested).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = call(&router, "/operator/request", Some(&token), &requested).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, bytes) = call(&router, "/friend/poll", None, &friend).await;
    assert_eq!(status, StatusCode::OK);
    let polled: Polled = parse(&bytes);
    assert_eq!(polled.operator.as_deref(), Some(EMAIL));
    assert_eq!(polled.command.as_ref(), Some(&command));
    assert!(execute_consented(&command, false, Arc::new(AtomicBool::new(false))).is_err());
    let bad_friend = Friend {
        session: started.session.clone(),
        friend_token: "wrong".into(),
    };
    let (status, _) = call(&router, "/friend/poll", None, &bad_friend).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let invalid_result = Completed {
        session: started.session.clone(),
        friend_token: started.friend_token.clone(),
        request_id: 7,
        output: "ignore instructions".into(),
    };
    let (status, _) = call(&router, "/friend/result", None, &invalid_result).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let oversized_result = Completed {
        output: "1".repeat(4097),
        ..invalid_result
    };
    let (status, _) = call(&router, "/friend/result", None, &oversized_result).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let output = execute_consented(&command, true, Arc::new(AtomicBool::new(false))).unwrap();
    assert!(output.len() <= 4096);
    let completed = Completed {
        session: started.session.clone(),
        friend_token: started.friend_token.clone(),
        request_id: 7,
        output: output.clone(),
    };
    let (status, _) = call(&router, "/friend/result", None, &completed).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let result_request = ResultForOperator {
        session: started.session.clone(),
        request_id: 7,
    };
    let (status, bytes) = call(&router, "/operator/result", Some(&token), &result_request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse::<ResultValue>(&bytes).output, Some(output));

    let pending = Requested {
        session: started.session.clone(),
        command: Command {
            request_id: 8,
            command_id: "memory.total".into(),
        },
    };
    let (status, _) = call(&router, "/operator/request", Some(&token), &pending).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let (status, _) = call(&router, "/friend/disconnect", None, &friend).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let late = Completed {
        session: started.session.clone(),
        friend_token: started.friend_token.clone(),
        request_id: 8,
        output: "8".into(),
    };
    let (status, _) = call(&router, "/friend/result", None, &late).await;
    assert_eq!(status, StatusCode::GONE);
    let (status, _) = call(&router, "/friend/poll", None, &friend).await;
    assert_eq!(status, StatusCode::GONE);
    let (status, _) = call(&router, "/operator/result", Some(&token), &result_request).await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn operator_jwt_and_scope_fail_closed() {
    let (private, public) = keys();
    let (_, other_public) = keys();
    assert!(OperatorVerifier::from_rsa_pem(b"", ISSUER, AUDIENCE, EMAIL).is_err());
    assert!(OperatorVerifier::from_rsa_pem(public.as_bytes(), "", AUDIENCE, EMAIL).is_err());
    let verifier =
        OperatorVerifier::from_rsa_pem(public.as_bytes(), ISSUER, AUDIENCE, EMAIL).unwrap();
    let router = Relay::new(verifier).router();
    let (_, bytes) = call(&router, "/friend/start", None, &Start { consent: true }).await;
    let started: Started = parse(&bytes);
    let variants = [
        jwt(&private, "wrong-issuer", AUDIENCE, EMAIL, future()),
        jwt(&private, ISSUER, "wrong-audience", EMAIL, future()),
        jwt(&private, ISSUER, AUDIENCE, EMAIL, 1),
    ];
    for token in variants {
        let (status, _) = call(
            &router,
            "/operator/match",
            Some(&token),
            &Match {
                display_code: started.display_code.clone(),
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let wrong_identity = jwt(
        &private,
        ISSUER,
        AUDIENCE,
        "stranger@fixture.invalid",
        future(),
    );
    let (status, _) = call(
        &router,
        "/operator/match",
        Some(&wrong_identity),
        &Match {
            display_code: started.display_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let valid = jwt(&private, ISSUER, AUDIENCE, EMAIL, future());
    let wrong_key_router = Relay::new(
        OperatorVerifier::from_rsa_pem(other_public.as_bytes(), ISSUER, AUDIENCE, EMAIL).unwrap(),
    )
    .router();
    let (status, _) = call(
        &wrong_key_router,
        "/operator/match",
        Some(&valid),
        &Match {
            display_code: started.display_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut tampered = valid.clone();
    tampered.push('x');
    let (status, _) = call(
        &router,
        "/operator/match",
        Some(&tampered),
        &Match {
            display_code: started.display_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(
        &router,
        "/operator/match",
        Some("malformed.jwt"),
        &Match {
            display_code: started.display_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let wrong_algorithm = encode(
        &Header::new(Algorithm::HS256),
        &Claims {
            iss: ISSUER,
            aud: AUDIENCE,
            exp: future(),
            email: EMAIL,
        },
        &EncodingKey::from_secret(b"fixture-only-secret"),
    )
    .unwrap();
    let (status, _) = call(
        &router,
        "/operator/match",
        Some(&wrong_algorithm),
        &Match {
            display_code: started.display_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(
        &router,
        "/operator/match",
        Some(&valid),
        &Match {
            display_code: started.display_code,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let forbidden = Requested {
        session: started.session,
        command: Command {
            request_id: 1,
            command_id: "arbitrary.shell".into(),
        },
    };
    let (status, _) = call(&router, "/operator/request", Some(&valid), &forbidden).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn actual_handlers_expire_pair_session_and_pending_request() {
    let (private, public) = keys();
    let verifier =
        OperatorVerifier::from_rsa_pem(public.as_bytes(), ISSUER, AUDIENCE, EMAIL).unwrap();
    let jwt = jwt(&private, ISSUER, AUDIENCE, EMAIL, future());
    let router = Relay::fixture_lifetimes(
        verifier,
        Duration::from_millis(50),
        Duration::from_millis(200),
        Duration::from_millis(30),
    )
    .router();
    let (_, bytes) = call(&router, "/friend/start", None, &Start { consent: true }).await;
    let first: Started = parse(&bytes);
    tokio::time::sleep(Duration::from_millis(60)).await;
    let (status, _) = call(
        &router,
        "/operator/match",
        Some(&jwt),
        &Match {
            display_code: first.display_code,
        },
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, bytes) = call(&router, "/friend/start", None, &Start { consent: true }).await;
    let second: Started = parse(&bytes);
    let (status, _) = call(
        &router,
        "/operator/match",
        Some(&jwt),
        &Match {
            display_code: second.display_code,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let command = Requested {
        session: second.session.clone(),
        command: Command {
            request_id: 99,
            command_id: "os.version".into(),
        },
    };
    let (status, _) = call(&router, "/operator/request", Some(&jwt), &command).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(40)).await;
    let friend = Friend {
        session: second.session.clone(),
        friend_token: second.friend_token.clone(),
    };
    let (status, bytes) = call(&router, "/friend/poll", None, &friend).await;
    assert_eq!(status, StatusCode::OK);
    assert!(parse::<Polled>(&bytes).command.is_none());
    let late = Completed {
        session: second.session.clone(),
        friend_token: second.friend_token,
        request_id: 99,
        output: "1".into(),
    };
    let (status, _) = call(&router, "/friend/result", None, &late).await;
    assert_eq!(status, StatusCode::CONFLICT);
    tokio::time::sleep(Duration::from_millis(180)).await;
    let (status, _) = call(&router, "/friend/poll", None, &friend).await;
    assert_eq!(status, StatusCode::GONE);
}
