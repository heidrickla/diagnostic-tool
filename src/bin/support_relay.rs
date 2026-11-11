//! Local-only relay runner for protocol development. No production listener is
//! present in ordinary builds; even feature builds refuse non-loopback binds.
#[cfg(not(feature = "live_support"))]
fn main() {
    eprintln!("Friend support relay is disabled in this build.");
    std::process::exit(2);
}

#[cfg(feature = "live_support")]
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Friend support relay did not start: {error}");
        std::process::exit(2);
    }
}

#[cfg(feature = "live_support")]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    use diagnostics::support_transport::{OperatorVerifier, Relay};
    use std::net::SocketAddr;

    let bind: SocketAddr = std::env::var("FRIEND_SUPPORT_FIXTURE_BIND")?.parse()?;
    if !bind.ip().is_loopback() {
        return Err("fixture relay may bind loopback only".into());
    }
    let pem = std::fs::read(std::env::var("FRIEND_SUPPORT_OPERATOR_PUBLIC_KEY")?)?;
    let issuer = std::env::var("FRIEND_SUPPORT_OPERATOR_ISSUER")?;
    let audience = std::env::var("FRIEND_SUPPORT_OPERATOR_AUDIENCE")?;
    let email = std::env::var("FRIEND_SUPPORT_OPERATOR_EMAIL")?;
    let verifier = OperatorVerifier::from_rsa_pem(&pem, &issuer, &audience, &email)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, Relay::new(verifier).router()).await?;
    Ok(())
}
