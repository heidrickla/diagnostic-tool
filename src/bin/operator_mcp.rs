//! Disabled by default; no MCP registration or operator token is installed.
#[cfg(not(feature = "live_support"))]
fn main() {
    eprintln!("Friend support MCP adapter is disabled in this build.");
    std::process::exit(2);
}

#[cfg(feature = "live_support")]
#[tokio::main]
async fn main() {
    use diagnostics::operator_tools::SupportTools;
    use diagnostics::support_client::OperatorClient;
    use rmcp::{transport::stdio, ServiceExt};
    use std::sync::Arc;

    let run = async {
        let endpoint = std::env::var("FRIEND_SUPPORT_ENDPOINT")?;
        let token = std::env::var("FRIEND_SUPPORT_ACCESS_JWT")?;
        let client = OperatorClient::new(&endpoint, token)?;
        let service = SupportTools::new(Arc::new(client)).serve(stdio()).await?;
        service.waiting().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    if let Err(error) = run.await {
        eprintln!("Friend support adapter could not start: {error}");
        std::process::exit(2);
    }
}
