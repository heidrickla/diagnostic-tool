//! Limited operator MCP tools. The backend is injectable so the exact MCP
//! surface can be tested against in-memory HTTP handlers and fixture JWTs.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

use crate::protocol::{check_arguments, toolkit_commands, toolkit_deadline_text, toolkit_tool};
use crate::support_client::OperatorClient;
use crate::support_transport::{Command, Requested, RequestedTool, ResultForOperator};

/// The fixed diagnostics the relay accepts; `toolkit.<name>` commands follow them.
const FIXED: [&str; 3] = ["os.version", "memory.total", "disk.free"];

fn in_catalog(command_id: &str) -> bool {
    FIXED.contains(&command_id) || toolkit_tool(command_id).is_some()
}

/// The catalog as the operator reads it: each command, and each tool's usage.
pub fn catalog_text() -> String {
    let mut text = String::from("Fixed diagnostics (no arguments, deadline 15 s):\n");
    for id in FIXED {
        text.push_str(&format!("  {id}\n"));
    }
    text.push_str(
        "Toolkit tools (read-only; arguments are plain tokens checked against the usage; \
         the result is JSON when the tool has it, else text, capped and redacted; \
         each has its own deadline from the tool's time bound):\n",
    );
    for id in toolkit_commands() {
        if let Some(tool) = toolkit_tool(id) {
            let deadline =
                toolkit_deadline_text(tool.name).unwrap_or_else(|| "deadline 15 s".into());
            text.push_str(&format!(
                "\n{id}: {} ({deadline})\n{}\n",
                tool.summary, tool.usage
            ));
        }
    }
    text
}

pub type ToolFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

pub trait OperatorBackend: Send + Sync {
    fn pair<'a>(&'a self, code: String) -> ToolFuture<'a, String>;
    fn request<'a>(&'a self, session: String, command: Command) -> ToolFuture<'a, ()>;
    /// A request with typed arguments. Backends that carry none accept only an empty list.
    fn request_tool<'a>(
        &'a self,
        session: String,
        command: Command,
        args: Vec<String>,
    ) -> ToolFuture<'a, ()> {
        if args.is_empty() {
            return self.request(session, command);
        }
        Box::pin(async { Err("this backend carries no typed arguments".into()) })
    }
    fn result<'a>(&'a self, session: String, request_id: u64) -> ToolFuture<'a, Option<String>>;
    fn end<'a>(&'a self, session: String) -> ToolFuture<'a, ()>;
}

impl OperatorBackend for OperatorClient {
    fn pair<'a>(&'a self, code: String) -> ToolFuture<'a, String> {
        Box::pin(async move { self.match_code(code).await.map(|value| value.session) })
    }
    fn request<'a>(&'a self, session: String, command: Command) -> ToolFuture<'a, ()> {
        Box::pin(async move { self.request(Requested { session, command }).await })
    }
    fn request_tool<'a>(
        &'a self,
        session: String,
        command: Command,
        args: Vec<String>,
    ) -> ToolFuture<'a, ()> {
        Box::pin(async move {
            OperatorClient::request_tool(
                self,
                RequestedTool {
                    session,
                    command,
                    args,
                },
            )
            .await
        })
    }
    fn result<'a>(&'a self, session: String, request_id: u64) -> ToolFuture<'a, Option<String>> {
        Box::pin(async move {
            self.result(ResultForOperator {
                session,
                request_id,
            })
            .await
            .map(|value| value.output)
        })
    }
    fn end<'a>(&'a self, session: String) -> ToolFuture<'a, ()> {
        Box::pin(async move { self.end(session).await })
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PairArgs {
    code: String,
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CommandArgs {
    session: String,
    command_id: String,
    request_id: u64,
    /// Typed arguments for a `toolkit.<name>` command, as on its usage line.
    #[serde(default)]
    args: Vec<String>,
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ResultArgs {
    session: String,
    request_id: u64,
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EndArgs {
    session: String,
}

#[derive(Clone)]
pub struct SupportTools {
    backend: Arc<dyn OperatorBackend>,
}
impl SupportTools {
    pub fn new(backend: Arc<dyn OperatorBackend>) -> Self {
        Self { backend }
    }
}

#[tool_router(server_handler)]
impl SupportTools {
    #[tool(
        description = "Match a computer owner who approved a diagnostic session and read you the one-time code"
    )]
    async fn pair(&self, Parameters(args): Parameters<PairArgs>) -> String {
        match self.backend.pair(args.code).await {
            Ok(session) => format!("Paired session: {session}"),
            Err(error) => format!("Pairing refused: {error}"),
        }
    }

    #[tool(
        description = "List the cataloged read-only commands: the fixed diagnostics and one toolkit.<name> per toolkit tool, with each tool's usage"
    )]
    async fn command_catalog(&self) -> String {
        catalog_text()
    }

    #[tool(
        description = "Request one bounded read-only diagnostic from a consented session; toolkit.<name> commands take typed arguments from the tool's usage"
    )]
    async fn request_diagnostic(&self, Parameters(args): Parameters<CommandArgs>) -> String {
        if !in_catalog(&args.command_id) {
            return "Diagnostic command is outside the reviewed catalog.".into();
        }
        if let Err(reason) = check_arguments(&args.command_id, &args.args) {
            return format!("Diagnostic refused: {reason}");
        }
        match self
            .backend
            .request_tool(
                args.session,
                Command {
                    request_id: args.request_id,
                    command_id: args.command_id,
                },
                args.args,
            )
            .await
        {
            Ok(()) => "Diagnostic requested. The computer owner can Pause or Disconnect.".into(),
            Err(error) => format!("Diagnostic refused: {error}"),
        }
    }

    #[tool(description = "Read one bounded diagnostic result from a consented session")]
    async fn read_result(&self, Parameters(args): Parameters<ResultArgs>) -> String {
        match self.backend.result(args.session, args.request_id).await {
            Ok(Some(output)) => output,
            Ok(None) => "No result available yet.".into(),
            Err(error) => format!("Result unavailable: {error}"),
        }
    }

    #[tool(description = "End the diagnostic session and revoke pending commands")]
    async fn end_session(&self, Parameters(args): Parameters<EndArgs>) -> String {
        match self.backend.end(args.session).await {
            Ok(()) => "Session ended.".into(),
            Err(error) => format!("End session failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records what reached the backend; the relay itself is tested in `support_transport`.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, Vec<String>)>>);
    impl OperatorBackend for Recorder {
        fn pair<'a>(&'a self, _: String) -> ToolFuture<'a, String> {
            Box::pin(async { Err("unused".into()) })
        }
        fn request<'a>(&'a self, _: String, command: Command) -> ToolFuture<'a, ()> {
            self.request_tool(String::new(), command, Vec::new())
        }
        fn request_tool<'a>(
            &'a self,
            _: String,
            command: Command,
            args: Vec<String>,
        ) -> ToolFuture<'a, ()> {
            self.0.lock().unwrap().push((command.command_id, args));
            Box::pin(async { Ok(()) })
        }
        fn result<'a>(&'a self, _: String, _: u64) -> ToolFuture<'a, Option<String>> {
            Box::pin(async { Ok(None) })
        }
        fn end<'a>(&'a self, _: String) -> ToolFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn typed_requests_are_checked_before_they_leave_the_adapter() {
        let recorder = Arc::new(Recorder::default());
        let tools = SupportTools::new(recorder.clone());
        let ask = |command_id: &str, args: &[&str]| {
            Parameters(CommandArgs {
                session: "s".into(),
                command_id: command_id.into(),
                request_id: 1,
                args: args.iter().map(|arg| arg.to_string()).collect(),
            })
        };
        let unknown = tools.request_diagnostic(ask("toolkit.shell", &[])).await;
        assert!(unknown.contains("outside the reviewed catalog"));
        for (id, args) in [
            ("toolkit.events", &["--format", "x"][..]),
            ("toolkit.perf", &["--seconds", "301"][..]),
            ("toolkit.space", &["--drive", "C:/"][..]),
            ("disk.free", &["--all"][..]),
        ] {
            let refused = tools.request_diagnostic(ask(id, args)).await;
            assert!(refused.starts_with("Diagnostic refused"), "{id} {refused}");
        }
        assert!(recorder.0.lock().unwrap().is_empty());
        let sent = tools
            .request_diagnostic(ask("toolkit.perf", &["--seconds", "5", "--top", "3"]))
            .await;
        assert!(sent.contains("Diagnostic requested"), "{sent}");
        assert_eq!(
            *recorder.0.lock().unwrap(),
            [(
                "toolkit.perf".to_string(),
                vec!["--seconds".into(), "5".into(), "--top".into(), "3".into()]
            )]
        );
    }

    #[test]
    fn catalog_lists_every_toolkit_tool_with_its_usage() {
        let text = catalog_text();
        for tool in crate::tools::TOOLS {
            let id = format!("toolkit.{}", tool.name);
            assert!(in_catalog(&id), "{id}");
            assert!(text.contains(&format!("{id}: ")), "{id}");
            assert!(text.contains(tool.usage), "{id} usage");
        }
        assert!(text.contains("toolkit.perf: ") && text.contains("--seconds value plus 5 s"));
        assert!(in_catalog("os.version"));
        assert!(!in_catalog("toolkit.shell"));
        assert!(!in_catalog("toolkit."));
        assert!(!in_catalog("hardware.inventory"));
    }
}
