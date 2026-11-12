//! Settings fixed at build time from `site.toml`; a build without that file has none of
//! them and works as a generic program.

/// The support service a friend's session connects to and the one account it trusts.
pub struct Support {
    pub endpoint: &'static str,
    pub operator_email: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/site.rs"));

/// How the person helping is named in a build without an operator name.
pub const GENERIC_OPERATOR: &str = "your technician";
/// The same, for the start of a sentence.
pub const GENERIC_OPERATOR_FIRST: &str = "Your technician";

/// How friend-facing text names the person helping, for use inside a sentence.
pub fn operator() -> &'static str {
    OPERATOR_NAME.unwrap_or(GENERIC_OPERATOR)
}

/// The same name for the start of a sentence.
pub fn operator_first() -> &'static str {
    OPERATOR_NAME.unwrap_or(GENERIC_OPERATOR_FIRST)
}

/// The support endpoint's host, such as `support.example.com`.
pub fn support_host() -> Option<&'static str> {
    let endpoint = SUPPORT.as_ref()?.endpoint;
    let rest = endpoint.strip_prefix("https://").unwrap_or(endpoint);
    Some(rest.split(['/', ':']).next().unwrap_or(rest))
}
