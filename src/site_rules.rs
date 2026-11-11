//! What `site.toml` may hold. The build script and the library both use these functions, so
//! a value the build accepts is one the update and support code can use.

/// The longest operator name, in characters; the start heading fits its line with it.
pub const OPERATOR_NAME_MAX: usize = 12;

/// Splits an `https://host/path` address into host and path. The host is dot-separated
/// labels of ASCII letters, digits and hyphens; there is no userinfo, port, query or fragment.
pub fn https_parts(url: &str) -> Result<(&str, &str), String> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the address has whitespace or control characters".into());
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or("the address must start with https://")?;
    if rest.contains(['?', '#', '\\']) {
        return Err("the address must have no query, fragment or backslash".into());
    }
    let (host, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    if host.contains('@') {
        return Err("the address must have no user name".into());
    }
    if host.contains(':') {
        return Err("the address must have no port".into());
    }
    check_host(host)?;
    Ok((host, path))
}

fn check_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("the address has no host".into());
    }
    if host.len() > 253 {
        return Err("the host name is too long".into());
    }
    for label in host.split('.') {
        let edge = |c: Option<char>| c == Some('-');
        if label.is_empty() || label.len() > 63 {
            return Err("every part of the host name must be 1 to 63 characters".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("the host name may use only letters, digits, hyphens and dots".into());
        }
        if edge(label.chars().next()) || edge(label.chars().next_back()) {
            return Err("a part of the host name starts or ends with a hyphen".into());
        }
    }
    Ok(())
}

/// The update base: an https address with a path and no trailing slash.
pub fn check_update_base(url: &str) -> Result<(), String> {
    let (_, path) = https_parts(url)?;
    if path.is_empty() || path.ends_with('/') {
        return Err("the update address needs a path and no trailing slash".into());
    }
    Ok(())
}

/// The support endpoint: an https origin with no path.
pub fn check_support_endpoint(url: &str) -> Result<(), String> {
    let (_, path) = https_parts(url)?;
    if !path.is_empty() {
        return Err("the support address must be a host with no path".into());
    }
    Ok(())
}

/// A name that fits the start heading: not empty, at most `OPERATOR_NAME_MAX` characters,
/// no control characters, no space at either end.
pub fn check_operator_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the name is empty".into());
    }
    if name.chars().count() > OPERATOR_NAME_MAX {
        return Err(format!(
            "the name has more than {OPERATOR_NAME_MAX} characters"
        ));
    }
    if name.chars().any(char::is_control) {
        return Err("the name has a control character".into());
    }
    if name.starts_with(char::is_whitespace) || name.ends_with(char::is_whitespace) {
        return Err("the name has a space at its start or end".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_https_address_splits_into_host_and_path() {
        assert_eq!(
            https_parts("https://updates.example.com/releases/win"),
            Ok(("updates.example.com", "/releases/win"))
        );
        assert_eq!(https_parts("https://a-b.example"), Ok(("a-b.example", "")));
        assert_eq!(https_parts("https://host/"), Ok(("host", "/")));
    }

    #[test]
    fn every_rejection_class_is_refused() {
        for bad in [
            "http://host/x",
            "ftp://host/x",
            "host/x",
            "https://",
            "https:///releases",
            "https://host:8443/x",
            "https://host:/x",
            "https://user@host/x",
            "https://user:pw@host/x",
            "https://host/x?a=1",
            "https://host?a=1",
            "https://host/x#top",
            "https://host#top",
            "https://host/x y",
            "https://ho st/x",
            "https://host/x\t",
            "https://host/x\n",
            "https://host/x\\y",
            "https://.example.com/x",
            "https://example..com/x",
            "https://example.com./x",
            "https://-a.example.com/x",
            "https://a-.example.com/x",
            "https://exa_mple.com/x",
            "https://exämple.com/x",
            "https://[::1]/x",
            "https://[::1]:443/x",
        ] {
            assert!(https_parts(bad).is_err(), "{bad}");
        }
        let long_label = format!("https://{}.example/x", "a".repeat(64));
        assert!(https_parts(&long_label).is_err());
        let long_host = format!("https://{}/x", ["abcdefghi"; 30].join("."));
        assert!(https_parts(&long_host).is_err());
    }

    #[test]
    fn the_update_base_needs_a_path_without_a_trailing_slash() {
        assert!(check_update_base("https://updates.example.com/releases").is_ok());
        assert!(check_update_base("https://updates.example.com/a/b").is_ok());
        for bad in [
            "https://updates.example.com",
            "https://updates.example.com/",
            "https://updates.example.com/releases/",
            "https://updates.example.com:8443/releases",
            "https:///releases",
        ] {
            assert!(check_update_base(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_support_endpoint_is_an_origin_with_no_path() {
        assert!(check_support_endpoint("https://support.example.com").is_ok());
        for bad in [
            "https://support.example.com/",
            "https://support.example.com/api",
            "https://support.example.com:8443",
            "http://support.example.com",
        ] {
            assert!(check_support_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_operator_name_is_short_and_plain() {
        assert!(check_operator_name("Alex").is_ok());
        assert!(check_operator_name("Alex R-Smith").is_ok());
        assert!(check_operator_name(&"W".repeat(OPERATOR_NAME_MAX)).is_ok());
        assert!(check_operator_name(&"W".repeat(OPERATOR_NAME_MAX + 1)).is_err());
        for bad in ["", " Alex", "Alex ", "Al\tex", "Al\nex", "\u{7f}Alex"] {
            assert!(check_operator_name(bad).is_err(), "{bad:?}");
        }
        let multibyte = "é".repeat(OPERATOR_NAME_MAX);
        assert!(check_operator_name(&multibyte).is_ok());
    }
}
