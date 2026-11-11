//! Link settings, Windows resources and the optional `site.toml` settings for the DiagnosticTool GUI.

use std::env;
use std::fs;
use std::path::PathBuf;

#[path = "src/site_rules.rs"]
mod site_rules;

const BIN: &str = "DiagnosticTool";

fn main() {
    for input in [
        "build.rs",
        "src/site_rules.rs",
        "assets/app.rc",
        "assets/app.manifest",
        "assets/app.ico",
    ] {
        println!("cargo:rerun-if-changed={input}");
    }
    write_site();
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    // The loader resolves the exe's imports from System32 only, so a DLL planted
    // beside it in Downloads (gdiplus.dll, dwmapi.dll) is never loaded.
    println!("cargo:rustc-link-arg-bin={BIN}=/DEPENDENTLOADFLAG:0x800");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::write(out_dir.join("version.rh"), version_header()).expect("write version.rh");
    let assets =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets it")).join("assets");
    embed_resource::compile_for(
        "assets/app.rc",
        [BIN],
        embed_resource::ParamsIncludeDirs([assets]),
    )
    .manifest_required()
    .expect("compile assets/app.rc");
}

/// The package version as VERSIONINFO wants it: four numbers and the full string.
fn version_header() -> String {
    let part = |name: &str| env::var(name).expect("cargo sets the version parts");
    let full = part("CARGO_PKG_VERSION");
    let pre_release = !part("CARGO_PKG_VERSION_PRE").is_empty();
    format!(
        "#define VER_NUMERIC {},{},{},0\n#define VER_STRING \"{full}\"\n#define VER_FLAGS {}\n",
        part("CARGO_PKG_VERSION_MAJOR"),
        part("CARGO_PKG_VERSION_MINOR"),
        part("CARGO_PKG_VERSION_PATCH"),
        // VS_FF_PRERELEASE marks rc and beta builds in the file properties.
        if pre_release { "0x2" } else { "0x0" },
    )
}

/// The values `site.toml` gives, each `None` when its key is absent.
#[derive(Default)]
struct Site {
    operator_name: Option<String>,
    support: Option<(String, String)>,
    update: Option<(String, String)>,
}

/// Reads `site.toml` when present and writes `$OUT_DIR/site.rs`; a bad file fails the build.
fn write_site() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let path = manifest.join("site.toml");
    // Cargo reruns a script every build for a watched file that is missing, so only an
    // existing site.toml is watched; after adding one to a built tree, touch build.rs.
    if path.exists() {
        println!("cargo:rerun-if-changed=site.toml");
    }
    let site = match fs::read_to_string(&path) {
        Ok(text) => parse_site(&text).unwrap_or_else(|message| {
            eprintln!("error: site.toml: {message}");
            std::process::exit(1);
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Site::default(),
        Err(error) => {
            eprintln!("error: site.toml could not be read: {error}");
            std::process::exit(1);
        }
    };
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::write(out_dir.join("site.rs"), site_source(&site)).expect("write site.rs");
}

/// Flat `key = "value"` lines; blank lines and `#` comments are skipped.
fn parse_site(text: &str) -> Result<Site, String> {
    const KEYS: [&str; 5] = [
        "operator_name",
        "support_endpoint",
        "support_operator_email",
        "update_base",
        "update_public_key",
    ];
    let mut found: Vec<(&str, String)> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |message: &str| format!("line {number}: {message}: {line}");
        let Some((key, value)) = line.split_once('=') else {
            return Err(at("expected key = \"value\""));
        };
        let key = key.trim();
        let Some(&known) = KEYS.iter().find(|known| **known == key) else {
            return Err(at("unknown key"));
        };
        if found.iter().any(|(seen, _)| *seen == known) {
            return Err(at("key given twice"));
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .filter(|inner| !inner.contains(['"', '\\']) && !inner.chars().any(char::is_control))
            .ok_or_else(|| {
                at("the value must be one quoted string without quotes or backslashes")
            })?;
        match known {
            "support_endpoint" => site_rules::check_support_endpoint(value).map_err(|m| at(&m))?,
            "update_base" => site_rules::check_update_base(value).map_err(|m| at(&m))?,
            "operator_name" => site_rules::check_operator_name(value).map_err(|m| at(&m))?,
            "update_public_key" => {
                let lowercase_hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
                if value.len() != 128 || !value.chars().all(lowercase_hex) {
                    return Err(at("the key must be 128 lowercase hex characters"));
                }
            }
            _ if value.is_empty() => return Err(at("the value is empty")),
            _ => {}
        }
        found.push((known, value.to_string()));
    }
    let get = |key: &str| {
        found
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.clone())
    };
    let pair = |first: &str, second: &str| match (get(first), get(second)) {
        (Some(a), Some(b)) => Ok(Some((a, b))),
        (None, None) => Ok(None),
        _ => Err(format!("{first} and {second} must be given together")),
    };
    Ok(Site {
        operator_name: get("operator_name"),
        support: pair("support_endpoint", "support_operator_email")?,
        update: pair("update_base", "update_public_key")?,
    })
}

/// The constants `src/site.rs` includes.
fn site_source(site: &Site) -> String {
    let name = match &site.operator_name {
        Some(name) => format!("Some({name:?})"),
        None => "None".into(),
    };
    let support = match &site.support {
        Some((endpoint, email)) => {
            format!("Some(Support {{ endpoint: {endpoint:?}, operator_email: {email:?} }})")
        }
        None => "None".into(),
    };
    let update = match &site.update {
        Some((base, key)) => {
            let bytes: Vec<String> = (0..64)
                .map(|i| format!("0x{}", &key[i * 2..i * 2 + 2]))
                .collect();
            format!(
                "Some(crate::update::Source {{ base: {base:?}, public_key_xy: [{}] }})",
                bytes.join(", ")
            )
        }
        None => "None".into(),
    };
    format!(
        "pub const OPERATOR_NAME: Option<&str> = {name};\npub const SUPPORT: Option<Support> = {support};\npub const UPDATE: Option<crate::update::Source> = {update};\n"
    )
}
