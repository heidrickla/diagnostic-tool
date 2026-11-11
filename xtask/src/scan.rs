//! Finds builder-specific paths inside a binary, in UTF-8 and UTF-16LE, ignoring
//! ASCII case and the choice of path separator.

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub needle: String,
    pub encoding: &'static str,
    pub offset: usize,
}

/// The first occurrence of each needle in each encoding.
pub fn find_paths(haystack: &[u8], needles: &[String]) -> Vec<Finding> {
    let lowered = haystack.to_ascii_lowercase();
    let mut findings = Vec::new();
    for needle in needles {
        let trimmed = needle.trim_end_matches(['\\', '/']);
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        let mut forms = vec![lower.clone()];
        let flipped = lower.replace('\\', "/");
        if flipped != lower {
            forms.push(flipped);
        }
        for form in &forms {
            let utf16: Vec<u8> = form.encode_utf16().flat_map(u16::to_le_bytes).collect();
            for (encoding, pattern) in [("UTF-8", form.as_bytes()), ("UTF-16LE", &utf16[..])] {
                if let Some(offset) = position(&lowered, pattern) {
                    findings.push(Finding {
                        needle: form.clone(),
                        encoding,
                        offset,
                    });
                }
            }
        }
    }
    findings
}

fn position(haystack: &[u8], pattern: &[u8]) -> Option<usize> {
    let first = *pattern.first()?;
    let last_start = haystack.len().checked_sub(pattern.len())?;
    (0..=last_start).find(|&i| haystack[i] == first && &haystack[i..i + pattern.len()] == pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needles() -> Vec<String> {
        vec![
            r"C:\Users\Builder".to_string(),
            r"D:\Work\diagnostic-tool\".to_string(),
        ]
    }

    // Shaped like an unremapped build: a registry path in a panic location.
    fn unremapped_fixture() -> Vec<u8> {
        let mut exe = b"MZ\0\0panic at ".to_vec();
        exe.extend_from_slice(br"c:\users\BUILDER\.cargo\registry\src\index\tokio-1.0\src\lib.rs");
        exe.extend_from_slice(b"\0\0");
        let wide = "D:/Work/Diagnostic-Tool/target/release/build/out";
        exe.extend(wide.encode_utf16().flat_map(u16::to_le_bytes));
        exe
    }

    #[test]
    fn unremapped_build_paths_are_found_in_both_encodings() {
        let found = find_paths(&unremapped_fixture(), &needles());
        let summary: Vec<_> = found
            .iter()
            .map(|f| (f.needle.as_str(), f.encoding))
            .collect();
        assert_eq!(
            summary,
            [
                (r"c:\users\builder", "UTF-8"),
                ("d:/work/diagnostic-tool", "UTF-16LE"),
            ]
        );
    }

    #[test]
    fn remapped_build_paths_are_clean() {
        let mut exe = b"MZ\0\0panic at /cargo/registry/src/index/tokio-1.0/src/lib.rs\0".to_vec();
        exe.extend(
            "/build/target/release"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        exe.extend_from_slice(b"Copyright 2026 Example Author users");
        assert!(find_paths(&exe, &needles()).is_empty());
    }
}
