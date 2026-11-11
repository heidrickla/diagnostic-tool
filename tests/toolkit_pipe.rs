//! The toolkit binary ends cleanly when its reader goes away before it writes.
use std::process::{Command, Stdio};

#[test]
fn a_closed_output_pipe_is_not_a_crash() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_toolkit"))
        .arg("help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
