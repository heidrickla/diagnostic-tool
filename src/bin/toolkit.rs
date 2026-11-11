//! The toolkit from a console: `toolkit <tool> [options]`, `toolkit help`.
use std::io::{self, Write};
use std::process::ExitCode;

use diagnostics::tools;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        None => Ok(tools::list()),
        Some((name, _)) if name == "help" || name == "--help" || name == "-h" => Ok(tools::list()),
        Some((name, rest)) => tools::run(name, rest),
    };
    match result {
        // A reader that stops early (a pipe to `head`) is not a failure of the tool.
        Ok(text) => match writeln!(io::stdout().lock(), "{text}") {
            Err(error) if error.kind() != io::ErrorKind::BrokenPipe => {
                eprintln!("could not write the output: {error}");
                ExitCode::from(2)
            }
            _ => ExitCode::SUCCESS,
        },
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
