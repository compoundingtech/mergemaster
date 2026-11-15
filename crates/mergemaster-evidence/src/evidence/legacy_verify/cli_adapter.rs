//! Lossless CLI ingress. Dispatch consumes successful namespaces without reparsing.
pub use super::projection_process_error::decode;
use super::{
    argparse_diagnostic, argparse_int,
    argparse_parse::{self, ParseOutcome, ParsedArguments},
    terminal_sink,
    value_inputs::TextRef,
};

pub struct Exit {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}
#[derive(Debug)]
pub enum Error {
    Option(argparse_diagnostic::InvalidOption),
    Sink(terminal_sink::Error),
}
pub fn prepare<'a>(
    argv: &[TextRef<'a>],
    width: usize,
) -> Result<Result<ParsedArguments<'a>, Exit>, Error> {
    let outcome = argparse_parse::parse(argv);
    if let Ok(ParseOutcome::Parsed(parsed)) = outcome {
        return Ok(Ok(parsed));
    }
    let streams = argparse_diagnostic::render(outcome, TextRef::Str("evidence-verify"), width)
        .map_err(Error::Option)?;
    // The only remaining outcomes are help or a parser diagnostic.
    let Some(streams) = streams else {
        return Err(Error::Option(argparse_diagnostic::InvalidOption));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    streams
        .stdout
        .write_terminal(&mut stdout)
        .map_err(Error::Sink)?;
    streams
        .stderr
        .write_terminal(&mut stderr)
        .map_err(Error::Sink)?;
    Ok(Err(Exit {
        stdout,
        stderr,
        code: if streams.exit == 0 { 0 } else { 2 },
    }))
}
/// shutil.get_terminal_size: positive COLUMNS, then original stdout, then 80.
/// The formatter receives columns minus two, with Python's minimum of zero.
pub fn width() -> usize {
    let columns = std::env::var_os("COLUMNS")
        .and_then(|v| argparse_int::parse(decode(&v).borrowed()).ok())
        .filter(argparse_int::Integer::is_positive);
    let columns = columns.map_or_else(
        || {
            let mut size = std::mem::MaybeUninit::<libc::winsize>::uninit();
            // SAFETY: ioctl writes a winsize into the correctly sized live pointer;
            // only a successful result permits reading the initialized value.
            if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) } == 0
            {
                let size = unsafe { size.assume_init() };
                if size.ws_col > 0 {
                    return usize::from(size.ws_col);
                }
            }
            80
        },
        |v| v.digits.parse::<usize>().unwrap_or(usize::MAX),
    );
    columns.saturating_sub(2)
}
#[cfg(test)]
#[path = "cli_adapter_tests.rs"]
mod tests;
