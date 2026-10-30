//! CLI stdout policy copied from fractal at d6e91e3b6db855c30b4d35f2e78a29a3948b1ded.
use std::fmt;
use std::io::{self, Write as _};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

static CLOSED: AtomicBool = AtomicBool::new(false);

/// Streaming readers stop after a failed stdout write. Commands with effects keep running.
pub fn closed() -> bool {
    CLOSED.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! cli_print {
    ($($arg:tt)*) => { $crate::cli_output::print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! cli_println {
    () => { $crate::cli_print!("\n") };
    ($($arg:tt)*) => { $crate::cli_print!("{}\n", format_args!($($arg)*)) };
}

pub fn print(arguments: fmt::Arguments<'_>) {
    if closed() {
        return;
    }
    if let Err(error) = output_result(io::stdout().lock().write_fmt(arguments), ()) {
        let _ = writeln!(io::stderr().lock(), "st: write stdout: {error}");
        std::process::exit(1);
    }
}

fn output_result<T>(result: io::Result<T>, discarded: T) -> io::Result<T> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            CLOSED.store(true, Ordering::Relaxed);
            Ok(discarded)
        }
        other => other,
    }
}

/// Include a final unterminated line in the policy; std's shutdown flush ignores errors.
pub fn finish(code: ExitCode) -> ExitCode {
    if closed() {
        return code;
    }
    match io::stdout().flush() {
        Ok(()) => code,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => code,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "st: flush stdout: {error}");
            ExitCode::FAILURE
        }
    }
}

