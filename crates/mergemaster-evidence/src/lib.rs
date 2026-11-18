//! Portable signed gate observations in immutable Git notes.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
#[doc(hidden)]
pub mod cli_output;
pub mod evidence;
pub mod gate;
pub mod parity_drift;
#[cfg(test)]
pub(crate) mod pinned_python;
mod product_dirs;
