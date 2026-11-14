//! Library-only `--crate-key` parsing; policy loading and terminal sinks stay unwired.
use super::{Failure, python_repr::Repr, value_inputs::TextRef};
use crate::evidence::legacy_policy::ErrorOrigin;
use std::borrow::Cow;

pub struct ParsedCrateKey<'a> {
    pub name: TextRef<'a>,
    pub key: Cow<'a, str>,
}

/// Empty arguments are absent. Split only the first '=' and accept lowercase
/// SHA-1/SHA-256 syntax, without resolving or inspecting the named Git object.
/// Refusals use unbounded Python repr; callers must use an escaped wire sink.
pub fn parse(argument: TextRef<'_>) -> Result<Option<ParsedCrateKey<'_>>, Failure> {
    if argument.points().next().is_none() {
        return Ok(None);
    }
    let pair = match argument {
        TextRef::Str(text) => text
            .split_once('=')
            .map(|(name, key)| (TextRef::Str(name), TextRef::Str(key))),
        TextRef::Points(points) => points.iter().position(|p| *p == 61).map(|at| {
            (
                TextRef::Points(&points[..at]),
                TextRef::Points(&points[at + 1..]),
            )
        }),
    };
    if let Some((name, key)) = pair {
        let size = key.points().count();
        if name.points().next().is_some()
            && matches!(size, 40 | 64)
            && key.points().all(|p| matches!(p, 48..=57 | 97..=102))
        {
            let key = match key {
                TextRef::Str(key) => Cow::Borrowed(key),
                // The predicate above establishes ASCII; no lossy conversion.
                TextRef::Points(points) => {
                    Cow::Owned(points.iter().filter_map(|p| char::from_u32(*p)).collect())
                }
            };
            return Ok(Some(ParsedCrateKey { name, key }));
        }
    }
    Err(Failure {
        reason: "error",
        detail: format!(
            "--crate-key must be CRATE=KEY with a git tree id, not {}",
            Repr(argument)
        )
        .into(),
        attempts: None,
        origin: ErrorOrigin::Failure,
    })
}

#[cfg(test)]
#[path = "crate_key_argument_tests.rs"]
mod tests;
