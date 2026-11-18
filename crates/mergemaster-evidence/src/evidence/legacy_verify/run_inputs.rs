//! Borrowed CLI pairs and accepted-base overwrite order, without a String map bridge.
use super::{InputMap, python_repr::Repr, value_inputs::TextRef};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError};

#[derive(Default)]
pub struct RunInputs<'a> {
    entries: Vec<(TextRef<'a>, TextRef<'a>)>,
}
impl<'a> RunInputs<'a> {
    pub fn parse(pairs: impl IntoIterator<Item = TextRef<'a>>) -> Result<Self, PolicyError> {
        let mut inputs = Self::default();
        for pair in pairs {
            let (key, value) = pair
                .split_once("=")
                .filter(|(key, _)| key.len() != 0)
                .ok_or_else(|| PolicyError {
                    resource: None,
                    origin: ErrorOrigin::Failure,
                    reason: "error",
                    detail: format!("--run-input must be KEY=VALUE, not {}", Repr(pair)).into(),
                })?;
            inputs.insert(key, value);
        }
        Ok(inputs)
    }
    fn insert(&mut self, key: TextRef<'a>, value: TextRef<'a>) {
        if let Some((_, old)) = self
            .entries
            .iter_mut()
            .find(|(name, _)| name.points().eq(key.points()))
        {
            *old = value;
        } else {
            self.entries.push((key, value));
        }
    }
    /// Keep the accepted-base reader's owned hashes alive while this view is used.
    /// Accepted values override caller pairs, retaining the original key position.
    pub fn merge_base(&mut self, base: &'a [(TextRef<'a>, String)]) {
        for (key, value) in base {
            self.insert(*key, TextRef::Str(value));
        }
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (TextRef<'_>, TextRef<'_>)> {
        self.entries.iter().copied()
    }
}
impl InputMap for RunInputs<'_> {
    fn get_text(&self, key: TextRef<'_>) -> Option<TextRef<'_>> {
        self.entries
            .iter()
            .find(|(name, _)| name.points().eq(key.points()))
            .map(|(_, value)| *value)
    }
}
#[cfg(test)]
#[path = "run_inputs_merge_tests.rs"]
mod tests;
