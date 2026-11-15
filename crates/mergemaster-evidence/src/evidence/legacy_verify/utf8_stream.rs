//! Strict incremental UTF-8 with original whole-stream error offsets.
#[derive(Default)]
pub struct Utf8 {
    pending: [u8; 4],
    used: usize,
    position: u128,
    error: Option<String>,
}
impl Utf8 {
    pub fn push(&mut self, bytes: &[u8], mut emit: impl FnMut(char)) {
        if self.error.is_some() {
            return;
        }
        for &byte in bytes {
            self.position += 1;
            if self.used == 0 && byte.is_ascii() {
                emit(char::from(byte));
                continue;
            }
            self.pending[self.used] = byte;
            self.used += 1;
            match std::str::from_utf8(&self.pending[..self.used]) {
                Ok(text) => {
                    if let Some(character) = text.chars().next() {
                        emit(character);
                    }
                    self.used = 0;
                }
                Err(error) if error.error_len().is_some() => {
                    self.error = Some(super::crate_inputs_text::utf8_error(
                        &self.pending[..self.used],
                        error,
                        self.position - self.used as u128,
                    ));
                    return;
                }
                Err(_) => {}
            }
        }
    }
    pub fn finish(self) -> Result<(), String> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.used != 0 {
            return std::str::from_utf8(&self.pending[..self.used])
                .map(|_| ())
                .map_err(|error| {
                    super::crate_inputs_text::utf8_error(
                        &self.pending[..self.used],
                        error,
                        self.position - self.used as u128,
                    )
                });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "utf8_stream_tests.rs"]
mod tests;
