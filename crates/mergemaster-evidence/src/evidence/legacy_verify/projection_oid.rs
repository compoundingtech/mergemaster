//! Bounded incremental Python-whitespace-stripped Git object IDs.
const OID_LIMIT: usize = 65;
pub fn space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
#[derive(Default)]
pub struct ObjectId {
    bytes: Vec<u8>,
    pending: [u8; 4],
    used: usize,
    trailing: bool,
    malformed: bool,
}
impl ObjectId {
    pub fn finish(self, width: usize) -> Option<Vec<u8>> {
        if self.malformed || self.used != 0 || self.bytes.len() != width {
            None
        } else {
            Some(self.bytes)
        }
    }
    fn character(&mut self, c: char) {
        if space(c) {
            self.trailing |= !self.bytes.is_empty();
        } else if c.is_ascii_hexdigit() && !self.trailing && self.bytes.len() < OID_LIMIT {
            self.bytes.push(c as u8);
        } else {
            self.malformed = true;
        }
    }
    pub fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.malformed {
                return;
            }
            if self.used == 0 && byte.is_ascii() {
                self.character(char::from(byte));
                continue;
            }
            self.pending[self.used] = byte;
            self.used += 1;
            match std::str::from_utf8(&self.pending[..self.used]) {
                Ok(text) => {
                    let c = text.chars().next();
                    self.used = 0;
                    if let Some(c) = c {
                        self.character(c);
                    }
                }
                Err(error) if error.error_len().is_some() || self.used == 4 => {
                    self.malformed = true
                }
                Err(_) => {}
            }
        }
    }
}
#[cfg(test)]
#[path = "projection_oid_tests.rs"]
mod tests;
