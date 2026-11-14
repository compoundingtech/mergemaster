//! Python 3.14.7 string repr, using generated Unicode 16.0.0 printability.
//! Only diagnostic text; this primitive never decides record acceptance.
use super::value_inputs::TextRef;
use std::fmt::{self, Write};

const RANGES: &[u8] = include_bytes!("python_printable.generated.bin");
fn bound(at: usize) -> u32 {
    u32::from_le_bytes([RANGES[at], RANGES[at + 1], RANGES[at + 2], RANGES[at + 3]])
}
fn printable(point: u32) -> bool {
    if point < 128 {
        return (32..127).contains(&point);
    }
    let (mut low, mut high) = (0_usize, RANGES.len() / 8);
    while low < high {
        let middle = low.midpoint(high);
        if point < bound(middle * 8) {
            high = middle;
        } else if point <= bound(middle * 8 + 4) {
            return true;
        } else {
            low = middle + 1;
        }
    }
    false
}
/// Borrowed Python text (code points 0..=0x10ffff, including lone surrogates).
/// Streaming repr is always scalar text, even when the input contains surrogates.
pub struct Repr<'a>(pub TextRef<'a>);
impl fmt::Display for Repr<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let quote = if self.0.points().any(|p| p == 39) && !self.0.points().any(|p| p == 34) {
            '"'
        } else {
            '\''
        };
        out.write_char(quote)?;
        for point in self.0.points() {
            match point {
                9 => out.write_str("\\t")?,
                10 => out.write_str("\\n")?,
                13 => out.write_str("\\r")?,
                92 => out.write_str("\\\\")?,
                p if p == u32::from(quote) => {
                    out.write_char('\\')?;
                    out.write_char(quote)?;
                }
                p if printable(p) => out.write_char(char::from_u32(p).ok_or(fmt::Error)?)?,
                p if p < 256 => write!(out, "\\x{p:02x}")?,
                p if p < 65536 => write!(out, "\\u{p:04x}")?,
                p => write!(out, "\\U{p:08x}")?,
            }
        }
        out.write_char(quote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_repr_and_generated_assets_match_exhaustively() {
        let generator = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/evidence/legacy_verify/gen_python_printable.py"
        );
        let result = std::process::Command::new("python3")
            .args([generator, "--check"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result = std::process::Command::new("python3").args(["-c", r#"
import itertools,json
values=[''.join(map(chr,range(0x110000)))]+[''.join(parts) for n in range(5) for parts in itertools.product("'\"\\\n\ta",repeat=n)]
print(json.dumps([repr(value) for value in values]))
"#]).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let expected: Vec<String> = serde_json::from_slice(&result.stdout).unwrap();
        let points: Vec<u32> = (0..0x110000).collect();
        assert_eq!(Repr(TextRef::Points(&points)).to_string(), expected[0]);
        let alphabet = [39, 34, 92, 10, 9, 97];
        let mut at = 1;
        for length in 0..5_u32 {
            for mut index in 0..6_usize.pow(length) {
                let mut value = vec![0; length as usize];
                for point in value.iter_mut().rev() {
                    *point = alphabet[index % 6];
                    index /= 6;
                }
                assert_eq!(Repr(TextRef::Points(&value)).to_string(), expected[at]);
                let scalar: String = value.iter().map(|p| char::from_u32(*p).unwrap()).collect();
                assert_eq!(Repr(TextRef::Str(&scalar)).to_string(), expected[at]);
                at += 1;
            }
        }
        assert_eq!(at, expected.len());
    }
}
