//! Python json.loads byte transport, before JSON parsing or statement validation.
/// Python strings may contain lone surrogates, so retain code points, not Rust chars.
/// Matches json.detect_encoding followed by decoding with errors="surrogatepass".
pub fn decode_json_bytes(bytes: &[u8]) -> Option<Vec<u32>> {
    decode_json_bytes_exact(bytes).ok()
}
#[derive(Debug)]
pub struct DecodeError {
    codec: &'static str,
    start: usize,
    end: usize,
    byte: u8,
    reason: &'static str,
}
impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}' codec can't decode ", self.codec)?;
        if self.end == self.start + 1 {
            write!(f, "byte 0x{:02x} in position {}", self.byte, self.start)?;
        } else {
            write!(f, "bytes in position {}-{}", self.start, self.end - 1)?;
        }
        write!(f, ": {}", self.reason)
    }
}
/// Exact UnicodeDecodeError text for callers where Python does not catch decoding.
pub fn decode_json_bytes_exact(bytes: &[u8]) -> Result<Vec<u32>, DecodeError> {
    let (data, width, little) = if bytes.starts_with(b"\0\0\xfe\xff") {
        (&bytes[4..], 4, false)
    } else if bytes.starts_with(b"\xff\xfe\0\0") {
        (&bytes[4..], 4, true)
    } else if bytes.starts_with(b"\xfe\xff") {
        (&bytes[2..], 2, false)
    } else if bytes.starts_with(b"\xff\xfe") {
        (&bytes[2..], 2, true)
    } else if bytes.starts_with(b"\xef\xbb\xbf") {
        (&bytes[3..], 1, false)
    } else if bytes.len() >= 4 && bytes[0] == 0 {
        (bytes, if bytes[1] == 0 { 4 } else { 2 }, false)
    } else if bytes.len() >= 4 && bytes[1] == 0 {
        (
            bytes,
            if bytes[2] == 0 && bytes[3] == 0 { 4 } else { 2 },
            true,
        )
    } else if bytes.len() == 2 && (bytes[0] == 0 || bytes[1] == 0) {
        (bytes, 2, bytes[1] == 0)
    } else {
        (bytes, 1, false)
    };
    let codec = match (width, little) {
        (2, true) => "utf-16-le",
        (2, false) => "utf-16-be",
        (4, true) => "utf-32-le",
        (4, false) => "utf-32-be",
        _ => "utf-8",
    };
    let offset = if width == 1 {
        0
    } else {
        bytes.len() - data.len()
    };
    let error = |start: usize, end: usize, reason| DecodeError {
        codec,
        start: start + offset,
        end: end + offset,
        byte: data[start],
        reason,
    };
    let mut points = Vec::with_capacity(data.len() / width);
    let mut i = 0;
    while i < data.len() {
        let mut point = u32::from(data[i]);
        if width == 1 {
            let length = match data[i] {
                0..=0x7f => 1,
                0xc2..=0xdf => {
                    point &= 0x1f;
                    2
                }
                0xe0..=0xef => {
                    point &= 0x0f;
                    3
                }
                0xf0..=0xf4 => {
                    point &= 7;
                    4
                }
                _ => return Err(error(i, i + 1, "invalid start byte")),
            };
            // CPython's surrogatepass handler accepts only complete surrogate triples.
            if data[i] == 0xed
                && data.get(i + 1).is_some_and(|b| *b >= 0xa0)
                && !(data.get(i + 2).is_some_and(|b| b & 0xc0 == 0x80) && data[i + 1] <= 0xbf)
            {
                return Err(error(i, i + 1, "invalid continuation byte"));
            }
            for j in 1..length {
                let Some(&byte) = data.get(i + j) else {
                    return Err(error(i, data.len(), "unexpected end of data"));
                };
                if byte & 0xc0 != 0x80
                    || (j == 1
                        && ((data[i] == 0xe0 && byte < 0xa0)
                            || (data[i] == 0xf0 && byte < 0x90)
                            || (data[i] == 0xf4 && byte > 0x8f)))
                {
                    return Err(error(i, i + j, "invalid continuation byte"));
                }
                point = (point << 6) | u32::from(byte & 0x3f);
            }
            i += length;
        } else {
            if data.len() - i < width {
                return Err(error(i, data.len(), "truncated data"));
            }
            point = 0;
            for (j, &byte) in data[i..i + width].iter().enumerate() {
                point |= u32::from(byte) << (8 * if little { j } else { width - j - 1 });
            }
            i += width;
            if width == 2 && (0xd800..=0xdbff).contains(&point) && data.len() - i >= 2 {
                let next = if little {
                    u16::from_le_bytes([data[i], data[i + 1]])
                } else {
                    u16::from_be_bytes([data[i], data[i + 1]])
                };
                if (0xdc00..=0xdfff).contains(&next) {
                    point = 0x10000 + ((point - 0xd800) << 10) + u32::from(next - 0xdc00);
                    i += 2;
                }
            }
            if point > 0x10ffff {
                return Err(error(i - width, i, "code point not in range(0x110000)"));
            }
        }
        points.push(point);
    }
    Ok(points)
}
#[cfg(test)]
#[path = "statement_bytes_tests.rs"]
mod tests;
