//! Python json.loads byte transport, before JSON parsing or statement validation.
/// Python strings may contain lone surrogates, so retain code points, not Rust chars.
/// Matches json.detect_encoding followed by decoding with errors="surrogatepass".
pub fn decode_json_bytes(bytes: &[u8]) -> Option<Vec<u32>> {
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
    if !data.len().is_multiple_of(width) {
        return None;
    }
    let mut points = Vec::with_capacity(data.len() / width);
    let mut i = 0;
    while i < data.len() {
        let mut point = u32::from(data[i]);
        if width == 1 {
            let (length, minimum) = match data[i] {
                0..=0x7f => (1, 0),
                0xc2..=0xdf => {
                    point &= 0x1f;
                    (2, 0x80)
                }
                0xe0..=0xef => {
                    point &= 0x0f;
                    (3, 0x800)
                }
                0xf0..=0xf4 => {
                    point &= 7;
                    (4, 0x10000)
                }
                _ => return None,
            };
            for &byte in data.get(i + 1..i + length)? {
                if byte & 0xc0 != 0x80 {
                    return None;
                }
                point = (point << 6) | u32::from(byte & 0x3f);
            }
            if !(minimum..=0x10ffff).contains(&point) {
                return None;
            }
            i += length;
        } else {
            point = 0;
            for (j, &byte) in data[i..i + width].iter().enumerate() {
                point |= u32::from(byte) << (8 * if little { j } else { width - j - 1 });
            }
            i += width;
            if width == 2 && (0xd800..=0xdbff).contains(&point) && i < data.len() {
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
                return None;
            }
        }
        points.push(point);
    }
    Some(points)
}
#[cfg(test)]
#[path = "statement_bytes_tests.rs"]
mod tests;
