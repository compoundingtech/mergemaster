//! Strict UTF-8 and POSIX operations used by rust-test-keys.
/// Python str.decode() error text, not Rust's UTF-8 diagnostic.
pub fn utf8(data: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(data).map_err(|e| {
        let start = e.valid_up_to();
        let len = e.error_len().unwrap_or(data.len() - start);
        let byte = data.get(start).copied().unwrap_or_default();
        let reason = if e.error_len().is_none() {
            "unexpected end of data"
        } else if !(0xc2..=0xf4).contains(&byte) {
            "invalid start byte"
        } else {
            "invalid continuation byte"
        };
        let location = if len == 1 {
            format!("byte 0x{byte:02x} in position {start}")
        } else {
            format!("bytes in position {start}-{}", start + len - 1)
        };
        format!("'utf-8' codec can't decode {location}: {reason}")
    })
}
/// POSIX normpath, including its special exactly-two-leading-slashes rule.
pub fn normpath(path: &str) -> String {
    let leading = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            ".." if !leading.is_empty() => {}
            _ => parts.push(part),
        }
    }
    let out = format!("{leading}{}", parts.join("/"));
    if out.is_empty() { ".".into() } else { out }
}
pub fn joined(directory: &str, path: &str) -> String {
    if path.starts_with('/') {
        normpath(path)
    } else if directory.is_empty() || directory.ends_with('/') {
        normpath(&format!("{directory}{path}"))
    } else {
        normpath(&format!("{directory}/{path}"))
    }
}
#[cfg(test)]
#[path = "crate_inputs_text_tests.rs"]
mod tests;
