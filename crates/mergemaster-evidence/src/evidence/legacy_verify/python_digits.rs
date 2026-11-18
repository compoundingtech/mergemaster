//! Python 3.14.7 / Unicode 16.0.0 digit properties for legacy integer conversion.
//! Tables are committed runtime inputs, not generated during Rust builds.
include!("python_digits.generated.rs");

/// Numeric_Type=Decimal value, distinct from Python's broader str.isdigit set.
pub fn decimal(point: u32) -> Option<u8> {
    let index = DECIMAL_ZEROS.partition_point(|zero| *zero <= point);
    let zero = *DECIMAL_ZEROS.get(index.checked_sub(1)?)?;
    u8::try_from(point - zero).ok().filter(|value| *value < 10)
}
/// Numeric_Type=Digit|Decimal, including superscripts that int() cannot parse.
pub fn is_digit(point: u32) -> bool {
    if decimal(point).is_some() {
        return true;
    }
    let index = DIGIT_ONLY.partition_point(|(_, end)| *end < point);
    DIGIT_ONLY
        .get(index)
        .is_some_and(|(start, _)| *start <= point)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_codepoint_matches_pinned_python_and_generated_assets_are_fresh() {
        let generator = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/evidence/legacy_verify/gen_python_digits.py");
        let checked = crate::pinned_python::command()
            .arg(generator)
            .arg("--check")
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
        let oracle = crate::pinned_python::command().args([
            "-c", "import sys,unicodedata as u; assert sys.version_info[:3]==(3,14,7) and u.unidata_version=='16.0.0'; sys.stdout.buffer.write(bytes(u.decimal(chr(p),10 if chr(p).isdigit() else 11) for p in range(0x110000)))",
        ]).output().unwrap();
        assert!(
            oracle.status.success(),
            "{}",
            String::from_utf8_lossy(&oracle.stderr)
        );
        assert_eq!(oracle.stdout.len(), 0x110000);
        for (point, expected) in (0..0x110000).zip(oracle.stdout) {
            assert_eq!(
                decimal(point),
                (expected < 10).then_some(expected),
                "U+{point:04X}"
            );
            assert_eq!(is_digit(point), expected <= 10, "U+{point:04X}");
        }
        for point in [0x110000, u32::MAX] {
            assert_eq!(decimal(point), None);
            assert!(!is_digit(point));
        }
    }
}
