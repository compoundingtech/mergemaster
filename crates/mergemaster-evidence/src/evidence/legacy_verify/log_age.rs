//! Python timedelta.total_seconds(): exact integer true division, rounded once.
/// The difference of two i64 microsecond stamps needs at most 64 unsigned bits.
/// Scaling the exact ratio to a 53-bit significand needs at most 73 bits, so all
/// quotient/remainder arithmetic fits u128 without truncation or overflow.
pub fn total_seconds(now: i64, then: i64) -> f64 {
    let delta = i128::from(now) - i128::from(then);
    let n = delta.unsigned_abs();
    if n == 0 {
        return 0.0;
    }
    let mut exponent = n.ilog2() as i32 - 19;
    let below = if exponent >= 0 {
        n < 1_000_000_u128 << exponent
    } else {
        n << -exponent < 1_000_000
    };
    if below {
        exponent -= 1;
    }
    let scaled = n << (52 - exponent);
    let (mut significand, remainder) = (scaled / 1_000_000, scaled % 1_000_000);
    if remainder > 500_000 || (remainder == 500_000 && significand & 1 != 0) {
        significand += 1;
    }
    // Both conversions are exact: significand <=2^53, and scale is a power of 2.
    let seconds = significand as f64 * 2_f64.powi(exponent - 52);
    if delta < 0 { -seconds } else { seconds }
}

#[cfg(test)]
#[path = "log_age_tests.rs"]
mod tests;
