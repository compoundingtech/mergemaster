//! CPython-compatible decimal rounding without an intermediate floating-point scale.

/// Round the exact binary input to decimal with ties-to-even, then back to binary.
/// CPython leaves finite doubles unchanged above 323 decimal places.
pub(crate) fn python_round(value: f64, ndigits: u32) -> f64 {
    if !value.is_finite() || value == 0.0 || ndigits > 323 {
        return value;
    }
    // Fixed-precision formatting rounds the exact binary input, unlike scaling
    // by 10^ndigits first. Parsing then correctly rounds the decimal back to f64.
    // Parsing cannot fail for a finite f64 formatted by the standard library.
    format!("{:.*}", ndigits as usize, value)
        .parse()
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::python_round;
    use std::io::Write;
    use std::process::Stdio;

    #[test]
    fn decimal_ties_and_signed_zero() {
        for (value, digits, expected) in [
            (2.675, 2, 2.67),
            (0.125, 2, 0.12),
            (0.375, 2, 0.38),
            (-0.125, 2, -0.12),
            (0.5, 0, 0.0),
            (-0.5, 0, -0.0),
            (1.5, 0, 2.0),
            (2.5, 0, 2.0),
            (-2.5, 0, -2.0),
            (-0.0, 323, -0.0),
            (f64::MAX, 0, f64::MAX),
            (f64::from_bits(1), 324, f64::from_bits(1)),
            (-f64::from_bits(1), 323, -0.0),
            (f64::MIN_POSITIVE, u32::MAX, f64::MIN_POSITIVE),
        ] {
            assert_eq!(
                python_round(value, digits).to_bits(),
                f64::to_bits(expected),
                "{value:?}, {digits}"
            );
        }
    }

    #[test]
    fn generated_cases_match_pinned_python_bits() {
        let mut cases = Vec::new();
        let precisions = [
            0,
            1,
            2,
            3,
            4,
            6,
            12,
            15,
            16,
            17,
            22,
            23,
            50,
            100,
            200,
            300,
            307,
            308,
            309,
            322,
            323,
            324,
            325,
            u32::MAX,
        ];
        let mut add = |bits: u64| {
            if f64::from_bits(bits).is_finite() {
                for digits in precisions {
                    cases.push((bits, digits));
                    cases.push((bits ^ (1_u64 << 63), digits));
                }
            }
        };
        // Neighbors of every binary exponent boundary include the normal /
        // subnormal transition, huge integral values, and the smallest values.
        for exponent in 0_u64..=2046 {
            let center = exponent << 52;
            for bits in [
                center.saturating_sub(1),
                center,
                center + 1,
                center + ((1_u64 << 52) - 1),
            ] {
                add(bits);
            }
        }
        // Exact decimal ties and immediate binary neighbors, at precisions
        // for which ties are representable (denominators are powers of two).
        for digits in 0..=22 {
            for odd in (1..64).step_by(2) {
                let tie = (odd as f64) / 2.0_f64.powi(digits + 1);
                for bits in [tie.to_bits() - 1, tie.to_bits(), tie.to_bits() + 1] {
                    add(bits);
                }
            }
        }
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            add(state);
        }
        // Sweep every supported precision as well as CPython's early-return
        // boundary using deterministic full-domain bit patterns.
        for digits in 0..=325 {
            for _ in 0..16 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if f64::from_bits(state).is_finite() {
                    cases.push((state, digits));
                }
            }
        }
        let mut input = Vec::new();
        for (bits, digits) in &cases {
            writeln!(input, "{bits} {digits}").unwrap();
        }
        let mut child = crate::pinned_python::command()
            .args(["-c", "import sys,struct\nfor line in sys.stdin:\n b,n=map(int,line.split()); x=struct.unpack('>d',struct.pack('>Q',b))[0]; y=round(x,n); print(struct.unpack('>Q',struct.pack('>d',y))[0])"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        // Write concurrently: the oracle emits more than a pipe buffer of
        // output, so a synchronous write followed by wait can deadlock.
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let expected: Vec<u64> = text.lines().map(|line| line.parse().unwrap()).collect();
        assert_eq!(expected.len(), cases.len());
        for ((bits, digits), expected) in cases.into_iter().zip(expected) {
            assert_eq!(
                python_round(f64::from_bits(bits), digits).to_bits(),
                expected,
                "input bits {bits:#018x}, ndigits {digits}"
            );
        }
    }
}
