//! Numeric operations used by the Python-compatible runner report.
use super::legacy_verify::statement_document::Node;
use anyhow::{Result, bail};
use std::cmp::Ordering;

fn integer(node: &Node) -> Option<&str> {
    match node {
        Node::Integer(text) => Some(text),
        Node::Bool(false) => Some("0"),
        Node::Bool(true) => Some("1"),
        _ => None,
    }
}

fn parts(text: &str) -> (bool, &str) {
    let negative = text.starts_with('-');
    let digits = text.trim_start_matches(['-', '+']).trim_start_matches('0');
    (negative && !digits.is_empty(), digits)
}

fn integer_compare(a: &str, b: &str) -> Ordering {
    let (an, a) = parts(a);
    let (bn, b) = parts(b);
    if an != bn {
        return bn.cmp(&an);
    }
    let magnitude = a.len().cmp(&b.len()).then_with(|| a.cmp(b));
    if an { magnitude.reverse() } else { magnitude }
}

fn integer_float_compare(integer: &str, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float.is_infinite() {
        return Some(if float.is_sign_positive() {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    // Fixed formatting preserves every digit of the integral binary float;
    // converting the integer to f64 would lose comparison bits above 2**53.
    let truncated = float.trunc();
    let order = integer_compare(integer, &format!("{truncated:.0}"));
    Some(if order == Ordering::Equal {
        if float > truncated {
            Ordering::Less
        } else if float < truncated {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    } else {
        order
    })
}

pub(super) fn compare(a: &Node, b: &Node) -> Option<Ordering> {
    match (integer(a), integer(b), a, b) {
        (Some(a), Some(b), _, _) => Some(integer_compare(a, b)),
        (Some(a), _, _, Node::Float(b)) => integer_float_compare(a, *b),
        (_, Some(b), Node::Float(a), _) => integer_float_compare(b, *a).map(Ordering::reverse),
        (_, _, Node::Float(a), Node::Float(b)) => a.partial_cmp(b),
        _ => None,
    }
}

// Little-endian base-2**32 magnitude. Only the integer prefix needs unbounded
// arithmetic; no decimal rendering or float narrowing occurs while summing it.
#[derive(Default)]
struct Magnitude(Vec<u32>);

impl Magnitude {
    fn from_u64(value: u64) -> Self {
        let mut words = Vec::new();
        if value != 0 {
            words.push(value as u32);
            if value >> 32 != 0 {
                words.push((value >> 32) as u32);
            }
        }
        Self(words)
    }

    fn decimal(digits: &str) -> Self {
        let mut value = Self::default();
        for digit in digits.bytes() {
            let mut carry = u64::from(digit - b'0');
            for word in &mut value.0 {
                let next = u64::from(*word) * 10 + carry;
                *word = next as u32;
                carry = next >> 32;
            }
            if carry != 0 {
                value.0.push(carry as u32);
            }
        }
        value
    }

    fn bits(&self) -> usize {
        self.0.last().map_or(0, |last| {
            (self.0.len() - 1) * 32 + (32 - last.leading_zeros()) as usize
        })
    }

    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }

    fn add(&mut self, other: &Self) {
        self.0.resize(self.0.len().max(other.0.len()), 0);
        let mut carry = 0_u64;
        for (index, word) in self.0.iter_mut().enumerate() {
            let sum =
                u64::from(*word) + u64::from(other.0.get(index).copied().unwrap_or(0)) + carry;
            *word = sum as u32;
            carry = sum >> 32;
        }
        if carry != 0 {
            self.0.push(carry as u32);
        }
    }

    // Caller has established self >= other.
    fn subtract(&mut self, other: &Self) {
        let mut borrow = 0_u64;
        for (index, word) in self.0.iter_mut().enumerate() {
            let sub = u64::from(other.0.get(index).copied().unwrap_or(0)) + borrow;
            let original = u64::from(*word);
            *word = original.wrapping_sub(sub) as u32;
            borrow = u64::from(original < sub);
        }
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    fn shifted(&self, bits: usize) -> Self {
        if self.0.is_empty() {
            return Self::default();
        }
        let mut words = Vec::with_capacity(self.0.len() + bits / 32 + 1);
        words.resize(bits / 32, 0);
        let mut carry = 0_u64;
        for word in &self.0 {
            let next = (u64::from(*word) << (bits % 32)) | carry;
            words.push(next as u32);
            carry = next >> 32;
        }
        if carry != 0 {
            words.push(carry as u32);
        }
        Self(words)
    }

    /// Correctly rounded integer true division, including overflow and subnormals.
    fn divide_float(&self, divisor: u64, negative: bool) -> Result<f64> {
        if self.0.is_empty() {
            return Ok(if negative { -0.0 } else { 0.0 });
        }
        let denominator = Self::from_u64(divisor);
        let mut exponent = self.bits() as i32 - denominator.bits() as i32;
        let order = if exponent >= 0 {
            self.cmp(&denominator.shifted(exponent as usize))
        } else {
            self.shifted((-exponent) as usize).cmp(&denominator)
        };
        if order == Ordering::Less {
            exponent -= 1;
        }
        if exponent > 1023 {
            bail!("integer division result too large for a float");
        }
        let quantum = (exponent - 52).max(-1074);
        let mut remainder = self.shifted((-quantum).max(0) as usize);
        let denominator = denominator.shifted(quantum.max(0) as usize);
        let mut quotient = 0_u64;
        for bit in (0..=53).rev() {
            let shifted = denominator.shifted(bit);
            if remainder.cmp(&shifted) != Ordering::Less {
                remainder.subtract(&shifted);
                quotient |= 1_u64 << bit;
            }
        }
        let halfway = remainder.shifted(1).cmp(&denominator);
        if halfway == Ordering::Greater || (halfway == Ordering::Equal && quotient & 1 != 0) {
            quotient += 1;
        }
        // The power of two is exact, and the rounded significand fits in 54 bits
        // (the sole 54-bit possibility is the exact value 2**53).
        let value = if quantum == -1074 {
            f64::from_bits(quotient)
        } else {
            (quotient as f64) * 2.0_f64.powi(quantum)
        };
        if !value.is_finite() {
            bail!("integer division result too large for a float");
        }
        Ok(if negative { -value } else { value })
    }
}

#[derive(Default)]
struct IntegerSum {
    negative: bool,
    magnitude: Magnitude,
}

impl IntegerSum {
    fn from_i64(value: i64) -> Self {
        Self {
            negative: value < 0,
            magnitude: Magnitude::from_u64(value.unsigned_abs()),
        }
    }

    fn add(&mut self, text: &str) {
        let (negative, digits) = parts(text);
        let mut magnitude = Magnitude::decimal(digits);
        if self.negative == negative {
            self.magnitude.add(&magnitude);
        } else if self.magnitude.cmp(&magnitude) == Ordering::Less {
            magnitude.subtract(&self.magnitude);
            self.magnitude = magnitude;
            self.negative = negative;
        } else {
            self.magnitude.subtract(&magnitude);
        }
        if self.magnitude.0.is_empty() {
            self.negative = false;
        }
    }

    fn float(&self) -> Result<f64> {
        self.magnitude.divide_float(1, self.negative)
    }
}

pub(super) fn mean<'a>(values: impl Iterator<Item = &'a Node>) -> Result<f64> {
    let mut count = 0_u64;
    let mut prefix = IntegerSum::default();
    let mut fast_integer = Some(0_i64);
    let mut floats: Option<(f64, f64)> = None;
    let mut compensated = false;
    for node in values {
        count += 1;
        if let Some(text) = integer(node) {
            if let Some((hi, lo)) = &mut floats {
                // Decimal-to-binary conversion is correctly rounded, just like
                // PyLong_AsDouble, without constructing another big integer.
                let value: f64 = text.parse()?;
                if !value.is_finite() {
                    bail!("int too large to convert to float");
                }
                // CPython's float loop accepts arbitrary PyLong values, not
                // only machine integers; successful conversion stays compensated.
                add_float(hi, lo, value, compensated);
            } else if let Some(sum) = fast_integer {
                if let Some(next) = text
                    .parse::<i64>()
                    .ok()
                    .and_then(|item| sum.checked_add(item))
                {
                    fast_integer = Some(next);
                } else {
                    prefix = IntegerSum::from_i64(sum);
                    prefix.add(text);
                    fast_integer = None;
                }
            } else {
                prefix.add(text);
            }
        } else if let Node::Float(value) = node {
            if let Some((hi, lo)) = &mut floats {
                add_float(hi, lo, *value, compensated);
            } else {
                // The first float is added by PyNumber_Add before entering the
                // compensated loop. Integer fast-path overflow instead sends
                // the entire remaining sequence through ordinary addition.
                let initial = if let Some(sum) = fast_integer {
                    sum as f64
                } else {
                    prefix.float()?
                };
                floats = Some((initial + value, 0.0));
                compensated = fast_integer.is_some();
            }
        } else {
            bail!("unsupported operand type for sum");
        }
    }
    if count == 0 {
        bail!("division by zero");
    }
    if let Some((hi, lo)) = floats {
        let total = if lo != 0.0 && lo.is_finite() {
            hi + lo
        } else {
            hi
        };
        Ok(total / count as f64)
    } else if let Some(sum) = fast_integer {
        if sum.unsigned_abs() <= 1_u64 << 53 && count <= 1_u64 << 53 {
            Ok(sum as f64 / count as f64)
        } else {
            IntegerSum::from_i64(sum)
                .magnitude
                .divide_float(count, sum < 0)
        }
    } else {
        prefix.magnitude.divide_float(count, prefix.negative)
    }
}

fn add_float(hi: &mut f64, lo: &mut f64, value: f64, compensated: bool) {
    let next = *hi + value;
    if compensated {
        *lo += if hi.abs() >= value.abs() {
            (*hi - next) + value
        } else {
            (value - next) + *hi
        };
    }
    *hi = next;
}

pub(super) fn float_repr(value: f64) -> Result<String> {
    if value.is_nan() {
        return Ok("nan".into());
    }
    if value.is_infinite() {
        return Ok(if value.is_sign_negative() {
            "-inf"
        } else {
            "inf"
        }
        .into());
    }
    super::legacy_request::float_token(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Stdio;

    fn node(token: &str) -> Node {
        match token {
            "True" => Node::Bool(true),
            "False" => Node::Bool(false),
            "nan" => Node::Float(f64::NAN),
            "inf" => Node::Float(f64::INFINITY),
            "-inf" => Node::Float(f64::NEG_INFINITY),
            _ if token.contains(['.', 'e', 'E']) => Node::Float(token.parse().unwrap()),
            _ => Node::Integer(token.into()),
        }
    }

    fn oracle(input: String, program: &str) -> Vec<String> {
        let mut child = crate::pinned_python::command()
            .args(["-c", program])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    const PARSE: &str = "def parse(s):\n if s in ('True','False'): return s=='True'\n return float(s) if any(c in s for c in '.eE') or s in ('nan','inf','-inf') else int(s)\n";

    #[test]
    fn comparisons_match_pinned_python() {
        let mut tokens: Vec<String> = [
            "True",
            "False",
            "0",
            "-0",
            "-0.0",
            "0.0",
            "0.5",
            "-0.5",
            "nan",
            "inf",
            "-inf",
            "5e-324",
            "-5e-324",
            "1.7976931348623157e308",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for power in [0, 31, 53, 63, 100, 1023] {
            let float = 2.0_f64.powi(power);
            tokens.push(format!("{float:e}"));
            let base = format!("{float:.0}");
            tokens.push(base.clone());
            tokens.push(format!("-{base}"));
            if power <= 100 {
                let integer = 1_i128 << power;
                for delta in [-1, 1] {
                    tokens.push((integer + delta).to_string());
                    tokens.push((-integer + delta).to_string());
                }
            }
        }
        tokens.push("9".repeat(4300));
        tokens.push(format!("-{}", "9".repeat(4300)));
        let mut input = String::new();
        for a in &tokens {
            for b in &tokens {
                input.push_str(&format!("{a} {b}\n"));
            }
        }
        let program = format!(
            "{PARSE}import sys\nfor line in sys.stdin:\n a,b=map(parse,line.split()); print('None' if a!=a or b!=b else ('Less' if a<b else 'Greater' if a>b else 'Equal'))\n"
        );
        let expected = oracle(input, &program);
        let mut index = 0;
        for a in &tokens {
            for b in &tokens {
                assert_eq!(
                    format!("{:?}", compare(&node(a), &node(b)))
                        .replace("Some(", "")
                        .replace(')', ""),
                    expected[index],
                    "{a} versus {b}"
                );
                index += 1;
            }
        }
    }

    #[test]
    fn means_match_pinned_python() {
        let mut cases: Vec<Vec<String>> = [
            vec!["0.1", "0.1", "0.1", "0.3"],
            vec!["1e16", "1.0", "-1e16"],
            vec!["9007199254740993", "-9007199254740992", "0.1", "0.2"],
            vec![
                "9223372036854775807",
                "1",
                "-9223372036854775808",
                "1e16",
                "1.0",
                "-1e16",
            ],
            vec![
                "9223372036854775808",
                "-9223372036854775808",
                "0.1",
                "0.1",
                "0.1",
                "0.3",
            ],
            vec!["9007199254740993", "9007199254740992"],
            vec!["9007199254740995", "9007199254740992"],
            vec!["-9007199254740993", "-9007199254740992"],
            vec!["True", "False", "True"],
            vec!["-0.0"],
            vec!["-0.0", "-0.0"],
            vec!["0", "-0.0"],
            vec!["-5e-324", "-5e-324"],
            vec!["5e-324", "0.0"],
            vec!["inf"],
            vec!["-inf"],
            vec!["nan"],
            vec!["inf", "-inf"],
            vec!["inf", "1.0"],
            vec!["1.0", "-inf"],
            vec!["nan", "1.0"],
            vec!["1e308", "1e308", "-1e308"],
            vec!["1e16", "1", "-1e16", "True"],
            vec![
                "1e16",
                "9223372036854775808",
                "-9223372036854775808",
                "-1e16",
                "0.1",
            ],
            vec![
                "1e16",
                "1",
                "9223372036854775808",
                "-9223372036854775808",
                "-1e16",
                "0.1",
            ],
            vec![
                "0.1",
                "1267650600228229401496703205377",
                "-1267650600228229401496703205376",
                "0.2",
            ],
            vec![
                "0.0",
                "9223372036854775809",
                "-9223372036854775808",
                "1e16",
                "1.0",
                "-1e16",
            ],
        ]
        .into_iter()
        .map(|items| items.into_iter().map(str::to_owned).collect())
        .collect();
        let huge = "9".repeat(4300);
        cases.push(vec![huge.clone(), format!("-{huge}"), "3".into()]);
        cases.push(vec![
            huge.clone(),
            format!("-{huge}"),
            "0.1".into(),
            "0.2".into(),
        ]);
        cases.push(vec![huge.clone(), "0.0".into(), format!("-{huge}")]);
        cases.push(vec!["0.0".into(), huge.clone()]);
        cases.push(vec![huge]);
        for power in [53, 63, 100, 500, 1023] {
            let base = format!("{:.0}", 2.0_f64.powi(power));
            for length in [1, 2, 3, 7, 31] {
                let mut values = vec![base.clone(); length];
                values.push("1".into());
                cases.push(values);
            }
        }
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut values = vec![
                (state as i64).to_string(),
                (state.rotate_left(19) as i64).to_string(),
            ];
            values.resize(2 + (state % 17) as usize, "0".into());
            cases.push(values.clone());
            values.extend(["1e16".into(), "0.1".into(), "1.0".into(), "-1e16".into()]);
            cases.push(values);
        }
        let input = cases
            .iter()
            .map(|case| format!("{}\n", case.join(" ")))
            .collect();
        let program = format!(
            "{PARSE}import sys,struct\nfor line in sys.stdin:\n try:\n  values=list(map(parse,line.split())); value=sum(values)/len(values); print('nan' if value!=value else struct.pack('>d',value).hex())\n except OverflowError: print('overflow')\n"
        );
        let expected = oracle(input, &program);
        for (case, expected) in cases.iter().zip(expected) {
            let nodes: Vec<Node> = case.iter().map(|token| node(token)).collect();
            let actual = match mean(nodes.iter()) {
                Ok(value) if value.is_nan() => "nan".into(),
                Ok(value) => format!("{:016x}", value.to_bits()),
                Err(_) => "overflow".into(),
            };
            assert_eq!(actual, expected, "{case:?}");
        }
    }

    #[test]
    fn float_representations_match_pinned_python() {
        let mut bits = vec![
            0,
            1,
            1_u64 << 63,
            (1_u64 << 63) | 1,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            f64::NAN.to_bits(),
        ];
        for exponent in [0, 1, 100, 1022, 1023, 1024, 2046] {
            for delta in [0, 1, (1_u64 << 52) - 1] {
                bits.push((exponent << 52) | delta);
                bits.push((1_u64 << 63) | (exponent << 52) | delta);
            }
        }
        for value in [0.1_f64, 0.15, 1e-5, 1e-4, 1e15, 1e16, 1.2345678901234567] {
            bits.push(value.to_bits());
        }
        let input = bits.iter().map(|bits| format!("{bits}\n")).collect();
        let expected = oracle(
            input,
            "import sys,struct\nfor line in sys.stdin:\n print(repr(struct.unpack('>d',struct.pack('>Q',int(line)))[0]))\n",
        );
        for (bits, expected) in bits.into_iter().zip(expected) {
            assert_eq!(float_repr(f64::from_bits(bits)).unwrap(), expected);
        }
    }
}
