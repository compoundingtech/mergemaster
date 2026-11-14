//! Owned integer seconds; wide decimal payloads never narrow through serde.
#[derive(Debug, Clone)]
pub struct Seconds(Repr);
#[derive(Debug, Clone)]
enum Repr {
    Small(u64),
    Wide(String),
}
impl From<u64> for Seconds {
    fn from(seconds: u64) -> Self {
        Self(Repr::Small(seconds))
    }
}
impl Seconds {
    pub fn positive(decimal: &str) -> Option<Self> {
        if !decimal
            .as_bytes()
            .first()
            .is_some_and(|b| (b'1'..=b'9').contains(b))
            || !decimal.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        Some(
            decimal
                .parse::<u64>()
                .map_or_else(|_| Self(Repr::Wide(decimal.to_owned())), Self::from),
        )
    }
    pub fn bounded(&self) -> Option<u64> {
        match &self.0 {
            Repr::Small(value) => Some(*value),
            Repr::Wide(_) => None,
        }
    }
    pub(crate) fn write_json(&self, out: &mut impl std::fmt::Write) -> std::fmt::Result {
        match &self.0 {
            Repr::Small(value) => write!(out, "{value}"),
            Repr::Wide(decimal) => out.write_str(decimal),
        }
    }
}
impl serde::Serialize for Seconds {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Repr::Small(value) => serializer.serialize_u64(value),
            Repr::Wide(_) => Err(serde::ser::Error::custom(
                "wide integer seconds require the lossless JSON writer",
            )),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seconds_payload_retains_decimal_and_refuses_wide_serde() {
        for decimal in [
            "1",
            "18446744073709551615",
            "18446744073709551616",
            "99999999999999999999999999999999999999999999999999",
        ] {
            let value = Seconds::positive(decimal).unwrap();
            let mut out = String::new();
            crate::evidence::legacy_output::write(&mut out, |writer| writer.policy_seconds(&value))
                .unwrap();
            assert_eq!(out, decimal);
            assert_eq!(
                serde_json::to_string(&value).is_ok(),
                value.bounded().is_some()
            );
        }
        for invalid in ["", "0", "-1", "01", "1.0", "1e3"] {
            assert!(Seconds::positive(invalid).is_none());
        }
    }
}
