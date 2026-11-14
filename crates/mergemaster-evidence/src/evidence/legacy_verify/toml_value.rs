//! Owned TOML values: integer source is lossless and never converted through f64.
use indexmap::IndexMap;
pub type Table = IndexMap<String, Value>;
#[derive(Debug)]
pub enum Value {
    String(String),
    Bool(bool),
    /// Accepted integer token, including its radix and underscores.
    Integer(String),
    Float(f64),
    Date(Date),
    Time(Time),
    DateTime {
        date: Date,
        time: Time,
        offset_minutes: Option<i16>,
    },
    Array(Vec<Value>),
    Table(Table),
}
impl Value {
    fn drain_children(&mut self, pending: &mut Vec<Value>) {
        match self {
            Self::Array(values) => pending.append(values),
            Self::Table(values) => pending.extend(values.drain(..).map(|(_, value)| value)),
            _ => {}
        }
    }
}
impl Drop for Value {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        self.drain_children(&mut pending);
        while let Some(mut value) = pending.pop() {
            value.drain_children(&mut pending);
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub microsecond: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deep_owned_container_drop_does_not_recurse() {
        let mut value = Value::Integer("0".into());
        for depth in 0..100_000 {
            value = if depth % 2 == 0 {
                Value::Array(vec![value])
            } else {
                Value::Table(Table::from([("x".into(), value)]))
            };
        }
        drop(value);
    }
}
