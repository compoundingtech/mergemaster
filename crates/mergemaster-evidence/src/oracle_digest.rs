//! Test-only decoding of reviewable input recipes and typed JSON value identities.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub(crate) fn rows(data: &[u8]) -> Value {
    let mut document: Value = serde_json::from_slice(data).unwrap();
    assert_eq!(document["version"], 1);
    document["rows"].take()
}

#[track_caller]
pub(crate) fn bytes(recipe: &Value) -> Vec<u8> {
    let size = usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap();
    let mut output = Vec::with_capacity(size);
    for part in recipe["parts"].as_array().unwrap() {
        let text = part[0].as_str().unwrap();
        let repeats = usize::try_from(part[1].as_u64().unwrap()).unwrap();
        assert!(repeats > 0 && text.len().is_multiple_of(2));
        let start = output.len();
        let end = start.checked_add(text.len() / 2).unwrap();
        assert!(end <= size);
        output.resize(end, 0);
        hex::decode_to_slice(text, &mut output[start..end]).unwrap();
        for _ in 1..repeats {
            assert!(output.len().checked_add(end - start).unwrap() <= size);
            output.extend_from_within(start..end);
        }
    }
    assert_eq!(output.len(), size);
    assert_eq!(
        hex::encode(Sha256::digest(&output)),
        recipe["sha256"].as_str().unwrap()
    );
    output
}

pub(crate) fn json(recipe: &Value) -> Value {
    serde_json::from_slice(&bytes(recipe)).unwrap()
}

#[track_caller]
pub(crate) fn assert_value(actual: &Value, expected: &Value) {
    struct Sink {
        bytes: u64,
        digest: Sha256,
    }
    impl std::fmt::Write for Sink {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.put(text.as_bytes());
            Ok(())
        }
    }
    impl Sink {
        fn put(&mut self, bytes: &[u8]) {
            self.bytes += bytes.len() as u64;
            self.digest.update(bytes);
        }
        fn length(&mut self, size: usize) {
            self.put(&(size as u64).to_be_bytes());
        }
        fn entry(&mut self, key: &str, value: &Value) {
            self.put(b"s");
            self.length(key.len());
            self.put(key.as_bytes());
            self.value(value);
        }
        fn value(&mut self, value: &Value) {
            match value {
                Value::Null => self.put(b"n"),
                Value::Bool(value) => self.put(if *value { b"t" } else { b"f" }),
                Value::Number(value) => {
                    if value.is_i64() || value.is_u64() {
                        self.put(b"i");
                        write!(self, "{value}").unwrap();
                        self.put(b";");
                    } else {
                        let value = value.as_f64().unwrap();
                        self.put(b"d");
                        self.put(&(if value == 0.0 { 0.0 } else { value }).to_be_bytes());
                    }
                }
                Value::String(value) => {
                    self.put(b"s");
                    self.length(value.len());
                    self.put(value.as_bytes());
                }
                Value::Array(values) => {
                    self.put(b"a");
                    self.length(values.len());
                    for value in values {
                        self.value(value);
                    }
                }
                Value::Object(values) => {
                    self.put(b"o");
                    self.length(values.len());
                    if values.keys().is_sorted() {
                        for (key, value) in values {
                            self.entry(key, value);
                        }
                    } else {
                        let mut pairs: Vec<_> = values.iter().collect();
                        pairs.sort_unstable_by(|a, b| a.0.cmp(b.0));
                        for (key, value) in pairs {
                            self.entry(key, value);
                        }
                    }
                }
            }
        }
    }
    assert_eq!(expected["encoding"], "json-value-v1");
    let mut sink = Sink {
        bytes: 0,
        digest: Sha256::new(),
    };
    sink.value(actual);
    assert_eq!(
        sink.bytes,
        expected["bytes"].as_u64().unwrap(),
        "typed JSON byte count"
    );
    assert_eq!(
        hex::encode(sink.digest.finalize()),
        expected["sha256"].as_str().unwrap(),
        "typed JSON SHA-256"
    );
}
