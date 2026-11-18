//! Legacy policy evaluation, separate from native gate authorization.
pub mod argparse_diagnostic;
pub mod argparse_help;
pub mod argparse_int;
pub mod argparse_options;
pub mod argparse_parse;
pub mod argparse_usage;
pub mod base_input_values;
mod binding_path;
pub mod candidates;
pub mod cli_adapter;
pub mod cli_config;
pub mod cli_lane_git;
pub mod cli_lanes;
pub mod cli_validation;
pub mod collection;
pub mod configured;
pub mod crate_bindings;
pub mod crate_closure;
pub mod crate_input_document;
pub mod crate_inputs;
pub mod crate_inputs_text;
pub mod crate_key_argument;
pub mod crate_keys;
pub mod crate_layout;
pub mod crate_manifest_ops;
pub mod crate_paths;
pub mod crate_sources;
pub mod discovery;
pub mod events;
pub mod facts;
pub mod failure_json;
pub mod inputs;
pub mod json_bytes;
pub mod judgment;
pub mod lane_entry;
pub mod lane_git;
pub mod lanes;
pub mod log_age;
pub mod log_lines;
pub mod log_transport;
pub mod log_view;
mod manifest_capture;
pub mod member_digest;
pub mod member_project;
pub mod members;
pub mod members_log_view;
pub mod ordering;
pub mod paths_project;
pub mod policy_loader;
pub mod prefix;
pub mod projection;
pub mod projection_capture;
pub mod projection_oid;
pub mod projection_process_error;
pub mod python_digits;
pub mod python_repr;
pub mod raw_batch;
pub mod records;
pub mod require_all;
mod require_all_json;
pub mod result;
mod result_json;
pub mod routing;
pub mod run_inputs;
pub mod selection;
pub mod selection_json;
pub mod signature;
pub mod source_io;
pub mod source_resource;
pub mod stale;
pub mod statement;
pub mod statement_bytes;
pub mod statement_document;
pub mod statement_tokens;
pub mod terminal_sink;
pub mod toml;
pub mod trust;
pub mod utf8_stream;
pub(crate) mod value_inputs;
pub mod workflow;
pub mod zero_test_crates;
use super::legacy_policy::{ErrorOrigin, kind_rules::KindRule, normalized_text::NormalizedText};
use serde::Serialize;
use std::collections::BTreeMap;
pub use value_inputs::{InputMap, ValidatedInputs};
use value_inputs::{InputSource, TextRef};

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Failure {
    pub reason: &'static str,
    pub detail: NormalizedText,
    pub attempts: Option<usize>,
    /// Explicit Python handler provenance; exceptions abort aggregates globally.
    #[serde(skip)]
    pub origin: ErrorOrigin,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    pub fn exception(class: &'static str, detail: impl Into<NormalizedText>) -> Self {
        Self {
            reason: "error",
            detail: detail.into(),
            attempts: None,
            origin: ErrorOrigin::Exception { class },
        }
    }
}

pub(super) fn invalid_statement() -> super::legacy_policy::PolicyError {
    super::legacy_policy::PolicyError {
        resource: None,
        reason: "error",
        origin: ErrorOrigin::Failure,
        detail: "invalid validated statement".into(),
    }
}
pub(super) fn invalid_statement_failure() -> Failure {
    let error = invalid_statement();
    Failure {
        reason: error.reason,
        origin: error.origin,
        detail: error.detail,
        attempts: None,
    }
}

pub fn value_checks(
    rule: &KindRule,
    inputs: &BTreeMap<String, String>,
    run: &BTreeMap<String, String>,
    attempts: usize,
) -> Result<(), Failure> {
    value_checks_source(rule, InputSource::Native(inputs), run, attempts)
}
/// Apply value guards to a validated statement's input object without narrowing strings.
pub fn value_checks_document(
    rule: &KindRule,
    inputs: ValidatedInputs<'_>,
    run: &BTreeMap<String, String>,
    attempts: usize,
) -> Result<(), Failure> {
    value_checks_source(rule, InputSource::Document(inputs), run, attempts)
}
fn value_checks_source(
    rule: &KindRule,
    inputs: InputSource<'_>,
    run: &dyn InputMap,
    attempts: usize,
) -> Result<(), Failure> {
    let metadata = |reason| Failure {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason,
        detail: "".into(),
        attempts: Some(attempts),
    };
    for (key, order) in &rule.values.input_order {
        let choices = || {
            NormalizedText::concat(order.iter().enumerate().flat_map(|(i, text)| {
                [
                    TextRef::Str(if i == 0 { "" } else { ", " }),
                    text.borrowed(),
                ]
            }))
        };
        let key = key.borrowed();
        let rank = |value: Option<TextRef<'_>>| {
            value.and_then(|value| {
                order
                    .iter()
                    .position(|entry| value.points().eq(entry.borrowed().points()))
            })
        };
        let run = run.get_text(key);
        let note = inputs.get_text(key);
        let run_rank = rank(run).ok_or_else(|| Failure {
            detail: NormalizedText::concat(
                [
                    TextRef::Str("this run did not say its "),
                    key,
                    TextRef::Str(" (one of "),
                    choices().borrowed(),
                    TextRef::Str("), so no record can cover it"),
                ]
                .into_iter(),
            ),
            ..metadata("no_run_input")
        })?;
        let note_rank = rank(note).ok_or_else(|| Failure {
            detail: NormalizedText::concat(
                [
                    TextRef::Str("record input "),
                    key,
                    TextRef::Str(" is "),
                    TextRef::Str(
                        &note.map_or_else(|| "None".into(), |v| python_repr::Repr(v).to_string()),
                    ),
                    TextRef::Str(", not one of "),
                    choices().borrowed(),
                ]
                .into_iter(),
            ),
            ..metadata("wrong_input")
        })?;
        if note_rank > run_rank {
            return Err(Failure {
                detail: NormalizedText::concat(
                    [
                        TextRef::Str("record input "),
                        key,
                        TextRef::Str("="),
                        note.unwrap_or(TextRef::Str("None")),
                        TextRef::Str(" does not cover this run's "),
                        key,
                        TextRef::Str("="),
                        run.unwrap_or(TextRef::Str("None")),
                    ]
                    .into_iter(),
                ),
                ..metadata("wrong_input")
            });
        }
    }
    for (key, _) in &rule.base_inputs {
        let key = key.borrowed();
        let expected = run
            .get_text(key)
            .filter(|value| value.len() != 0)
            .ok_or_else(|| Failure {
                detail: NormalizedText::around(
                    "the accepted base's ",
                    key,
                    " is not known, so no record can cover it",
                ),
                ..metadata("no_run_input")
            })?;
        if !inputs
            .get_text(key)
            .is_some_and(|value| value.points().eq(expected.points()))
        {
            return Err(Failure {
                detail: NormalizedText::concat(
                    [
                        TextRef::Str("record input "),
                        key,
                        TextRef::Str("="),
                        inputs.get_text(key).unwrap_or(TextRef::Str("None")),
                        TextRef::Str(" is not the accepted base's "),
                        key,
                        TextRef::Str("="),
                        expected,
                    ]
                    .into_iter(),
                ),
                ..metadata("wrong_input")
            });
        }
    }
    if let Some(shards) = &rule.values.shard_inputs {
        let count_key = shards.count.borrowed();
        let raw_count = inputs.get_text(count_key);
        let count = raw_count.and_then(shard_count).ok_or_else(|| Failure {
            detail: NormalizedText::concat(
                [
                    TextRef::Str("record input "),
                    count_key,
                    TextRef::Str(" is "),
                    TextRef::Str(
                        &raw_count
                            .map_or_else(|| "None".into(), |v| python_repr::Repr(v).to_string()),
                    ),
                    TextRef::Str(", not a shard count from 1 to 16"),
                ]
                .into_iter(),
            ),
            ..metadata("wrong_input")
        })?;
        let results_key = shards.results.borrowed();
        let complete = inputs
            .get_text(results_key)
            .is_some_and(|value| value.complete_shards(count));
        if !complete {
            use std::fmt::Write;
            let mut expected = String::new();
            for index in 0..count {
                if index != 0 {
                    expected.push(',');
                }
                // Formatting into String is infallible.
                let _ = write!(expected, "{index}=success");
            }
            return Err(Failure {
                detail: NormalizedText::concat(
                    [
                        TextRef::Str("record input "),
                        results_key,
                        TextRef::Str(" must name every one of its "),
                        raw_count.unwrap_or(TextRef::Str("None")),
                        TextRef::Str(" shards as a success ("),
                        TextRef::Str(&expected),
                        TextRef::Str(")"),
                    ]
                    .into_iter(),
                ),
                ..metadata("wrong_input")
            });
        }
        if inputs
            .get_text(TextRef::Str("event_name"))
            .is_some_and(|event| event.equals("pull_request"))
            && let Some(expected) = shards
                .pull_request_count
                .flatten()
                .filter(|expected| *expected != u64::from(count))
        {
            return Err(Failure {
                detail: NormalizedText::concat(
                    [
                        TextRef::Str(&format!(
                            "a pull_request record must have {expected} shard(s), not "
                        )),
                        raw_count.unwrap_or(TextRef::Str("None")),
                    ]
                    .into_iter(),
                ),
                ..metadata("wrong_input")
            });
        }
    }
    Ok(())
}
fn shard_count(value: TextRef<'_>) -> Option<u8> {
    // unicode-shard-count: ordinary refusal, not Python's numeric conversion exceptions.
    if value.len() == 0 || value.len() > 4300 || !value.points().all(|p| (48..=57).contains(&p)) {
        return None;
    }
    value
        .points()
        .try_fold(0_u8, |count, digit| {
            count
                .checked_mul(10)?
                .checked_add(u8::try_from(digit - 48).ok()?)
                .filter(|count| *count <= 16)
        })
        .filter(|count| *count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::legacy_policy::PolicyDocument;
    use serde_json::{Value, json};
    #[test]
    fn value_judgments_and_shards_match_the_oracle() {
        let mut cases: Vec<Value> = serde_json::from_str(r#"[
          [{},{},{}],
          [{"input_order":{"z":["strong","weak"],"a":["strong","weak"]}},{"z":"bad"},{"z":"strong"}],
          [{"input_order":{"a":["strong","weak"],"z":["strong","weak"]}},{"z":"bad"},{"z":"strong"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"strong"},{"x":"weak"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"weak"},{"x":"strong"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"strong"},{"x":"strong"}],
          [{"input_order":{"x":["strong","weak"]}},{"x":"strong"},{"x":"bad"}],
          [{"base_inputs":{"z":"z","a":"a"}},{"z":"bad"},{"z":"expected"}],
          [{"base_inputs":{"a":"a","z":"z"}},{"z":"bad"},{"z":"expected"}],
          [{"base_inputs":{"x":"."}},{"x":"same"},{"x":"same"}],
          [{"base_inputs":{"x":"."}},{"x":"same"},{"x":""}]
        ]"#).unwrap();
        for count in ["1", "01", "0", "17", "", "-1", "1.0", "١", "１", "𝟙", "²"] {
            cases.push(json!([{"shard_inputs":{"count":"n","results":"r"}},{"n":count,"r":"0=success"},{}]));
        }
        for length in [4300, 4301] {
            cases.push(json!([{"shard_inputs":{"count":"n","results":"r"}},
                {"n":format!("{}1","0".repeat(length - 1)),"r":"0=success"},{}]));
        }
        for results in [
            "0=success,1=success",
            "1=success,0=success",
            "0=success",
            "0=success,1=failure",
            "00=success,1=success",
            "0=success,1=success,",
        ] {
            cases.push(
                json!([{"shard_inputs":{"count":"n","results":"r","pull_request_count":2}},
                {"n":"2","r":results,"event_name":"pull_request"},{}]),
            );
        }
        for event in ["pull_request", "merge_group"] {
            cases.push(
                json!([{"shard_inputs":{"count":"n","results":"r","pull_request_count":2}},
                {"n":"1","r":"0=success","event_name":event},{}]),
            );
        }
        let all_shards = (0..16)
            .map(|index| format!("{index}=success"))
            .collect::<Vec<_>>()
            .join(",");
        cases.push(
            json!([{"shard_inputs":{"count":"n","results":"r","pull_request_count":null}},
            {"n":"16","r":all_shards,"event_name":"pull_request"},{}]),
        );
        cases.push(json!([{"shard_inputs":{"count":"n","results":"r"}},{"r":"0=success"},{}]));
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule, inputs, run in json.loads(sys.argv[2]):
    try:
        oracle['value_checks'](rule, inputs, run, 7)
        results.append(dict(reason='satisfied'))
    except oracle['Failure'] as failure:
        results.append(dict(reason=failure.reason, attempts=failure.extra['attempts']))
    except ValueError:
        results.append(dict(reason='ValueError'))
print(json.dumps(results))
"#;
        let output = crate::pinned_python::command()
            .args(["-c", script, &root, &serde_json::to_string(&cases).unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cases.len(), expected.len());
        for (case, expected) in cases.iter().zip(expected) {
            let mut rule = case[0].clone();
            rule["command"] = json!(["true"]);
            let policy = json!({"version":1,"checks":{"check":{"trust_levels":["agent"],"kinds":{"wrapper":rule}}}});
            let rules = PolicyDocument::parse(&policy.to_string(), "check")
                .unwrap()
                .into_rules("owner/repo")
                .unwrap();
            let inputs = serde_json::from_value(case[1].clone()).unwrap();
            let run = serde_json::from_value(case[2].clone()).unwrap();
            let native = value_checks(&rules.kinds[0].1, &inputs, &run, 7);
            let document =
                statement_document::Document::from_bytes(case[1].to_string().as_bytes()).unwrap();
            assert_eq!(
                native,
                value_checks_document(
                    &rules.kinds[0].1,
                    ValidatedInputs::new(&document, document.root()).unwrap(),
                    &run,
                    7
                )
            );
            let actual = native
                .map(|()| json!({"reason":"satisfied"}))
                .unwrap_or_else(|failure| {
                    assert!(!failure.detail.to_string().is_empty());
                    json!({"reason":failure.reason,"attempts":failure.attempts})
                });
            let count = inputs.get("n").map(String::as_str).unwrap_or("");
            if matches!(count, "١" | "１" | "𝟙" | "²") || count.len() > 4300 {
                assert_eq!(actual, json!({"reason":"wrong_input","attempts":7}));
                assert_eq!(
                    expected["reason"],
                    if matches!(count, "²") || count.len() > 4300 {
                        "ValueError"
                    } else {
                        "satisfied"
                    }
                );
            } else {
                assert_eq!(actual, expected, "{case}");
            }
        }
    }
}
