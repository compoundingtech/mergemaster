//! Legacy skip-policy schemas; unrelated to native gate authorization.
pub mod check_names;
pub mod kind_rules;
pub mod level_rules;
pub mod normalized_text;
pub mod seconds;
pub mod value_rules;
pub mod value_source;
use super::legacy_verify::statement_document::{Document, Node};
use super::legacy_verify::{failure_json::TextRef, python_repr::Repr};
use check_names::CheckName;
use normalized_text::NormalizedText;
use serde::Serialize;
use serde_json::Value;
use value_source::Source;

/// Python handler provenance; exception classification is never inferred from text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorOrigin {
    Failure,
    Exception { class: &'static str },
}
#[derive(Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub reason: &'static str,
    pub detail: normalized_text::NormalizedText,
    pub origin: ErrorOrigin,
}
impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}
impl std::error::Error for PolicyError {}

#[derive(Debug)]
pub struct PolicyDocument<'a> {
    check: CheckName<'a>,
    document: Document,
    entry: Option<usize>,
}
impl<'a> PolicyDocument<'a> {
    pub fn parse(text: &str, check: impl Into<CheckName<'a>>) -> Result<Self, PolicyError> {
        let check = check.into();
        let document = policy_document(text)?;
        let entry = Source::root(&document).get("checks").and_then(|checks| {
            checks
                .object()?
                .iter()
                .find(|(name, _)| check.matches(name))
                .map(|(_, id)| *id)
        });
        Ok(Self {
            check,
            document,
            entry,
        })
    }
    /// Unrelated entries are syntax-checked without bounded numeric conversion.
    pub fn into_header(self) -> Result<CheckHeader, PolicyError> {
        CheckHeader::parse(self.source()?, self.check)
    }
    pub fn source(&self) -> Result<Source<'_>, PolicyError> {
        let entry = self.entry.ok_or_else(|| PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "no_policy",
            detail: NormalizedText::around(
                "the skip policy has no entry for check ",
                self.check.text(),
                "",
            ),
        })?;
        Ok(Source::root(&self.document).at(entry))
    }
    /// Validate and normalize every selected kind before evidence evaluation.
    pub fn into_rules(self, repository: &str) -> Result<PolicyRules, PolicyError> {
        let source = self.source()?;
        let header = CheckHeader::parse(source, self.check)?;
        let kinds = match source.get("kinds") {
            Some(kinds) => {
                kind_rules::checked_kinds(kinds, &header.trust_levels, repository, self.check)?
            }
            None => {
                return Err(invalid(NormalizedText::around(
                    "skip policy for ",
                    self.check.text(),
                    " needs kinds and trust_levels, and nothing unknown",
                )));
            }
        };
        Ok(PolicyRules { header, kinds })
    }
}
/// Parse the complete policy before selection; duplicate keys use the last value.
fn policy_document(text: &str) -> Result<Document, PolicyError> {
    let document =
        Document::from_text(text).map_err(|error| match error {
            super::legacy_verify::statement_document::TextError::Syntax(error) => {
                invalid(format!("skip policy is not valid JSON: {error}"))
            }
            super::legacy_verify::statement_document::TextError::IntegerLimit { digits } => {
                invalid(format!("skip policy is not valid JSON: Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"))
            }
        })?;
    let root = Source::root(&document);
    let version_one = root.get("version").is_some_and(|value| match value.node() {
        Node::Bool(true) => true,
        Node::Integer(decimal) => decimal == "1",
        Node::Float(value) => *value == 1.0,
        _ => false,
    });
    if root.object().is_none_or(|entries| entries.len() != 2)
        || !version_one
        || root
            .get("checks")
            .is_none_or(|checks| checks.object().is_none())
    {
        return Err(invalid(
            "skip policy must be {\"version\": 1, \"checks\": {...}}",
        ));
    }
    Ok(document)
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RequireMode {
    Off,
    Shadow,
    Reject,
}

#[derive(Debug, Serialize)]
pub struct CheckHeader {
    pub trust_levels: Vec<NormalizedText>,
    pub max_age_s: Option<seconds::Seconds>,
    pub enforce: bool,
    pub inputs: Option<Vec<NormalizedText>>,
    pub sample_one_in: u64,
    pub require: RequireMode,
    pub events: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct PolicyRules {
    #[serde(flatten)]
    pub header: CheckHeader,
    #[serde(serialize_with = "serialize_kind_pairs")]
    pub kinds: Vec<(String, kind_rules::KindRule)>,
}
impl CheckHeader {
    pub fn parse<'a>(
        source: Source<'_>,
        check: impl Into<CheckName<'a>>,
    ) -> Result<Self, PolicyError> {
        let check = check.into();
        let error = |message: &str| {
            invalid(NormalizedText::concat(
                [
                    TextRef::Str("skip policy for "),
                    check.text(),
                    TextRef::Str(": "),
                    TextRef::Str(message),
                ]
                .into_iter(),
            ))
        };
        let shape = || {
            invalid(NormalizedText::around(
                "skip policy for ",
                check.text(),
                " needs kinds and trust_levels, and nothing unknown",
            ))
        };
        const KEYS: &[&str] = &[
            "kinds",
            "trust_levels",
            "max_age_s",
            "enforce",
            "inputs",
            "sample_one_in",
            "require",
            "events",
        ];
        if source.object().is_none_or(|entries| {
            entries
                .keys()
                .any(|key| !KEYS.iter().any(|k| value_source::key_is(key, k)))
        }) || source.get("kinds").is_none()
            || source.get("trust_levels").is_none()
        {
            return Err(shape());
        }
        let trust_levels = source
            .get("trust_levels")
            .and_then(value_source::names)
            .ok_or_else(|| error("trust_levels must be a nonempty list of names"))?;
        let max_age_s = match source.get("max_age_s") {
            None => None,
            Some(value) if value.is_null() => None,
            Some(value) => Some(
                match value.node() {
                    Node::Integer(decimal) => seconds::Seconds::positive(decimal),
                    _ => None,
                }
                .ok_or_else(|| error("max_age_s must be null or a positive integer"))?,
            ),
        };
        let enforce = source.get("enforce").map_or(Ok(false), |value| {
            value
                .as_bool()
                .ok_or_else(|| error("enforce must be true or false"))
        })?;
        let require = match source.get("require") {
            None => RequireMode::Off,
            Some(value) if value.str_is("off") => RequireMode::Off,
            Some(value) if value.str_is("shadow") => RequireMode::Shadow,
            Some(value) if value.str_is("reject") => RequireMode::Reject,
            Some(_) => return Err(error("require must be one of off, shadow, reject")),
        };
        let inputs = match source.get("inputs") {
            None => None,
            Some(value) if value.is_null() => None,
            Some(value) => Some(
                declared_source_paths(
                    value,
                    &[TextRef::Str("skip policy for "), check.text()],
                    true,
                )?
                .into_iter()
                .map(NormalizedText::from)
                .collect(),
            ),
        };
        let sample_one_in = source
            .get("sample_one_in")
            .map_or(Some(1), |value| value.as_u64())
            .filter(|v| (1..=1000).contains(v))
            .ok_or_else(|| error("sample_one_in must be an integer from 1 to 1000"))?;
        if source
            .get("kinds")
            .is_none_or(|kinds| kinds.object().is_none_or(|entries| entries.is_empty()))
        {
            return Err(error("kinds must name at least one kind"));
        }
        let events = match source.get("events") {
            None => None,
            Some(value) if value.is_null() => None,
            Some(value) => Some(
                value_source::names(value)
                    .filter(|events| {
                        events
                            .iter()
                            .all(|event| *event == "pull_request" || *event == "merge_group")
                            && (events.len() == 1 || (events.len() == 2 && events[0] != events[1]))
                    })
                    // Membership is against ASCII literals; keep the String schema.
                    .map(|events| {
                        events
                            .into_iter()
                            .map(|event| {
                                String::from_iter(event.borrowed().points().map(|p| {
                                    char::from_u32(p).unwrap_or(char::REPLACEMENT_CHARACTER)
                                }))
                            })
                            .collect()
                    })
                    .ok_or_else(|| {
                        error("events must be a nonempty list of pull_request, merge_group")
                    })?,
            ),
        };
        Ok(Self {
            trust_levels,
            max_age_s,
            enforce,
            inputs,
            sample_one_in,
            require,
            events,
        })
    }
}
fn invalid(detail: impl Into<normalized_text::NormalizedText>) -> PolicyError {
    PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.into(),
    }
}
fn rule_error(where_: &[TextRef<'_>], message: &str) -> PolicyError {
    invalid(NormalizedText::concat(
        [TextRef::Str("skip policy for ")]
            .into_iter()
            .chain(where_.iter().copied())
            .chain([TextRef::Str(": "), TextRef::Str(message)]),
    ))
}
fn exception(class: &'static str, detail: impl Into<NormalizedText>) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.into(),
        origin: ErrorOrigin::Exception { class },
    }
}

#[derive(Debug, Serialize)]
pub struct CommandInputs {
    pub command: Vec<normalized_text::NormalizedText>,
    pub required_inputs: Vec<normalized_text::NormalizedText>,
    #[serde(serialize_with = "serialize_pairs")]
    pub bind_inputs: Vec<(
        normalized_text::NormalizedText,
        normalized_text::NormalizedText,
    )>,
}
fn serialize_pairs<S: serde::Serializer, T: Serialize>(
    pairs: &[(normalized_text::NormalizedText, T)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(pairs.iter().map(|(key, value)| (key, value)))
}
fn serialize_kind_pairs<S: serde::Serializer>(
    pairs: &[(String, kind_rules::KindRule)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(pairs.iter().map(|(key, value)| (key, value)))
}
/// Borrow command/input fields from the original Document; kind/level key validation is separate.
/// Required-input duplicates/order and placeholders remain unnormalized here.
pub fn checked_command_inputs(
    rule: Source<'_>,
    where_: &[TextRef<'_>],
) -> Result<CommandInputs, PolicyError> {
    command_source(rule, where_)
}
fn command_source(
    rule: value_source::Source<'_>,
    where_: &[TextRef<'_>],
) -> Result<CommandInputs, PolicyError> {
    let error = |message: &str| rule_error(where_, message);
    let command = value_source::names(
        rule.get("command")
            .ok_or_else(|| exception("KeyError", "'command'"))?,
    )
    .ok_or_else(|| error("command must be a nonempty list of strings"))?;
    let malformed = || error("malformed required_inputs or bind_inputs");
    let required_inputs = rule
        .get("required_inputs")
        .map_or_else(|| Some(Vec::new()), source_strings)
        .ok_or_else(malformed)?;
    let bind_inputs = rule
        .get("bind_inputs")
        .map_or_else(|| Some(Vec::new()), source_pairs)
        .ok_or_else(malformed)?;
    Ok(CommandInputs {
        command,
        required_inputs,
        bind_inputs,
    })
}

/// Borrow and validate accepted-base file bindings from the original Document without reading files.
pub fn checked_base_inputs(
    rule: Source<'_>,
    where_: &[TextRef<'_>],
) -> Result<Vec<(normalized_text::NormalizedText, String)>, PolicyError> {
    base_source(rule, where_)
}
fn base_source(
    rule: value_source::Source<'_>,
    where_: &[TextRef<'_>],
) -> Result<Vec<(NormalizedText, String)>, PolicyError> {
    let base = rule
        .get("base_inputs")
        .map_or_else(|| Some(Vec::new()), source_pairs)
        .ok_or_else(|| rule_error(where_, "base_inputs maps an input name to a path"))?;
    for (_, path) in &base {
        let scalar: Option<String> = path.borrowed().points().map(char::from_u32).collect();
        let detail = if path.borrowed().points().nth(300).is_some() {
            Some("base_inputs: an input path is not a short string".into())
        } else if scalar
            .as_deref()
            .is_none_or(|path| path != "." && !literal_path(path))
        {
            Some(format!(
                "base_inputs: input path {} must be relative, literal and without . or .. parts",
                Repr(path.borrowed())
            ))
        } else {
            None
        };
        if let Some(detail) = detail {
            return Err(rule_error(where_, &detail));
        }
    }
    Ok(base
        .into_iter()
        .map(|(key, path)| (key, path.to_string()))
        .collect())
}

fn source_strings(value: value_source::Source<'_>) -> Option<Vec<NormalizedText>> {
    value
        .array()?
        .map(|item| {
            item.normalized()
                .filter(|text| text.borrowed().points().next().is_some())
        })
        .collect()
}
fn source_pairs(value: value_source::Source<'_>) -> Option<Vec<(NormalizedText, NormalizedText)>> {
    value
        .entries()?
        .map(|(key, value)| {
            if key.is_empty() {
                return None;
            }
            let text = value
                .normalized()
                .filter(|text| text.borrowed().points().next().is_some())?;
            Some((NormalizedText::from_points(key), text))
        })
        .collect()
}

/// Parse the legacy literal-path list, optionally allowing exclusions/selectors.
/// Results are deduplicated and sorted; `where_` supplies diagnostic context.
pub fn declared_paths(
    value: &Value,
    where_: &[TextRef<'_>],
    selectors: bool,
) -> Result<Vec<String>, PolicyError> {
    declared_path_items(
        value
            .as_array()
            .map(|values| values.iter().map(|v| v.as_str().map(TextRef::Str))),
        where_,
        selectors,
    )
}

fn declared_source_paths(
    value: value_source::Source<'_>,
    where_: &[TextRef<'_>],
    selectors: bool,
) -> Result<Vec<String>, PolicyError> {
    declared_path_items(
        value
            .array()
            .map(|values| values.map(|value| value.string_points().map(TextRef::Points))),
        where_,
        selectors,
    )
}

pub(super) fn declared_path_items<'a>(
    values: Option<impl ExactSizeIterator<Item = Option<TextRef<'a>>>>,
    where_: &[TextRef<'_>],
    selectors: bool,
) -> Result<Vec<String>, PolicyError> {
    let error = |message: String| PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: NormalizedText::concat(
            where_
                .iter()
                .copied()
                .chain([TextRef::Str(": "), TextRef::Str(&message)]),
        ),
    };
    let values = values
        .filter(|v| v.len() > 0 && v.len() <= 300)
        .ok_or_else(|| error("inputs must be a nonempty list of at most 300 paths".into()))?;
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let original = value
            .filter(|text| text.points().nth(300).is_none())
            .ok_or_else(|| error("an input path is not a short string".into()))?;
        let item = match original {
            TextRef::Str(text) => std::borrow::Cow::Borrowed(text),
            TextRef::Points(points) => std::borrow::Cow::Owned(
                points
                    .iter()
                    .map(|p| char::from_u32(*p).unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect::<String>(),
            ),
        };
        // Literal path/selector syntax is ASCII-only. Non-scalars cannot pass;
        // preserve the original points, not this validation view, in diagnostics.
        if selectors && item.starts_with('!') {
            if !literal_path(&item[1..]) {
                return Err(error(format!(
                    "excluded path {} must be relative, literal and without . or .. parts",
                    Repr(original)
                )));
            }
        } else if selectors && let Some((path, selector)) = item.split_once("::") {
            let selector_valid = selector.split('.').all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            });
            let workflow = path.ends_with(".yml") || path.ends_with(".yaml");
            if !literal_path(path) || !selector_valid {
                return Err(error(format!(
                    "input {} must be PATH::jobs.ID (a workflow) or PATH::KEY.KEY (a JSON file)",
                    Repr(original)
                )));
            }
            if workflow != selector.starts_with("jobs.") || !(workflow || path.ends_with(".json")) {
                return Err(error(format!(
                    "input {}: a .yml selects jobs.ID, a .json selects KEY.KEY",
                    Repr(original)
                )));
            }
        } else if item != "." && !literal_path(&item) {
            return Err(error(format!(
                "input path {} must be relative, literal and without . or .. parts",
                Repr(original)
            )));
        }
        paths.push(item);
    }
    paths.sort_unstable();
    paths.dedup();
    for item in &paths {
        if let Some(excluded) = item.strip_prefix('!')
            && !paths.iter().any(|p| {
                !p.starts_with('!')
                    && !p.contains("::")
                    && (*p == "."
                        || excluded
                            .strip_prefix(p.as_ref())
                            .is_some_and(|rest| rest.starts_with('/')))
            })
        {
            return Err(error(format!(
                "excluded path {} is not under a declared path, so it leaves nothing out",
                Repr(TextRef::Str(item))
            )));
        }
    }
    Ok(paths
        .into_iter()
        .map(std::borrow::Cow::into_owned)
        .collect())
}

fn literal_path(path: &str) -> bool {
    path.split('/').all(|p| {
        !p.is_empty()
            && p != "."
            && p != ".."
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._@+=,~#-".contains(&b))
    })
}

#[cfg(test)]
#[path = "legacy_policy/helper_diagnostics_tests.rs"]
mod helper_diagnostics_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn root_shape_and_version_equality_match_python() {
        let cases = [
            "null",
            "true",
            "1",
            "[]",
            "{}",
            r#"{"version":1,"checks":[]}"#,
            r#"{"version":1,"checks":{},"extra":0}"#,
            r#"{"version":true,"checks":{}}"#,
            r#"{"version":1.0,"checks":{}}"#,
            r#"{"version":1.00000000000000000000001,"checks":{}}"#,
            r#"{"version":1e0,"checks":{}}"#,
            r#"{"version":false,"checks":{}}"#,
            r#"{"version":"1","checks":{}}"#,
            r#"{"version":1e1000,"checks":{}}"#,
            r#"{"version":18446744073709551616,"checks":{}}"#,
            r#"{"version":0,"version":1,"checks":{}}"#,
            r#"{"version":1,"checks":false,"checks":{}}"#,
            r#"{"version":1,"checks":{},"\ud800":0}"#,
        ];
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); out=[]
for text in json.loads(sys.argv[2]):
 try: v['policy_rules'](text,'unit','org/repo'); raise AssertionError('missing check')
 except v['Failure'] as error: out.append(dict(reason=error.reason,detail=error.detail))
print(json.dumps(out))
"#,
                &std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle"),
                &serde_json::to_string(&cases).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cases.len(), expected.len());
        for (text, expected) in cases.iter().zip(expected) {
            let error = PolicyDocument::parse(text, "unit")
                .and_then(PolicyDocument::into_header)
                .unwrap_err();
            assert_eq!(
                json!({"reason":error.reason,"detail":error.detail}),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn policy_header_diagnostics_match_pinned_handlers_losslessly() {
        use crate::evidence::{legacy_output, legacy_verify::failure_json::WireError};
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
        let output = std::process::Command::new("python3").args(["-c", r#"
import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
handler=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id=='Failure')
single=compile(ast.Expression(handler.body[1].value.args[0]),'<single>','eval')
global_=compile(ast.Expression(handler.body[0].body[0].value.args[0]),'<global>','eval')
cases=[]
for name in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 base=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'])))
 entries=[None,{},dict(kinds=base['kinds']),dict(trust_levels=['agent']),dict(base,unknown=True)]
 for field,values in [('trust_levels',[[],['']]),('max_age_s',[0,-1,True,0.5,'x']),('enforce',[1]),('require',['bad']),('inputs',[[]]),('sample_one_in',[0,True]),('kinds',[{}]),('events',[[],['bad']])]:
  entries.extend(dict(base,**{field:value}) for value in values)
 for present,entry in [(False,None)]+[(True,entry) for entry in entries]+[(True,dict(base,max_age_s=2**64))]:
  text=json.dumps(dict(version=1,checks={name:entry} if present else {}))
  try: v['policy_rules'](text,name,'org/repo')
  except v['Failure'] as failure:
   env=dict(v,failure=failure,args=types.SimpleNamespace(check=name))
   cases.append(dict(text=text,name=list(map(ord,name)),reason=failure.reason,detail=list(map(ord,failure.detail)),single=eval(single,env),global_=eval(global_,env)))
  else:
   assert entry['max_age_s']==2**64
   cases.append(dict(text=text,name=list(map(ord,name)),accepted_seconds=str(entry['max_age_s'])))
print(json.dumps(cases))
"#, &root]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cases.len(), 132);
        let mut accepted = 0;
        for case in cases {
            let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
            let header = PolicyDocument::parse(case["text"].as_str().unwrap(), name.as_slice())
                .unwrap()
                .into_rules("org/repo")
                .map(|rules| rules.header);
            if let Some(expected) = case["accepted_seconds"].as_str() {
                let seconds = header.unwrap().max_age_s.unwrap();
                let mut actual = String::new();
                legacy_output::write(&mut actual, |writer| writer.policy_seconds(&seconds))
                    .unwrap();
                assert_eq!(actual, expected);
                accepted += 1;
                continue;
            }
            let error = header.unwrap_err();
            assert_eq!(error.origin, ErrorOrigin::Failure);
            let detail: Vec<u32> = error.detail.borrowed().points().collect();
            assert_eq!(error.reason, case["reason"]);
            assert_eq!(json!(detail), case["detail"]);
            let view = WireError::from_policy(&error);
            let mut single = String::new();
            legacy_output::write(&mut single, |w| view.write_json(name.as_slice().into(), w))
                .unwrap();
            assert_eq!(single, case["single"]);
            let mut global = String::new();
            legacy_output::write(&mut global, |w| view.write_global(w)).unwrap();
            assert_eq!(global, case["global_"]);
        }
        assert_eq!(accepted, 6);
    }

    #[test]
    fn command_and_base_inputs_match_the_oracle() {
        let base = json!({"command":["test","{repository}","{check}"]});
        let mut cases = vec![base.clone(), json!({})];
        let changes: Value = serde_json::from_str(
            r#"{
          "command": [null, [], false, "test", [""], [1], ["test"," "], [["test"]]],
          "required_inputs": [null, [], false, [""], [1], ["b","a","b"], [" "]],
          "bind_inputs": [null, [], false, {"":"x"}, {"x":""}, {"x":1}, {"z":"q","x":"y"}],
          "base_inputs": [null, [], false, {"":"x"}, {"x":""}, {"x":1}, {"x":"."},
                         {"b":"src/b","a":"src/a"}, {"x":"../src"}, {"x":"src/"},
                         {"x":"!src"}, {"x":"x.json::a"}, {"x":"café"}],
          "unrelated": [true]
        }"#,
        )
        .unwrap();
        for (key, values) in changes.as_object().unwrap() {
            for value in values.as_array().unwrap() {
                let mut rule = base.clone();
                rule[key] = value.clone();
                cases.push(rule);
            }
        }
        for length in [300, 301] {
            let mut rule = base.clone();
            rule["base_inputs"] = json!({"input":"a".repeat(length)});
            cases.push(rule);
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule in json.loads(sys.argv[2]):
    try:
        command, required, bind = oracle['checked_command_inputs'](rule, 'fixture')
        base = oracle['checked_base_inputs'](rule, 'fixture')
        results.append(dict(command=command, required_inputs=required, bind_inputs=bind, base_inputs=base))
    except (oracle['Failure'], KeyError):  # Missing command reaches the CLI's error handler.
        results.append({'reason': 'error'})
print(json.dumps(results))
"#;
        let output = std::process::Command::new("python3")
            .args(["-c", script, &root, &serde_json::to_string(&cases).unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), cases.len());
        for (rule, expected) in cases.iter().zip(expected) {
            let document = Document::from_bytes(rule.to_string().as_bytes()).unwrap();
            let fields = Source::root(&document);
            let actual = checked_command_inputs(fields, &[TextRef::Str("fixture")])
                .and_then(|inputs| {
                    let base = checked_base_inputs(fields, &[TextRef::Str("fixture")])?;
                    let mut value = serde_json::to_value(inputs).unwrap();
                    value["base_inputs"] = Value::Object(
                        base.into_iter()
                            .map(|(key, value)| (key.borrowed().to_string(), Value::String(value)))
                            .collect(),
                    );
                    Ok(value)
                })
                .unwrap_or_else(|error| {
                    assert!(
                        matches!(error.origin, ErrorOrigin::Exception { class: "KeyError" })
                            || error
                                .detail
                                .to_string()
                                .starts_with("skip policy for fixture: ")
                    );
                    json!({"reason":error.reason})
                });
            assert_eq!(actual, expected, "{rule}");
            if let Some(bind) = rule.get("bind_inputs").and_then(Value::as_object)
                && let Some(parsed) = actual["bind_inputs"].as_object()
            {
                assert!(bind.keys().eq(parsed.keys()), "{rule}");
            }
        }
    }

    #[test]
    fn base_input_order_preserves_the_oracle_deciding_reason() {
        let rules = json!([
            {"base_inputs":{"z":"src/z","a":"src/a"}},
            {"base_inputs":{"a":"src/a","z":"src/z"}}
        ]);
        let parsed: Vec<_> = rules
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                let document = Document::from_bytes(rule.to_string().as_bytes()).unwrap();
                let base = checked_base_inputs(Source::root(&document), &[TextRef::Str("fixture")])
                    .unwrap();
                Value::Object(
                    base.into_iter()
                        .map(|(key, value)| (key.borrowed().to_string(), Value::String(value)))
                        .collect(),
                )
            })
            .collect();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
reasons = []
for original, parsed in zip(json.loads(sys.argv[2]), json.loads(sys.argv[3])):
    for base in (original['base_inputs'], parsed):
        try:
            oracle['value_checks']({'base_inputs': base}, {'z': 'wrong'}, {'z': 'expected'}, 1)
        except oracle['Failure'] as failure:
            reasons.append(failure.reason)
print(json.dumps(reasons))
"#;
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                script,
                &root,
                &rules.to_string(),
                &serde_json::to_string(&parsed).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reasons: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            reasons,
            ["wrong_input", "wrong_input", "no_run_input", "no_run_input"]
        );
    }

    #[test]
    fn document_and_check_headers_match_the_oracle() {
        let base = json!({"version":1,"checks":{"unit":{"trust_levels":["agent"],
            "kinds":{"wrapper":{"command":["test","{repository}","{check}"]}}}}});
        let parse = |text: &str| {
            PolicyDocument::parse(text, "unit")?
                .into_rules("fixture/repo")
                .map(|rules| rules.header)
        };
        let mut cases: Vec<String> = [
            "\u{feff}{}",
            "{",
            "[]",
            r#"{"version":1,"checks":{}}"#,
            r#"{"version":2,"checks":{}}"#,
            r#"{"version":1,"checks":[]}"#,
            r#"{"version":1,"checks":{},"extra":true}"#,
            r#"{"checks":{}}"#,
            r#"{"version":false,"checks":{}}"#,
            r#"{"version":1,"checks":{"unit":false}}"#,
            r#"{"version":1,"checks":{"ignored":1e1000}}"#,
            r#"{"version":1,"checks":{"unit":{"kinds":{"wrapper":{"command":1e1000}},"trust_levels":["agent"]}}}"#,
            r#"{"version":1,"checks":{"ignored":{"n":1e1000,"n":2},"ignored":{"n":3,"n":4},"unit":{"kinds":{"wrapper":{"command":["test"]}},"trust_levels":["agent"]}}}"#,
        ]
        .map(str::to_owned)
        .into();
        cases.push(base.to_string());
        cases.push(
            base.to_string()
                .replace(r#"{"unit":"#, r#"{"ignored":1e1000,"unit":"#),
        );
        let changes: Value = serde_json::from_str(r#"{
          "trust_levels": [[], [""], true, [" "], ["agent","agent"]],
          "max_age_s": [null, 1, 18446744073709551615, 0, -1, true, 1.5, 1.0],
          "enforce": [true, false, null, 1],
          "require": ["off", "shadow", "reject", "bad", null],
          "sample_one_in": [1, 1000, 0, 1001, true, 1.0],
          "events": [null, ["pull_request","merge_group"], ["merge_group"], [], ["push"], ["pull_request","pull_request"]],
          "inputs": [null, ["src","!src/tmp","src"], ["x.yml::jobs.test"], ["."], [], ["../x"]],
          "kinds": [{}, []], "unknown": [true]
        }"#).unwrap();
        for (key, values) in changes.as_object().unwrap() {
            for value in values.as_array().unwrap() {
                let mut doc = base.clone();
                doc["checks"]["unit"][key] = value.clone();
                cases.push(doc.to_string());
            }
        }
        for key in ["kinds", "trust_levels"] {
            let mut doc = base.clone();
            doc["checks"]["unit"].as_object_mut().unwrap().remove(key);
            cases.push(doc.to_string());
        }
        let mut other = base.clone();
        other["checks"]["ignored"] = json!(false);
        cases.push(other.to_string());
        cases.push(base.to_string().replace(":1,", ":true,"));
        cases.push(base.to_string().replace(":1,", ":1.0,"));
        cases.extend([
            base.to_string()
                .replace(r#""version":1"#, r#""version":1e1000,"version":1"#),
            base.to_string()
                .replace(r#""checks":"#, r#""checks":false,"checks":"#),
            base.to_string()
                .replace(r#"{"unit":"#, r#"{"unit":1e1000,"unit":"#),
        ]);
        let large = base.to_string().replace(
            "\"trust_levels\"",
            "\"max_age_s\":18446744073709551616,\"trust_levels\"",
        );
        cases.push(large);
        for decimal in [
            "340282366920938463463374607431768211456".to_owned(),
            "9".repeat(400),
        ] {
            cases.push(base.to_string().replace(
                "\"trust_levels\"",
                &format!("\"max_age_s\":{decimal},\"trust_levels\""),
            ));
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for text in json.loads(sys.argv[2]):
    try:
        header = oracle['policy_rules'](text, 'unit', 'fixture/repo')
        del header['kinds']
        if header['max_age_s'] is not None: header['max_age_s']=str(header['max_age_s'])
        results.append(header)
    except oracle['Failure'] as failure:
        results.append({'reason': failure.reason})
print(json.dumps(results))
"#;
        let output = std::process::Command::new("python3")
            .args(["-c", script, &root, &serde_json::to_string(&cases).unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), cases.len());
        for (text, expected) in cases.iter().zip(expected) {
            let actual = parse(text)
                .map(|mut header| {
                    let seconds = header.max_age_s.take().map(|seconds| {
                        let mut text = String::new();
                        crate::evidence::legacy_output::write(&mut text, |writer| {
                            writer.policy_seconds(&seconds)
                        })
                        .unwrap();
                        text
                    });
                    let mut value = serde_json::to_value(header).unwrap();
                    value["max_age_s"] = json!(seconds);
                    value
                })
                .unwrap_or_else(|error| {
                    assert!(!error.detail.to_string().is_empty());
                    assert_eq!(error.origin, ErrorOrigin::Failure);
                    json!({"reason":error.reason})
                });
            assert_eq!(actual, expected, "{text}");
        }
        other["checks"]["unit"]["kinds"] = json!({"raw":false});
        assert_eq!(
            PolicyDocument::parse(&other.to_string(), "unit")
                .unwrap()
                .into_rules("owner/repository")
                .unwrap_err()
                .reason,
            "error"
        );
    }
    #[test]
    fn input_declarations_match_the_immutable_oracle() {
        let mut values: Vec<Value> = serde_json::from_str(
            r#"[
          null, {}, true, "src", [], [null], [3], [""], ["."], ["src","src","a"],
          ["src","!src/tmp"], ["src","!src"], ["src","!src2/tmp"], [".","!tmp"],
          ["!tmp"], ["src","!src/../tmp"], ["src","!src/."], ["!src/","src"],
          ["x.yml::jobs.test"], ["x.yaml::jobs.test-id"], ["x.json::a.b"],
          ["x.json::jobs.test"], ["x.yml::a"], ["x.yml::jobs.test.more"],
          ["x.txt::a"], ["x.json::a..b"], ["x.json::a::b"], ["x.json::"],
          ["x.yml::jobs.test","!x.yml/foo"], ["x.json::a","x.json","!x.json/sub"],
          ["../x"], ["x/./a"], ["/x"], ["x/"], ["x//a"], ["x\\a"], ["x:y"],
          ["a@+=,~#-._/b"], ["café"], ["x\n"], ["x\u0000"], ["**"]
        ]"#,
        )
        .unwrap();
        values.extend([
            json!(vec!["a"; 300]),
            json!(vec!["a"; 301]),
            json!(["a".repeat(300)]),
            json!(["a".repeat(301)]),
            json!(["é".repeat(300)]),
        ]);
        values.extend((0_u8..=127).map(|b| json!([format!("a{}b", char::from(b))])));
        let cases: Vec<_> = [false, true]
            .into_iter()
            .flat_map(|selectors| {
                values
                    .iter()
                    .map(move |value| json!({"value":value,"selectors":selectors}))
            })
            .collect();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for case in json.loads(sys.argv[2]):
    try:
        paths = oracle['declared_paths'](case['value'], 'fixture', case['selectors'])
        results.append({'paths': paths})
    except oracle['Failure'] as failure:
        results.append({'reason': failure.reason})
print(json.dumps(results))
"#,
                &root,
                &serde_json::to_string(&cases).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), cases.len());
        for (case, expected) in cases.iter().zip(expected) {
            let actual = match declared_paths(
                &case["value"],
                &[TextRef::Str("fixture")],
                case["selectors"].as_bool().unwrap(),
            ) {
                Ok(paths) => json!({"paths":paths}),
                Err(error) => {
                    assert!(error.detail.to_string().starts_with("fixture: "));
                    json!({"reason":error.reason})
                }
            };
            assert_eq!(actual, expected, "{case}");
        }
    }
}
