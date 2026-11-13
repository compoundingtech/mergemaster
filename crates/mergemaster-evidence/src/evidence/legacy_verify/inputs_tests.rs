use super::*;
use crate::evidence::legacy_policy::PolicyDocument;
use serde_json::{Value, json};
#[test]
fn lossless_input_guards_match_the_pinned_judge_prefix() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned Python oracle");
    let script = r#"
import ast, copy, json, pathlib, runpy, sys
from datetime import datetime, timezone
path = pathlib.Path(sys.argv[1])/'scripts/evidence-verify'; v = runpy.run_path(str(path))
owner = next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='verified')
judge = copy.deepcopy(next(n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='judge'))
stop = next(i for i,n in enumerate(judge.body) if isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and isinstance(n.test.left,ast.Name) and n.test.left.id=='lane')
judge.body = judge.body[:stop] + ast.parse("return dict(reason='satisfied')").body
v.update(command=None,kinds=(),bind=(),max_age=None,runner_prefix=None,trust_levels=None,lane=None,level_lane=None,check='check',attempts=7)
v['failed'] = lambda entry: entry[1]['predicate']['observed']['checks']['check']['exit_code'] != 0
exec(compile(ast.fix_missing_locations(ast.Module(body=[judge],type_ignores=[])),str(path),'exec'),v)
inputs = dict(req='yes',rank='strong',base='same',n='1',r='0=success'); cases = []
def add(label, observed='2026-01-01T00:00:00Z', now='2026-01-01T00:00:05Z', age=10, changes=None, code=0, command=None, rule_changes=None, prepared=None):
    rule = dict(command=['true'],required_inputs=['req'],input_order=dict(rank=['strong','weak']),base_inputs=dict(base='.'),shard_inputs=dict(count='n',results='r'))
    rule.update(rule_changes or {}); entry = dict(trust_levels=['agent'],kinds={('observed' if prepared else 'wrapper'):rule})
    if age is not None: entry['max_age_s'] = age
    policy = json.dumps(dict(version=1,checks=dict(check=entry)))
    values = dict(inputs); values.update(changes or {})
    statement = dict(predicate=dict(tier='full',observed_at=observed,observed=dict(runner='wrapper',inputs=values,checks=dict(check=dict(exit_code=code,command=command or ['true'])))))
    if changes is None: del statement['predicate']['observed']['inputs']
    v.update(rules=v['policy_rules'](policy,'check','owner/repo'),now=v['parse_time'](now),run_inputs=dict(rank='weak',base='same'))
    if prepared:
        v['rules']['kinds']['observed'].update(command=prepared['command'],runner_prefix=prepared['prefix'])
        statement['predicate']['observed']['runner']=prepared['runner']
    try: expected = v['judge'](('record',statement,'agent/alice'))
    except v['Failure'] as failure: expected = dict(reason=failure.reason,attempts=failure.extra['attempts'])
    except OverflowError: expected = dict(reason='error',attempts=7)
    if prepared: assert expected['reason']==prepared['reason'], (label,expected,prepared['reason'])
    delta = v['now'] - datetime(1970,1,1,tzinfo=timezone.utc)
    cases.append(dict(label=ascii(label),policy=policy,raw=json.dumps(statement),expected=expected,intended=None if prepared is None else prepared['reason'],exit_code=str(code),now=(delta.days*86400+delta.seconds)*1000000+delta.microseconds,prepared=None if prepared is None else dict(command=[list(map(ord,x)) for x in prepared['command']],prefix=list(map(ord,prepared['prefix'])))))
for offset in ['00:02:00','00:02:00.0000009','00:02:00.000001','00:02:01']:
    add('future '+offset,observed='2026-01-01T'+offset+'Z',now='2026-01-01T00:00:00Z',age=86400000000000,changes={})
for now in ['2026-01-01T00:00:10Z','2026-01-01T00:00:10.0000009Z','2026-01-01T00:00:10.000001Z','2025-12-31T23:59:59Z']:
    add('age '+now,now=now,changes={})
for age in [None,1,2,86399999999999,86400000000000]: add('duration '+str(age),age=age,changes={})
for observed,now in [('0001-01-01T00:00:00+23:59','0001-01-01T00:00:00Z'),('9999-12-31T23:59:59-23:59','9999-12-31T23:57:59.999999Z'),('1969-12-31T23:59:59.9999999Z','1970-01-01T00:00:00Z'),('2026-W01-1T12+01:30','2025-12-29T10:30:00Z'),('20260101\ud800123456,1234567-00:00:30.25','2026-01-01T12:35:26.373456Z'),('2026-01-01T24:00+00:00','2026-01-02T00:00:00Z')]:
    add('clock '+observed,observed=observed,now=now,age=None,changes={})
for now in ['9999-12-31T23:57:59.999999Z','9999-12-31T23:58:00Z','9999-12-31T23:59:59.999999Z']:
    add('UTC overflow '+now,observed='9999-12-31T23:57:59Z',now=now,changes={})
for value in ['', '\ud800', '\ufffd', '🦀']: add('required '+repr(value),changes=dict(req=value))
for key in ['x'*32,'x'*33,'x'*100,'🦀']: add('required key '+key,changes={key:'\ud800'},rule_changes=dict(required_inputs=[key]))
for value in ['\ud800','\ufffd','bad']: add('rank '+repr(value),changes=dict(rank=value))
for value in ['\ud800','\ufffd','bad']: add('base '+repr(value),changes=dict(base=value))
for code in [1,-1,10**100,-10**1000]: add('code '+str(code),code=code,changes={})
for command in [['true',''],['\ud800'],['\ufffd'],['true','🦀']]: add('command '+repr(command),command=command,changes={})
add('unicode command',command=['true','🦀'],rule_changes=dict(command=['true','🦀']),changes={})
add('required before exit',changes=dict(req=''),code=-10**100)
add('exit before command',changes={},code=1,command=['bad'])
add('command before value',changes=dict(rank='bad'),command=['bad'])
add('overflow before required',age=86400000000000)
add('omitted inputs')
def loose(label, actual=['true'], expected=['true'], age=None, code=0, observed='2026-01-01T00:00:00Z', now='2026-01-01T00:00:05Z'):
    statement=dict(predicate=dict(tier='full',observed_at=observed,observed=dict(runner='wrapper',inputs=dict(req='',rank='bad'),checks=dict(check=dict(exit_code=code,command=actual)))))
    v.update(rules=None,now=v['parse_time'](now),run_inputs={})
    try: verdict=v['judge'](('record',statement,'agent/alice'),command=expected,kinds=('wrapper',),max_age=age)
    except v['Failure'] as e: verdict=dict(reason=e.reason,attempts=e.extra['attempts'])
    except OverflowError: verdict=dict(reason='error',attempts=7)
    delta=v['now']-datetime(1970,1,1,tzinfo=timezone.utc)
    points=None if expected is None else [list(map(ord,arg)) for arg in expected]
    cases.append(dict(label=ascii(label),policy=None,raw=json.dumps(statement),expected=verdict,exit_code=str(code),now=(delta.days*86400+delta.seconds)*1000000+delta.microseconds,command=points,age=None if age is None else str(age)))
commands=[['true'],['\ud800'],['\ufffd'],['🦀'],['true','\0'],['true','']]
for actual in commands:
    for expected in [None,[]]+commands:
        for code in (0,-10**100): loose('loose command '+repr((actual,expected,code)),actual,expected,code=code)
for age in (None,0,1,2,86399999999999,86400000000000,2**64-1,2**64,10**100):
    loose('loose age '+str(age),age=age)
for now in ('2026-01-01T00:00:01Z','2026-01-01T00:00:01.0000009Z','2026-01-01T00:00:01.000001Z'):
    loose('loose exact age '+now,age=1,now=now)
for offset in ('00:02:00','00:02:00.000001','00:02:01'):
    loose('loose future precedence '+offset,expected=['wrong'],code=1,age=10**100,observed='2026-01-01T'+offset+'Z',now='2026-01-01T00:00:00Z')
for now in ('9999-12-31T23:57:59.999999Z','9999-12-31T23:58:00Z','9999-12-31T23:59:59.999999Z'):
    loose('loose UTC overflow '+now,observed='9999-12-31T23:57:59Z',now=now)
for command,runner,reason in [(['\ud800'],'github:\ud800','satisfied'),(['\ufffd'],'github:\ud800','wrong_command'),(['\ud800'],'github:\ufffd','wrong_runner'),(['🦀'],'github:🦀','satisfied')]:
    add('prepared '+repr((command,runner)),command=command,changes={},prepared=dict(command=['🦀'] if command==['🦀'] else ['\ud800'],prefix='github:🦀' if command==['🦀'] else 'github:\ud800',runner=runner,reason=reason))
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script, &root])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 168);
    for case in cases {
        let doc = super::super::statement_document::Document::from_bytes(
            case["raw"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let facts =
            DocumentFacts::for_check(&doc, &[99, 104, 101, 99, 107], "agent/alice").unwrap();
        assert_eq!(facts.exit_code, case["exit_code"].as_str().unwrap());
        let run = BTreeMap::from([
            ("rank".into(), "weak".into()),
            ("base".into(), "same".into()),
        ]);
        let checked = if case["policy"].is_null() {
            let command: Option<Vec<Vec<u32>>> =
                serde_json::from_value(case["command"].clone()).unwrap();
            let age = case["age"].as_str().map(|s| {
                s.parse::<u64>()
                    .map_or(AgeLimit::Overflow, AgeLimit::Seconds)
            });
            check_unconfigured_inputs(
                &facts,
                case["now"].as_i64().unwrap(),
                age,
                command.as_deref(),
                7,
            )
        } else {
            let mut rules = PolicyDocument::parse(case["policy"].as_str().unwrap(), "check")
                .unwrap()
                .into_rules("owner/repo")
                .unwrap();
            use crate::evidence::legacy_policy::normalized_text::NormalizedText;
            if let Some(prepared) = case["prepared"].as_object() {
                rules.kinds[0].1.inputs.command =
                    serde_json::from_value::<Vec<Vec<u32>>>(prepared["command"].clone())
                        .unwrap()
                        .into_iter()
                        .map(NormalizedText::Codepoints)
                        .collect();
                rules.kinds[0].1.runner_prefix = Some(NormalizedText::Codepoints(
                    serde_json::from_value(prepared["prefix"].clone()).unwrap(),
                ));
            }
            let evaluate = |rules: &PolicyRules| {
                super::super::routing::route_document(rules, &facts, 7).and_then(|routing| {
                    routing.check_document_runner(facts.runner, 7)?;
                    check_document_inputs(
                        rules,
                        &routing,
                        &facts,
                        case["now"].as_i64().unwrap(),
                        &run,
                        7,
                    )
                })
            };
            let first = evaluate(&rules);
            for (_, kind) in &mut rules.kinds {
                for text in &mut kind.inputs.command {
                    *text = NormalizedText::Codepoints(text.borrowed().points().collect());
                }
                if let Some(prefix) = &mut kind.runner_prefix {
                    *prefix = NormalizedText::Codepoints(prefix.borrowed().points().collect());
                }
            }
            let points = evaluate(&rules);
            assert_eq!(
                first
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| (e.reason, e.attempts)),
                points
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| (e.reason, e.attempts))
            );
            points
        };
        if let Err(error) = &checked {
            // This fixture catches OverflowError separately; explicit refusals never use error.
            assert_eq!(
                matches!(
                    error.origin,
                    crate::evidence::legacy_policy::ErrorOrigin::Exception {
                        class: "OverflowError"
                    }
                ),
                case["expected"]["reason"] == "error",
                "{}",
                case["label"]
            );
        }
        let actual = checked
            .map(|()| json!({"reason":"satisfied"}))
            .unwrap_or_else(|failure| json!({"reason":failure.reason,"attempts":failure.attempts}));
        assert_eq!(actual, case["expected"], "{}", case["label"]);
        if !case["intended"].is_null() {
            assert_eq!(
                actual["reason"], case["intended"],
                "prepared guard was not reached"
            );
        }
    }
}

#[test]
fn normalized_policy_text_preserves_native_command_comparisons() {
    use crate::evidence::legacy_policy::normalized_text::NormalizedText;
    for (actual, expected) in [("true", "true"), ("🦀", "🦀"), ("🦀", "�")] {
        let check = crate::evidence::Check {
            command: vec![actual.into()],
            exit_code: 0,
            output_sha256: String::new(),
        };
        let scalar = [NormalizedText::Scalar(expected.into())];
        let points = [NormalizedText::Codepoints(
            expected.chars().map(u32::from).collect(),
        )];
        for command in [&scalar, &points] {
            assert_eq!(
                CheckSource::Native(&check).matches_command(ExpectedCommand::Text(command)),
                actual == expected
            );
        }
        assert!(
            !CheckSource::Native(&check).matches_command(ExpectedCommand::Text(&[
                NormalizedText::Codepoints(vec![0xd800])
            ]))
        );
    }
}
