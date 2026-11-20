use super::*;
#[test]
fn repository_substitution_preserves_original_codepoints() {
    let rows = crate::oracle_digest::rows(include_bytes!(
        "../../../../../tests/fixtures/oracle/policy-helpers/repository-substitution-preserves-original-codepoints/stdout.bin"
    ));
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 24);
    for row in rows {
        let (text, repository): (String, Vec<u32>) =
            serde_json::from_value(crate::oracle_digest::json(&row["input"])).unwrap();
        let stderr: Vec<u8> = serde_json::from_value(row["stderr"].clone()).unwrap();
        let code = row["exit"].as_i64().unwrap() as i32;
        let evaluate = |repository| {
            let rules = PolicyDocument::parse(&text, "check")
                .unwrap()
                .into_rules(repository)
                .unwrap();
            let kind = &rules.kinds[0].1;
            let points = |s: &NormalizedText| s.borrowed().points().collect::<Vec<_>>();
            let result = (
                kind.inputs.command.iter().map(points).collect::<Vec<_>>(),
                points(kind.runner_prefix.as_ref().unwrap()),
                kind.by_level[0]
                    .1
                    .inputs
                    .command
                    .iter()
                    .map(points)
                    .collect::<Vec<_>>(),
            );
            let mut actual = serde_json::to_vec(&result).unwrap();
            actual.push(b'\n');
            crate::oracle_digest::assert_value(
                &serde_json::to_value(actual).unwrap(),
                &row["stdout"],
            );
            assert_eq!((Vec::<u8>::new(), 0), (stderr.clone(), code));
        };
        evaluate(TextRef::Points(&repository));
        if let Some(scalar) = repository
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            evaluate(TextRef::Str(&scalar));
        }
    }
}
