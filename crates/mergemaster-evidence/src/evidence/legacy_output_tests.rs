use super::*;

#[test]
fn legacy_output_matches_pinned_json_dumps_bytes() {
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
    let output = std::process::Command::new("python3").args(["-c", r#"
import runpy,sys
json=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
points=''.join(map(chr,range(0x110000)))
cases=[points,{},[],{'z':[], '\ud800😀':[True,False,None,-170141183460469231731687303715884105728,{'empty':{},'s':'quote"\\\n'}]}, [[[]],{}]]
for value in cases: print(json.dumps(value,indent=2))
"#, &root]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut actual = String::new();
    let points: Vec<_> = (0..=0x10ffff).collect();
    Writer::new(&mut actual).string(&points).unwrap();
    actual.push('\n');
    Writer::new(&mut actual).object(|_| Ok(())).unwrap();
    actual.push('\n');
    Writer::new(&mut actual).array(|_| Ok(())).unwrap();
    actual.push('\n');
    Writer::new(&mut actual)
        .object(|o| {
            o.field_text("z", |w| w.array(|_| Ok(())))?;
            o.field(&[0xd800, 0x1f600], |w| {
                w.array(|a| {
                    a.item(|w| w.boolean(true))?;
                    a.item(|w| w.boolean(false))?;
                    a.item(|w| w.null())?;
                    a.item(|w| w.integer(i128::MIN))?;
                    a.item(|w| {
                        w.object(|o| {
                            o.field_text("empty", |w| w.object(|_| Ok(())))?;
                            o.field_text("s", |w| w.text("quote\"\\\n"))
                        })
                    })
                })
            })
        })
        .unwrap();
    actual.push('\n');
    Writer::new(&mut actual)
        .array(|a| {
            a.item(|w| w.array(|a| a.item(|w| w.array(|_| Ok(())))))?;
            a.item(|w| w.object(|_| Ok(())))
        })
        .unwrap();
    actual.push('\n');
    assert_eq!(actual.as_bytes(), output.stdout);
}

#[test]
fn legacy_output_propagates_sink_and_codepoint_errors() {
    struct Refuse;
    impl Write for Refuse {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            Err(fmt::Error)
        }
    }
    assert!(Writer::new(&mut Refuse).object(|_| Ok(())).is_err());
    assert!(Writer::new(&mut String::new()).string(&[0x110000]).is_err());
    assert!(
        Writer::new(&mut String::new())
            .array(|_| Err(fmt::Error))
            .is_err()
    );
}
