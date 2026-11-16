use super::*;
#[test]
fn total_seconds_matches_python_single_rounding_bits_and_integer_age() {
    let script = r#"
import json,pathlib,random,runpy,struct,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); td=v['timedelta']; rows=[]
values={0,1,-1,999999,1000000,1000001,34359738368999997}
for e in range(0,44):
 for offset in [-1000001,-1000000,-999999,-7,-6,-5,-4,-3,-2,-1,0,1,2,3,4,5,6,7,999999,1000000,1000001]:
  value=(1<<e)*1000000+offset
  values.update([value,-value])
# Ties to an even binary significand, on each side of the microsecond boundary.
for e in range(34,44):
 for offset in range(-16,17): values.update([(1<<e)*1000000+15625+offset,-((1<<e)*1000000+15625+offset)])
r=random.Random(245)
values.update(r.randrange(-(1<<63),(1<<63)) for _ in range(2000))
for delta in sorted(values):
 if not -(1<<63)<=delta<(1<<63): continue
 result=td(microseconds=delta).total_seconds(); rows.append([delta,0,struct.pack('>d',result).hex(),int(result)])
for now,then in [(-(1<<63),(1<<63)-1),((1<<63)-1,-(1<<63)),(-(1<<63),-(1<<63)),((1<<63)-1,(1<<63)-1)]:
 result=td(microseconds=now-then).total_seconds(); rows.append([now,then,struct.pack('>d',result).hex(),int(result)])
assert int(td(microseconds=34359738368999997).total_seconds())==34359738369
print(json.dumps(rows))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .arg(std::env::var("MERGEMASTER_PYTHON_PARITY_ORACLE").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<(i64, i64, String, i64)> = serde_json::from_slice(&output.stdout).unwrap();
    for (now, then, bits, integer) in rows {
        let result = total_seconds(now, then);
        assert_eq!(format!("{:016x}", result.to_bits()), bits, "{now} - {then}");
        assert_eq!(result as i64, integer, "{now} - {then}");
    }
}
