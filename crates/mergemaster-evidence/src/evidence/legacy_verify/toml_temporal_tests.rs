use super::*;
use serde_json::json;

#[test]
fn temporal_prefixes_match_pinned_tomllib() {
    let script = r#"
import datetime,itertools,json,sys
from tomllib import TOMLDecodeError
from tomllib._re import RE_DATETIME,RE_LOCALTIME,match_to_datetime,match_to_localtime
assert sys.version_info[:3]==(3,14,7),sys.version
samples=['', 'x', '12:34', '2024-01', '２０２４-01-01', '2024-０１-01',
         '2024-01-０１', '１２:34:56', '12:３４:56', '12:34:５６']
for year,month,day in itertools.product(
    ['0000','0001','0004','0100','0400','1600','1900','2000','2023','2024','9999'],
    ['00','01','02','03','04','06','09','11','12','13','99'],
    ['00','01','28','29','30','31','32','99']):
 samples.append(f'{year}-{month}-{day}')
for hour,minute,second in itertools.product(
    ['00','01','09','19','20','23','24','29','99'],
    ['00','09','59','60','99'], ['00','09','59','60','99']):
 samples.append(f'{hour}:{minute}:{second}')
for sep,fraction,offset in itertools.product(
    ['T','t',' ','  ','\t','\n',''],
    ['', '.', '.x', '.0', '.1', '.000001', '.123456', '.1234567',
     '.12345678901234567890', '.999999999', '.１２'],
    ['', 'Z', 'z', '+00:00', '-00:00', '+23:59', '-23:59', '+01:30',
     '-01:30', '+24:00', '+00:60', '+1:00', '+00:0', '+', 'Z+01:00', '+０１:00']):
 samples.append('2024-02-29'+sep+'12:34:56'+fraction+offset)
for fraction in ['', '.', '.x', '.0', '.1', '.000001', '.12345678901234567890', '.１２']:
 for suffix in ['', 'Z', '+23:59', '-00:00', '🦀']:
  samples.append('23:59:59'+fraction+suffix)
for token in ['2024-02-29T23:59:59.123456789-23:59', '0000-02-29t00:00:00Z',
              '2023-02-29 00:00:00', '12:34:56.123456789']:
 samples.extend(token[:end] for end in range(len(token)+1))
cases=[]
for token in sorted(set(samples)):
 for prefix in ['', '🦀', '🦀\r\né']:
  raw=prefix+token
  src=raw.replace('\r\n','\n')
  for pos in sorted({len(prefix.replace('\r\n','\n')),len(src),len(src)+1}):
   match=RE_DATETIME.match(src,pos)
   try:
    if match:
     try: value=match_to_datetime(match)
     except ValueError: raise TOMLDecodeError('Invalid date or datetime',src,pos)
    else:
     match=RE_LOCALTIME.match(src,pos)
     value=match_to_localtime(match) if match else None
    if value is None: expected=dict(none=True)
    else:
     fields=dict(end=match.end())
     if isinstance(value,datetime.date):
      fields['date']=[value.year,value.month,value.day]
     if isinstance(value,(datetime.datetime,datetime.time)):
      fields['time']=[value.hour,value.minute,value.second,value.microsecond]
     if isinstance(value,datetime.datetime):
      offset=value.utcoffset()
      fields['offset']=None if offset is None else int(offset.total_seconds()/60)
     expected=fields
   except TOMLDecodeError as e:
    expected=dict(error=str(e),message=e.msg,pos=e.pos,line=e.lineno,
                  column=e.colno,kind=type(e).__name__)
   cases.append(dict(raw=raw,pos=pos,expected=expected))
print(json.dumps(cases))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases {
        let source = Source::new(case["raw"].as_str().unwrap());
        let pos = usize::try_from(case["pos"].as_u64().unwrap()).unwrap();
        let actual = match source.temporal(pos) {
            Ok(None) => json!({"none":true}),
            Ok(Some((end, Value::Date(date)))) => {
                json!({"end":end,"date":[date.year,date.month,date.day]})
            }
            Ok(Some((end, Value::Time(time)))) => {
                json!({"end":end,"time":[time.hour,time.minute,time.second,time.microsecond]})
            }
            Ok(Some((
                end,
                Value::DateTime {
                    date,
                    time,
                    offset_minutes,
                },
            ))) => {
                json!({"end":end,"date":[date.year,date.month,date.day],
                    "time":[time.hour,time.minute,time.second,time.microsecond],"offset":offset_minutes})
            }
            Ok(Some(other)) => panic!("unexpected temporal value: {other:?}"),
            Err(e) => json!({"error":e.to_string(),"message":e.message,"pos":e.position,
                "line":e.line,"column":e.column,"kind":e.kind.class()}),
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert!(Source::new("").temporal(usize::MAX).unwrap().is_none());
}
