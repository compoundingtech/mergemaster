use super::*;

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
    check: Vec<u32>,
    repository: Vec<u32>,
    success: bool,
    expected: String,
}

#[test]
fn wave2_a2_policy_rules_backend_matches_pinned_python_losslessly() {
    let script = r#"
import copy,json,os,pathlib,runpy
v=runpy.run_path(str(pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify'))
rows=[]
def add(name,entry=None,check='check',repository='org/repo',text=None):
 if text is None:
  text=json.dumps({'version':1,'checks':{check:entry}})
 try:
  result=v['policy_rules'](text,check,repository)
  assert isinstance(result,dict)
  success=True
 except v['Failure'] as error:
  result={'reason':error.reason,'detail':error.detail};success=False
 except Exception as error:
  result={'reason':'error','detail':f'{type(error).__name__}: {error}'};success=False
 rows.append(dict(name=name,text=text,check=list(map(ord,check)),repository=list(map(ord,repository)),success=success,expected=json.dumps(result,indent=2)))
simple={'trust_levels':['agent'],'kinds':{'wrapper':{'command':['run']}}}
add('defaults',simple)
complex={
 'trust_levels':['host','agent','host'],
 'max_age_s':10**100,'enforce':True,'inputs':['src','!docs','src','.github/workflows/check.yml::jobs.test'],
 'sample_one_in':1000,'require':'reject','events':['merge_group','pull_request'],
 'kinds':{
  'observed':{
   'command':['run','{repository}','{check}','{repository}/{check}'],
   'runner_prefix':'runner:{repository}:{check}',
   'required_inputs':['z','a','z'],'bind_inputs':{'bound':'event_name','a':'{check}'},
   'trust_levels':['host','agent'],
   'by_level':{
    'host':{'command':['host','{repository}/{check}'],'required_inputs':['z','z'],
     'bind_inputs':{'event':'event_name'},'events':['pull_request'],'lane':'tree'},
    'agent':{'command':['agent'],'events':['merge_group'],'lane':True}},
   'input_order':{'size':['large','small'],'mode':['strict','normal','quick']},
   'shard_inputs':{'count':'shards','results':'results','pull_request_count':2,'index':'index'},
   'base_inputs':{'baseline':'.github/clippy-baseline.json','lock':'Cargo.lock'}},
  'nix':{'command':['nix','build'],'runner_prefix':None,'trust_levels':None,'by_level':None},
  'sekrets':{'command':['sekrets'],'by_level':{'host':{'command':['test'],'events':['pull_request'],'lane':False}}}}
add('all normalized fields',complex,repository='org/{check}')
for label,shards in [
 ('absent',None),('null count',{'count':'n','results':'r','pull_request_count':None}),
 ('no count',{'count':'n','results':'r'}),('index only',{'count':'n','results':'r','index':'i'})]:
 entry=copy.deepcopy(simple);entry['kinds']['wrapper']['shard_inputs']=shards
 add('shards '+label,entry)
entry=copy.deepcopy(simple)
entry.update(max_age_s=None,inputs=None,events=None,require='shadow',sample_one_in=1)
add('explicit null header fields',entry)
s='\ud800';t='\udfff';check='check'+s
entry={'trust_levels':['host'+s], 'kinds':{'wrapper':{
 'command':['run'+s,'{repository}','{check}'],'runner_prefix':'runner{repository}{check}'+t,
 'required_inputs':[t,s,t,'scalar'],'bind_inputs':{s:'value'+t,'scalar':'{repository}'},
 'trust_levels':['host'+s],
 'by_level':{'host'+s:{'command':['{check}','{repository}',t],'required_inputs':[s,t],
   'bind_inputs':{t:s},'events':['pull_request'],'lane':'tree'}},
 'input_order':{s:['a'+s,'b'+t]},
 'shard_inputs':{'count':s,'results':t,'pull_request_count':None,'index':'index'+s},
 'base_inputs':{s:'Cargo.lock'}}}}
add('surrogates in every text domain',entry,check,'org/'+t+'/{check}')
add('missing check',check='missing'+s,text='{"version":1,"checks":{}}')
add('bad syntax',text='{"version":')
add('wrong top level',text='[]')
for name,change in [
 ('unknown field',{'unknown':True}),('invalid levels',{'trust_levels':[]}),
 ('boolean age',{'max_age_s':True}),('bad event',{'events':['push']}),
 ('bad sample',{'sample_one_in':0}),('empty kinds',{'kinds':{}})]:
 entry=copy.deepcopy(simple);entry.update(change);add(name,entry)
for name,change in [
 ('empty command',{'command':[]}),('bad base path',{'base_inputs':{'base':'../escape'}}),
 ('bad shards',{'shard_inputs':{'count':'n','results':'r','pull_request_count':17}}),
 ('bad override',{'by_level':{'agent':{'command':['run']}}}),
 ('unknown level',{'by_level':{'other':{'command':['run'],'events':['pull_request']}}}),
 ('by level exception',{'by_level':True}),
 ('unhashable order',{'input_order':{'key':[[],[]]}}),
 ('surrogate invalid command',{'command':[s,None]})]:
 entry=copy.deepcopy(simple);entry['kinds']['wrapper'].update(change);add(name,entry,check='bad'+s)
print(json.dumps(rows))
"#;
    let output = crate::pinned_python::command()
        .args(["-B", "-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Case> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 25);
    assert_eq!(cases.iter().filter(|case| case.success).count(), 8);
    for case in cases {
        let mut actual = String::new();
        let result = write(
            &case.text,
            TextRef::Points(&case.check),
            TextRef::Points(&case.repository),
            &mut actual,
        );
        assert_eq!(result.is_ok(), case.success, "{}: {result:?}", case.name);
        if let Err(error) = result {
            assert!(actual.is_empty(), "{}: partial rules output", case.name);
            legacy_output::write(&mut actual, |writer| {
                writer.object(|object| {
                    object.field_text("reason", |writer| writer.text(error.reason))?;
                    object.field_text("detail", |writer| match error.origin {
                        ErrorOrigin::Failure => text(writer, &error.detail),
                        ErrorOrigin::Exception { class } => writer.codepoints(
                            class
                                .chars()
                                .map(u32::from)
                                .chain([58, 32])
                                .chain(error.detail.borrowed().points()),
                        ),
                    })
                })
            })
            .unwrap();
        }
        assert_eq!(actual, case.expected, "{}", case.name);
    }
}

#[test]
fn wave2_a2_scalar_check_and_repository_use_the_same_backend() {
    let policy = r#"{"version":1,"checks":{"check":{"trust_levels":["agent"],"kinds":{"wrapper":{"command":["{repository}","{check}"]}}}}}"#;
    let mut scalar = String::new();
    write(
        policy,
        TextRef::Str("check"),
        TextRef::Str("org/repo"),
        &mut scalar,
    )
    .unwrap();
    let mut points = String::new();
    write(
        policy,
        TextRef::Points(&"check".chars().map(u32::from).collect::<Vec<_>>()),
        TextRef::Points(&"org/repo".chars().map(u32::from).collect::<Vec<_>>()),
        &mut points,
    )
    .unwrap();
    assert_eq!(scalar, points);
    assert!(scalar.contains("\"org/repo\""));
    assert!(!scalar.contains("{repository}"));
}
