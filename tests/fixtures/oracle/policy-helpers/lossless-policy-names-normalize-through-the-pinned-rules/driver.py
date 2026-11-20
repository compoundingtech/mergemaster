import json,pathlib,runpy,sys,tempfile
assert json.load(sys.stdin) is None
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
points=lambda s:list(map(ord,s))
for check in ['check','\ud800','\udfff','🦀','a\ud800b','\0','{repository}','{check}']:
 for repo in ['owner/repo','owner/{check}']:
  for mode in ['off','shadow','reject']:
   entry=dict(require=mode,trust_levels=['agent'],kinds=dict(wrapper=dict(command=['{repository}','{check}','{check}{check}','literal'],runner_prefix='producer/{repository}/{check}',by_level=dict(agent=dict(command=['level/{check}','{repository}'],events=['pull_request'])))))
   text=json.dumps(dict(version=1,checks={check:entry}),ensure_ascii=repo=='owner/repo' or any(0xd800<=ord(c)<=0xdfff for c in check))
   text.encode('utf-8')  # read_policy accepts strict UTF-8, not surrogatepass text.
   rules=v['policy_rules'](text,check,repo); kind=rules['kinds']['wrapper']
   expected=dict(require=rules['require'],command=[points(s) for s in kind['command']],prefix=points(kind['runner_prefix']),level_command=[points(s) for s in kind['by_level']['agent']['command']])
   cases.append(dict(text=text,check=points(check),repo=repo,expected=expected))
 for mutation in ['unknown','empty-kinds','missing-command','absent']:
  entry=dict(require='off',trust_levels=['agent'],kinds=dict(wrapper=dict(command=['true'])))
  if mutation=='unknown': entry['unknown']=True
  if mutation=='empty-kinds': entry['kinds']={}
  if mutation=='missing-command': del entry['kinds']['wrapper']['command']
  text=json.dumps(dict(version=1,checks={} if mutation=='absent' else {check:entry}))
  try: v['policy_rules'](text,check,'owner/repo'); raise AssertionError('expected refusal')
  except v['Failure'] as error: reason=error.reason
  except KeyError: reason='error'
  cases.append(dict(text=text,check=points(check),repo='owner/repo',expected=dict(reason=reason)))
namespace=v['read_policy'].__globals__; original=namespace['config_blob']
for invalid in [b'\xff',b'\xed\xa0\x80']:
 raw=b'{"version":1,"checks":{"'+invalid+b'":{}}}'
 with tempfile.NamedTemporaryFile() as file:
  file.write(raw); file.flush()
  namespace['config_blob']=lambda *args:pathlib.Path(file.name).read_bytes()
  try: v['read_policy']('unused','base'); raise AssertionError('invalid policy accepted')
  except v['Failure'] as error: reason=error.reason
  finally: namespace['config_blob']=original
 cases.append(dict(policy_bytes=list(raw),reason=reason))
print(json.dumps(cases))
