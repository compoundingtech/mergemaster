
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');cases=[]
for check in ['\ud800','\udfff']:
 for level in ['\ud800','\udfff']:
  base=dict(command=['run'],events=['pull_request'])
  overrides=[dict(base,command=[level,1]),dict(base,required_inputs=[level,1]),
   dict(base,bind_inputs={level:None}),dict(base,events=[level]),dict(base,**{level:True}),
   dict(base,lane=2**64),dict(base,lane=1e400),2**64,10**100,1e400]
  for override in overrides:
   text=json.dumps(dict(version=1,checks={check:dict(trust_levels=[level],kinds=dict(
    wrapper=dict(command=['run'],by_level={level:override})))}))
   try:v['policy_rules'](text,check,'org/repo')
   except v['Failure'] as error:
    cases.append(dict(text=text,check=list(map(ord,check)),reason=error.reason,detail=list(map(ord,error.detail))))
   else:raise AssertionError('expected refusal')
print(json.dumps(cases))
