import json,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');out=[]
for text in json.load(sys.stdin):
 try:v['policy_rules'](text,'check','org/repo')
 except v['Failure'] as error:
  out.append(dict(reason=error.reason,detail=list(map(ord,error.detail))))
 else:raise AssertionError('expected syntax refusal')
print(json.dumps(out))
