import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); out=[]
for text in json.load(sys.stdin):
 try: v['policy_rules'](text,'unit','org/repo'); raise AssertionError('missing check')
 except v['Failure'] as error: out.append(dict(reason=error.reason,detail=error.detail))
print(json.dumps(out))
