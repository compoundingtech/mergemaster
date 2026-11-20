import json,runpy,sys
assert json.load(sys.stdin) is None
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
cases=[]
for point in ['\ud800','\udfff','😀','\u0378']:
 for item in [point,'!'+point,'x.json::'+point,point+'.yml::jobs.id']:
  for selectors in [False,True]:
   text=json.dumps([item])
   try: result=v['declared_paths'](json.loads(text),'fixture',selectors)
   except v['Failure'] as error:
    cases.append(dict(text=text,selectors=selectors,reason=error.reason,detail=list(map(ord,error.detail))))
   else: raise AssertionError('expected invalid literal')
print(json.dumps(cases))
