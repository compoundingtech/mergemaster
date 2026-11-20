
import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
base=dict(command=['run'],events=['pull_request'])
overrides=[None,{},dict(command=['run']),dict(base,unknown=True),dict(base,lane='base'),dict(base,lane=0)]
for events in [[],['push'],['pull_request','pull_request'],[[]],None]:
 overrides.append(dict(base,events=events) if events is not None else dict(command=['run']))
cases_by_override=[]
for value in overrides: cases_by_override.append(value)
for check in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 for level in ['agent','unlisted','']:
  for value in cases_by_override:
   text=json.dumps(dict(version=1,checks={check:dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'],by_level={level:value})))}))
   try: v['policy_rules'](text,check,'org/repo')
   except Exception as error:
    failure=isinstance(error,v['Failure']);kind='Failure' if failure else 'Exception'
    env=dict(v,failure=error,error=error,args=types.SimpleNamespace(check=check))
    cases.append(dict(text=text,name=list(map(ord,check)),exception=None if failure else type(error).__name__,reason=error.reason if failure else 'error',detail=list(map(ord,error.detail if failure else str(error))),single=eval(dump(kind,False),env),global_=eval(dump(kind,True),env)))
   else: raise AssertionError('expected refusal')
print(json.dumps(cases))
