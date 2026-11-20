
import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
for check in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 kinds=[{kind:dict(command=['run'])} for kind in ['unknown','😀','quote\'"\n','\u0378','\ud800','\udfff']]
 kinds += [dict(wrapper=value) for value in [None,{},dict(command=['run'],unknown=True),dict(command=[]),dict(command=['run'],trust_levels=[]),dict(command=['run'],trust_levels=['']),dict(command=['run'],runner_prefix=''),dict(command=['run'],runner_prefix=1)]]
 kinds += [dict(wrapper=dict(command=['run'],by_level=value)) for value in [True,1,1.5,'x',[1],2**64,10**100,1e400,-1e400]]
 for point in ['\ud800','\udfff']:
  kinds += [dict(wrapper=dict(command=['run'],**fields)) for fields in [
   dict(base_inputs={point:point}),dict(input_order={point:[point,point]}),dict(bind_inputs={point:None})]]
 for value in kinds:
  text=json.dumps(dict(version=1,checks={check:dict(trust_levels=['agent'],kinds=value)}))
  try: v['policy_rules'](text,check,'org/repo')
  except Exception as error:
   failure=isinstance(error,v['Failure']);kind='Failure' if failure else 'Exception'
   env=dict(v,failure=error,error=error,args=types.SimpleNamespace(check=check))
   cases.append(dict(text=text,name=list(map(ord,check)),exception=None if failure else type(error).__name__,reason=error.reason if failure else 'error',detail=list(map(ord,error.detail if failure else str(error))),single=eval(dump(kind,False),env),global_=eval(dump(kind,True),env)))
  else: raise AssertionError('expected refusal')
print(json.dumps(cases))
