import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
module=ast.parse(open(path).read())
raise_node=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
detail=compile(ast.Expression(next(n for n in ast.walk(raise_node) if isinstance(n,ast.Raise) and isinstance(n.exc,ast.Call) and getattr(n.exc.func,'id',None)=='Failure' and isinstance(n.exc.args[0],ast.Constant) and n.exc.args[0].value=='no_record').exc.args[1]),'<detail>','eval')
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
for check in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 policy=json.dumps(dict(version=1,checks={check:dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['true'],shard_inputs=dict(count='n',results='r',index='i'))))}))
 statement=json.dumps(dict(predicate=dict(tier='full',observed_at='2026-01-01T00:00:00Z',observed=dict(runner='wrapper',inputs=dict(i='0'),checks={check:dict(exit_code=0,command=['true'])}))))
 failure=v['Failure']('no_record',eval(detail,dict(v,check=check)),attempts=1)
 env=dict(v,failure=failure,args=types.SimpleNamespace(check=check))
 cases.append(dict(name=list(map(ord,check)),policy=policy,statement=statement,detail=list(map(ord,failure.detail)),single=eval(dump('Failure',False),env),global_=eval(dump('Failure',True),env)))
print(json.dumps(cases))
