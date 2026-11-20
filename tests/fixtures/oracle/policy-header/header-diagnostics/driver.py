import ast,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
handler=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id=='Failure')
single=compile(ast.Expression(handler.body[1].value.args[0]),'<single>','eval')
global_=compile(ast.Expression(handler.body[0].body[0].value.args[0]),'<global>','eval')
cases=[]
for name in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 base=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'])))
 entries=[None,{},dict(kinds=base['kinds']),dict(trust_levels=['agent']),dict(base,unknown=True)]
 for field,values in [('trust_levels',[[],['']]),('max_age_s',[0,-1,True,0.5,'x']),('enforce',[1]),('require',['bad']),('inputs',[[]]),('sample_one_in',[0,True]),('kinds',[{}]),('events',[[],['bad']])]:
  entries.extend(dict(base,**{field:value}) for value in values)
 for present,entry in [(False,None)]+[(True,entry) for entry in entries]+[(True,dict(base,max_age_s=2**64))]:
  text=json.dumps(dict(version=1,checks={name:entry} if present else {}))
  try: v['policy_rules'](text,name,'org/repo')
  except v['Failure'] as failure:
   env=dict(v,failure=failure,args=types.SimpleNamespace(check=name))
   cases.append(dict(text=text,name=list(map(ord,name)),reason=failure.reason,detail=list(map(ord,failure.detail)),single=eval(single,env),global_=eval(global_,env)))
  else:
   assert entry['max_age_s']==2**64
   cases.append(dict(text=text,name=list(map(ord,name)),accepted_seconds=str(entry['max_age_s'])))
print(json.dumps(cases))
