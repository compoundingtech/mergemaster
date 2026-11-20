import ast,json,runpy,sys,types
assert json.load(sys.stdin) is None
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def dump(kind,global_):
 h=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(h.body[0].body[0].value.args[0] if global_ else h.body[1].value.args[0]),'<handler>','eval')
cases=[]
for name in ['check','\ud800','\udfff','😀','quote\'"\n','\u0378']:
 for helper,rules in [('checked_command_inputs',[{},dict(command=[]),dict(command=[None]),dict(command=['run'],required_inputs=1),dict(command=['run'],bind_inputs={'x':1})]),('checked_base_inputs',[dict(base_inputs=[]),dict(base_inputs={'x':'../bad'}),dict(base_inputs={'x':'a\n'}),dict(base_inputs={'x':'x'*301})]),('checked_value_rules',[dict(input_order=[]),dict(input_order={'x':['a','a']}),dict(input_order={'x':[[],[]]}),dict(input_order={'x':[{},'a']}),dict(input_order={'':['a',[]]}),dict(input_order={'x':[[]]}),dict(shard_inputs=[]),dict(shard_inputs={'count':'n','results':'r','index':None})])]:
  for rule in rules:
   try: v[helper](rule.copy(),name)
   except Exception as error:
    failure=isinstance(error,v['Failure']);kind='Failure' if failure else 'Exception'
    env=dict(v,failure=error,error=error,args=types.SimpleNamespace(check=name))
    cases.append(dict(helper=helper,rule=rule,name=list(map(ord,name)),class_=None if failure else type(error).__name__,reason=error.reason if failure else 'error',detail=list(map(ord,error.detail if failure else str(error))),single=eval(dump(kind,False),env),global_=eval(dump(kind,True),env)))
   else: raise AssertionError('expected refusal')
print(json.dumps(cases))
