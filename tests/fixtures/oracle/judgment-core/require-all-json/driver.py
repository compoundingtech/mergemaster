import ast,itertools,json,runpy,sys
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path);cases=[]
ns=v['require_all'].__globals__
names=['😀','z','\ud800','a']
for modes in itertools.product(['off','shadow','reject'],repeat=4):
 for pattern in ['ok','failure','mixed','no-lane']:
  checks=dict(zip(names,modes))
  ns['policy_rules']=lambda text,check,repo:dict(require=checks[check])
  def lane(repo,tree,lane_file,check,lane_base):
   if pattern=='no-lane' and check=='\ud800': raise v['Failure']('no_lane','fixture lane missing\ud800')
  def verify(repo,tree,check,*args,**kwargs):
   if pattern=='failure' or pattern=='mixed' and check!='a': raise v['Failure']('wrong_check','fixture refusal\nquote" λ😀\udfff')
   return dict(record='record',signer='agent/fixture',tier='full')
  ns['lane_for']=lane;ns['verify']=verify
  result=v['require_all'](None,'a'*40,None,json.dumps(dict(version=1,checks=checks)),'fixture')
  wire=json.dumps(result,indent=2)
  result['lanes']=[[list(map(ord,k)),dict(item,tier=list(map(ord,item['tier']))) if item['satisfied'] else dict(item,detail=list(map(ord,item['detail'])))] for k,item in result['lanes'].items()]
  cases.append(dict(value=result,wire=wire))
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
errors=[]
for kind in ['Failure','Exception']:
 handler=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 dump=compile(ast.Expression(handler.body[0].body[0].value.args[0]),'<pinned-global-envelope>','eval')
 for reason in ['error','no_policy'] if kind=='Failure' else ['error']:
  env=dict(v,failure=v['Failure'](reason,'fixture detail\nλ😀\ud800'),error=OverflowError('fixture overflow\udfff'))
  wire=eval(dump,env);value=json.loads(wire)
  value['detail']=list(map(ord,value['detail']))
  source=env['failure'] if kind=='Failure' else env['error']
  detail=source.detail if kind=='Failure' else str(source)
  errors.append(dict(value=value,wire=wire,source_detail=list(map(ord,detail)),exception=kind=='Exception'))
original_rows = dict(cases=cases,errors=errors)
raw_stdout = (json.dumps(original_rows) + '\n').encode()
import pathlib
h = runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
rows = {group: [dict(input=h['json_recipe']({key: value for key, value in row.items() if key != 'wire'}),
                     wire=h['identity'](row['wire'])) for row in values]
        for group, values in original_rows.items()}
print(json.dumps(h['document'](rows, raw_stdout), separators=(',', ':')))
