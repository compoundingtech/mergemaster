import ast,itertools,json,runpy,sys,types
path=sys.argv[1]+'/scripts/evidence-verify';v=runpy.run_path(path)
main=next(n for n in ast.parse(open(path).read()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
def expression(kind):
 handler=next(n for n in ast.walk(main) if isinstance(n,ast.ExceptHandler) and isinstance(n.type,ast.Name) and n.type.id==kind)
 return compile(ast.Expression(handler.body[1].value.args[0]),'<pinned-single-error>','eval')
failure_dump=expression('Failure');exception_dump=expression('Exception');cases=[]
names=['unit','','\ud800','\udfff','face😀'];details=['','line\nquote"\\','\ud800','\udfff','face😀','OverflowError: literal']
extras=[{},dict(attempts=0),dict(attempts=2),dict(attempts=2,decided_by='record',skipped_newer=[]),dict(decided_by='record',skipped_newer=['other level_not_accepted','\ud800😀'])]
def points(value): return None if value is None else list(map(ord,value))
for reason,check,detail,extra in itertools.product(['no_record','wrong_check','error','\ud800'],names,details,extras):
 failure=v['Failure'](reason,detail,**extra)
 wire=eval(failure_dump,dict(v,failure=failure,args=types.SimpleNamespace(check=check)))
 cases.append(dict(check=points(check),reason=points(reason),detail=points(detail),attempts=extra.get('attempts'),decided=points(extra.get('decided_by')),skipped=None if 'skipped_newer' not in extra else list(map(points,extra['skipped_newer'])),wire=wire))
for name,check,detail in itertools.product(['OverflowError','ValueError','Échec😀'],names,details):
 error=type(name,(Exception,),{})(detail)
 wire=eval(exception_dump,dict(v,error=error,args=types.SimpleNamespace(check=check)))
 cases.append(dict(check=points(check),class_=name,detail=points(detail),wire=wire))
for case in cases: case['class']=case.pop('class_',None)
print(json.dumps(cases))
