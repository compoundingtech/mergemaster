import ast, json, pathlib, sys
source=ast.parse((pathlib.Path(sys.argv[1])/'scripts/evidence-verify').read_text())
owner=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
accepted=next(n for n in owner.body if isinstance(n,ast.If) and n.lineno==1034)
preference=next(n for n in ast.walk(owner) if isinstance(n,ast.Compare) and n.lineno==1175 and isinstance(n.comparators[0],ast.Name) and n.comparators[0].id=='prefer_levels')
accept=compile(ast.Module(body=[accepted],type_ignores=[]),'pinned-accepted','exec')
prefer=compile(ast.Expression(body=preference),'pinned-preference','eval')
cases=[]
for levels in [None,[],['agent'],['agent','agent','host'],['\ud800'],['\ud800','\ufffd','🦀'],['','bad','host']]:
    ns=dict(rules=None,trust_levels=levels,prefer_levels=levels or [],level_of=lambda c:c)
    exec(accept,ns)
    for query in ['agent','host','fleet','','bad','\ufffd','🦀']:
        ns['c']=query
        cases.append(dict(levels=None if levels is None else [list(map(ord,s)) for s in levels],query=query,
                          accepted=ns['accepted'] is None or query in ns['accepted'],preferred=eval(prefer,ns)))
print(json.dumps(cases))
