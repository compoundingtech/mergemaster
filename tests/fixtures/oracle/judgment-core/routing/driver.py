import ast, copy, json, pathlib, runpy, sys
path = pathlib.Path(sys.argv[1])/'scripts/evidence-verify'
v = runpy.run_path(str(path)); module = ast.parse(path.read_text())
verify = next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
judge = copy.deepcopy(next(n for n in verify.body if isinstance(n,ast.FunctionDef) and n.name=='judge'))
stop = next(i for i,n in enumerate(judge.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='moment' for t in n.targets))
judge.body = judge.body[:stop] + ast.parse("return dict(reason='satisfied', command=command, required=list(required_inputs), bind=bind, events=events)").body
v.update(command=None,kinds=(),bind=(),max_age=None,runner_prefix=None,trust_levels=None,lane=None,level_lane=None,check='check',attempts=7)
v['failed'] = lambda entry: entry[1]['predicate']['observed']['checks']['check']['exit_code'] != 0
exec(compile(ast.fix_missing_locations(ast.Module(body=[judge],type_ignores=[])),str(path),'exec'),v)
cases = []
for runner in ['wrapper','wrapper\ud800','github:','github:\ud800','github:\ufffd','github:🦀','nix','other']:
 for code in [0,1,-10**100]:
  for tier,part in [('full',False),('test',True)]:
   for prefix in [None,'github:\ufffd']:
    entry = dict(trust_levels=['agent'],kinds={kind:dict(command=['true'],shard_inputs=dict(count='n',results='r',index='i'),by_level={'agent':dict(command=['override'],required_inputs=['bound'],events=['merge_group'])}) for kind in ['wrapper','observed','nix']})
    if prefix is not None:
     for kind in entry['kinds'].values(): kind['runner_prefix'] = prefix
    policy = json.dumps(dict(version=1,checks=dict(check=entry))); v['rules'] = v['policy_rules'](policy,'check','owner/repo')
    statement = dict(predicate=dict(tier=tier,observed_at='2026-01-01T00:00:00Z',observed=dict(runner=runner,checks=dict(check=dict(exit_code=code,command=['true'])))))
    if part: statement['predicate']['observed']['inputs'] = {'i':'\ud800'}
    try: expected = v['judge'](('record',statement,'agent/alice'))
    except v['Failure'] as failure: expected = dict(reason=failure.reason,attempts=failure.extra['attempts'],detail=list(map(ord,failure.detail)))
    cases.append(dict(policy=policy,raw=json.dumps(statement),expected=expected))
# Valid policy ingress can omit a recognized runner's kind; unknown runners
# reach the same explicit refusal. Neither case may use a default kind or skip.
for runner in ['nix', 'github:owner/repo/job', 'unknown']:
    policy = json.dumps(dict(version=1,checks=dict(check=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['true']))))))
    v['rules'] = v['policy_rules'](policy,'check','owner/repo')
    statement = dict(predicate=dict(tier='full',observed_at='2026-01-01T00:00:00Z',observed=dict(runner=runner,checks=dict(check=dict(exit_code=0,command=['true'])))))
    try:
        v['judge'](('record',statement,'agent/alice'))
        raise AssertionError('unsupported kind was accepted')
    except v['Failure'] as failure:
        assert (failure.reason,failure.detail,failure.extra['attempts']) == ('unsupported_kind',f'runner {runner!r} is not one of ',7)
        expected = dict(reason=failure.reason,attempts=failure.extra['attempts'],detail=list(map(ord,failure.detail)))
    cases.append(dict(policy=policy,raw=json.dumps(statement),expected=expected))
def loose(runner, tier, code, kinds, levels, prefix, principal='agent/alice'):
    v['rules'] = None
    statement = dict(predicate=dict(tier=tier,observed_at='2026-01-01T00:00:00Z',observed=dict(runner=runner,inputs={'i':'part'},checks=dict(check=dict(exit_code=code,command=['true'])))))
    try: expected = v['judge'](('record',statement,principal),kinds=kinds,trust_levels=levels,runner_prefix=prefix)
    except v['Failure'] as failure: expected = dict(reason=failure.reason,attempts=failure.extra['attempts'],detail=list(map(ord,failure.detail)))
    points = lambda value: None if value is None else list(map(ord,value))
    cases.append(dict(policy=None,raw=json.dumps(statement),expected=expected,principal=principal,
                      kinds=[points(kind) for kind in kinds],levels=None if levels is None else [points(level) for level in levels],prefix=points(prefix)))
all_kinds = ['wrapper','observed','nix','sekrets']
for runner in ['wrapper','wrapper\ud800','github:','github:\ud800','github:\ufffd','github:🦀','nix','sekrets','other','\ud800']:
 for tier in ['full','test']:
  for code in [0,-10**100]:
   for kinds,levels,prefix in [(all_kinds,None,None),([],None,None),(['wrapper','observed','\ud800'],['agent'],None),(all_kinds,[],None),(all_kinds,['host','\ud800'],None),(all_kinds,None,'github:\ud800'),(all_kinds,None,''),(all_kinds,None,'github:\ufffd'),(all_kinds,None,'github:🦀')]:
    loose(runner,tier,code,kinds,levels,prefix)
for principal in ['host/alice','agent','']:
 for levels in [None,[],['host','agent','']]:
  loose('wrapper','full',0,all_kinds,levels,None,principal)
raw_stdout = (json.dumps(cases) + '\n').encode()
h = runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
rows = [dict(input=h['json_recipe']({key: value for key, value in row.items() if key != 'expected'}),
             expected=h['identity'](json.loads(json.dumps(row['expected'])))) for row in cases]
print(json.dumps(h['document'](rows, raw_stdout), separators=(',', ':')))
