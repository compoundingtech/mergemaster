import ast,copy,itertools,json,runpy,sys
root=sys.argv[1]
ns=runpy.run_path(root+'/scripts/evidence-verify')
module=ast.parse(open(root+'/scripts/evidence-verify').read())
fn=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='verified')
fn.body=ast.parse('with_check = entries; input_key = source_inputs').body+[n for n in fn.body if n.lineno>=1012]
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'<pinned-result>','exec'),ns)
check_events=[None,['merge_group','pull_request'],['merge_group'],['merge_group','pull_request'],None,['merge_group','pull_request']]
level_events=[None,['pull_request'],['pull_request'],None,['merge_group','pull_request'],['pull_request','merge_group']]
command=['run😀','quote"\\\n']
fixtures=[]
for mode,inputs,matched,source,separator in itertools.product(range(6),[None,{}, {'\ud800':'\udfff','face😀':'line\n','z':'tail'}],['a'*40,'b'*40],[None,'c'*64],['T','\ud800']):
    rule=dict(command=command)
    principal='agent/key'
    if level_events[mode] is not None:
        rule['by_level']={'host':dict(command=command,events=level_events[mode])}
        principal='host/key'
    entry=dict(trust_levels=['agent','host'],kinds=dict(wrapper=rule),max_age_s=60 if mode%2 else None,enforce=bool(mode%2),sample_one_in=mode+1)
    if check_events[mode] is not None: entry['events']=check_events[mode]
    policy=json.dumps(dict(version=1,checks=dict(unit=entry)))
    observed=dict(kind='tests',runner='wrapper',checks=dict(unit=dict(command=command,exit_code=0,output_sha256='0'*64)))
    if inputs is not None: observed['inputs']=inputs
    statement=dict(_type='https://in-toto.io/Statement/v1',predicateType='https://compounding.tech/fractal/evidence/gate/v1',subject=[dict(name=matched,digest=dict(gitTree=matched))],predicate=dict(schema_version=1,tier='full',change_id='change',signer=principal,observed_at='2026-01-01'+separator+'00:05:00Z',observed=observed))
    fixtures.append(dict(policy=policy,statement=json.dumps(statement),principal=principal,source=source,matched=matched))
failed=copy.deepcopy(fixtures[-1])
statement=json.loads(failed['statement'])
statement['predicate']['observed']['checks']['unit']['exit_code']=1
failed['statement']=json.dumps(statement)
fixtures.append(failed)
fixtures += [dict(fixture,policy=None,age=age) for fixture in list(fixtures) for age in (None,60)]
for fixture in fixtures:
    ns['entries']=[('record',json.loads(fixture['statement']),fixture['principal'])]
    ns['source_inputs']=fixture['source']
    rules=None if fixture['policy'] is None else ns['policy_rules'](fixture['policy'],'unit','owner/repo')
    try:
        result=ns['verified'](None,'a'*40,'unit',None,command if rules is not None else None,rules=rules,kinds=['wrapper'],max_age=fixture.get('age'),now=ns['parse_time']('2026-01-01T00:05:00Z'),run_inputs={})
        fixture['wire']=[]
        for name,mode in itertools.product(['unit','\ud800','face😀'],range(3)):
            wire=dict(result,check=name)
            if mode==0:
                wire.pop('decided_by',None);wire.pop('skipped_newer',None)
            elif mode==2: wire['skipped_newer']=['other host level_not_accepted']
            fixture['wire'].append(json.dumps(wire,indent=2))
        for key in ('tier','observed_at','matched_tree'): result[key]=list(map(ord,result[key]))
        result['command']=[list(map(ord,arg)) for arg in result['command']]
        result['inputs']=[[list(map(ord,k)),list(map(ord,v))] for k,v in result['inputs'].items()]
        fixture['expected']=result
    except ns['Failure'] as e: fixture['expected']=dict(reason=e.reason)
raw_stdout = (json.dumps(fixtures) + '\n').encode()
import pathlib
h = runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
rows = [dict(input=h['json_recipe']({key: value for key, value in row.items() if key not in ('expected', 'wire')}),
             expected=h['identity'](row['expected']),
             wire=[h['identity'](wire) for wire in row.get('wire', [])]) for row in fixtures]
print(json.dumps(h['document'](rows, raw_stdout), separators=(',', ':')))
