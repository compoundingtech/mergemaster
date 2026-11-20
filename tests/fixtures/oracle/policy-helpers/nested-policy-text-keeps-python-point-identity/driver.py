import json,runpy,sys
assert json.load(sys.stdin) is None
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
p=lambda s:list(map(ord,s))
for name in ['\ud800','\udfff','a\ud800b','😀']:
 level='level/'+name
 fields=dict(command=[name,'{check}'],required_inputs=[name],bind_inputs={name:name},
             input_order={name:[name,'weak']},base_inputs={name:'.'},
             shard_inputs=dict(count=name,results=name,index=name),
             by_level={level:dict(command=[name,'{check}'],required_inputs=[name],bind_inputs={name:name},events=['pull_request'])})
 text=json.dumps(dict(version=1,checks={name:dict(kinds=dict(wrapper=fields),trust_levels=[level])}))
 r=v['policy_rules'](text,name,'org/repo'); k=r['kinds']['wrapper']; l=k['by_level'][level]
 expected=dict(level=p(r['trust_levels'][0]),command=[p(s) for s in k['command']],
   required=[p(s) for s in k['required_inputs']],bind=[[p(a),p(b)] for a,b in k['bind_inputs'].items()],
   order=[[p(a),[p(b) for b in bs]] for a,bs in k['input_order'].items()],
   base=[[p(a),b] for a,b in k['base_inputs'].items()],
   shard=[p(k['shard_inputs'][a]) for a in ['count','results','index']],
   by_level=p(level),level_command=[p(s) for s in l['command']],
   level_required=[p(s) for s in l['required_inputs']],level_bind=[[p(a),p(b)] for a,b in l['bind_inputs'].items()])
 cases.append(dict(text=text,name=p(name),expected=expected))
print(json.dumps(cases))
