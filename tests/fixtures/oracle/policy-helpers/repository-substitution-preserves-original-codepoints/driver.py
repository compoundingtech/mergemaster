import json,os,pathlib,runpy,subprocess,sys
assert json.load(sys.stdin) is None
p=pathlib.Path(sys.argv[1])/'scripts/evidence-verify'
child='''import json,runpy,sys
v=runpy.run_path(sys.argv[1]); text,repository=json.load(sys.stdin); check='check'
k=v['policy_rules'](text,check,repository)['kinds']['wrapper']
def points(s): return list(map(ord,s))
print(json.dumps([list(map(points,k['command'])),points(k['runner_prefix']),list(map(points,k['by_level']['agent']['command']))],separators=(',',':')))
'''
rows=[]
for repository in ['org/repo','org/é','org/🦀','org/'+chr(0xdcff),'org/'+chr(0xdcc3)+chr(0xdca9),'org/{check}','org/\\\n\x1b', 'x'*10000]:
 for template in ['{repository}:{check}:{repository}','{check}/{repository}','literal']:
  text=json.dumps(dict(version=1,checks={'check':dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=[template,'{repository}'],runner_prefix=template,by_level=dict(agent=dict(command=[template,'{repository}'],events=['pull_request'])))))}))
  done=subprocess.run([sys.executable,'-I','-c',child,str(p)],input=json.dumps([text,repository]).encode(),capture_output=True)
  assert done.returncode==0 and not done.stderr
  rows.append([text,list(map(ord,repository)),list(done.stdout),list(done.stderr),done.returncode])
raw_stdout=(json.dumps(rows)+'\n').encode()
h=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
compact=[dict(input=h['json_recipe']([text,repository]),stdout=h['identity'](stdout),stderr=stderr,exit=code) for text,repository,stdout,stderr,code in rows]
print(json.dumps(h['document'](compact,raw_stdout),separators=(',',':')))
