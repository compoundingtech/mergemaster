
import argparse,json,os,pathlib,re,runpy,subprocess,sys
assert sys.version_info[:3]==(3,14,7)
oracle=str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')
base=['--tree','x']; samples=[[],['--help'],['-h'],['-hh'],['-hx'],['-h=foo'],['-h-'],['--help=x'],['--tr'],['--tree'],['--tree','--tr'],['--tree=x','--revision=y'],['--revision=x','--tree=y'],base+['--unknown'],base+['--unknown','--max-age','bad'],base+['--max-age','bad'],base+['--max-age','1'*4301],base+['--project=yes'],base+['--'],base+['foo','bar']]
v=runpy.run_path(oracle); captured=[]; original=argparse.ArgumentParser.parse_args
argparse.ArgumentParser.parse_args=lambda self,argv:captured.append(self)
try: v['main']([])
except AttributeError: pass
finally: argparse.ArgumentParser.parse_args=original
for a in captured[0]._actions:
 flag=a.option_strings[-1]
 samples += [base+[flag+'='],base+[flag+'=x'],base+[flag],base+[flag,'--unknown']]
for group in captured[0]._mutually_exclusive_groups:
 a,b=group._group_actions
 samples += [base+[a.option_strings[-1],'a',b.option_strings[-1],'b'],base+[b.option_strings[-1],'b',a.option_strings[-1],'a']]
samples += [base+['--unknown'+c] for c in ['\x1b[31m\r\x07\x85é','\udc80','\n','\\']]
# Invoke the actual script, intercepting parse_args only after original parsing
# to stop successful namespaces before any Git/preflight operations.
wrapper='''
import argparse,runpy,sys
class Parsed(Exception): pass
p=argparse.ArgumentParser.parse_args
def parse(self,argv):
 p(self,argv)
 raise Parsed()
argparse.ArgumentParser.parse_args=parse
sys.argv=[sys.argv[1]]+sys.argv[2:]
try: runpy.run_path(sys.argv[0],run_name="__main__")
except Parsed: sys.exit(99)
'''
rows=[]
for argv in samples:
 env=dict(os.environ,NO_COLOR='1',TERM='dumb',COLUMNS='80'); env.pop('FORCE_COLOR',None)
 r=subprocess.run([sys.executable,'-I','-c',wrapper,oracle]+argv,env=env,capture_output=True)
 assert r.returncode in (0,2,99),(argv,r.stderr)
 rows.append(dict(argv=[list(map(ord,s)) for s in argv],parsed=r.returncode==99,stdout=list(r.stdout),stderr=list(r.stderr),exit=r.returncode))
 if argv in ([],['--help']):
  colored=dict(env,FORCE_COLOR='1',TERM='xterm'); colored.pop('NO_COLOR')
  c=subprocess.run([sys.executable,'-I','-c',wrapper,oracle]+argv,env=colored,capture_output=True)
  assert b'\x1b[' in c.stdout+c.stderr
  strip=lambda s:re.sub(rb'\x1b\[[0-9;]*m',b'',s)
  assert (strip(c.stdout),strip(c.stderr),c.returncode)==(r.stdout,r.stderr,r.returncode)
assert len(rows)==len(samples)
raw_stdout=(json.dumps(rows)+'\n').encode()
h=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
compact=[dict(row,argv=h['json_recipe'](row['argv']),stdout=h['identity'](row['stdout'])) for row in rows]
print(json.dumps(h['document'](compact,raw_stdout),separators=(',',':')))
