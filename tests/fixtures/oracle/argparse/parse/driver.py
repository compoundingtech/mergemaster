
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify')); original=argparse.ArgumentParser.parse_args; captured=[]
def capture(self,argv): captured.append(self); raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture; v['main']([]); argparse.ArgumentParser.parse_args=original
p=captured[0]; p.exit_on_error=False; base=['--tree','x']; samples=[base,['--revision','HEAD'],['--tr','x'],['--tree','-1suffix'],['--tree','-.５suffix'],['--tree','\udc80']]
samples += [base+['--max-age',s] for s in ['-0','+١_２','1'*4300]]
for a in p._actions:
 if a.dest not in ('help','tree','revision','max_age'): samples.append(base+[a.option_strings[-1]]*(2 if a.nargs==0 else 1)+([] if a.nargs==0 else ['first',a.option_strings[-1],'second']))
for group in p._mutually_exclusive_groups:
 a,b=group._group_actions; prefix=[] if group.required else base
 samples += [prefix+[first.option_strings[-1],'a',second.option_strings[-1],'b'] for first,second in [(a,b),(b,a)]]
def tag(x): return {'int':str(x)} if type(x) is int else list(map(ord,x)) if isinstance(x,str) else [list(map(ord,s)) for s in x] if isinstance(x,list) else x
rows=[]
for argv in samples:
 try: expected={'values':{k:tag(x) for k,x in vars(original(p,argv)).items()}}
 except argparse.ArgumentError as e: expected={'error':str(e)}
 rows.append(dict(argv=[list(map(ord,s)) for s in argv],**expected))
print(json.dumps(rows))
