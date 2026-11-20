
import json,math,runpy,struct,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
def lossless(value):
 if value is None: return ['null']
 if isinstance(value,bool): return ['bool',value]
 if isinstance(value,int): return ['int',str(value)]
 if isinstance(value,float) and math.isnan(value): return ['nan']
 if isinstance(value,float): return ['float',struct.unpack('>Q',struct.pack('>d',value))[0]]
 if isinstance(value,str): return ['str',[ord(c) for c in value]]
 if isinstance(value,list): return ['list',[lossless(v) for v in value]]
 return ['dict',[[[ord(c) for c in k],lossless(v)] for k,v in value.items()]]
out=[]
for text in json.load(sys.stdin):
 try:
  d=json.loads(text)
  if not isinstance(d,dict) or set(d)!={'version','checks'} or d['version']!=1 or not isinstance(d['checks'],dict): raise ValueError()
  names=sorted(d['checks']); values=[]
  if names==['\ud800'] and isinstance(d['checks'][names[0]],dict):
   assert v['require_all']('/not-a-repo','tree','/absent',text,'org/repo')=={'mode':'require-all','tree':'tree','satisfied':True,'decision':'ok','lanes':{}}
  for k in names:
   value=d['checks'][k]
   # Preserve only the original unselected huge-float syntax fixture's skip.
   values.append(None if k=='ignored' and text.find('1e1000')!=-1 else lossless(value))
  out.append({'names':[[ord(c) for c in k] for k in names],'values':values})
 except ValueError: out.append(None)
print(json.dumps(out))
