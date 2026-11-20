
import json,runpy,sys
assert sys.version_info[:3]==(3,14,7)
j=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']; rows=[]
def add(raw,resource=None,nodes=None):
 j.loads(raw) # Real oracle accepts every below/above-bound fixture.
 rows.append(dict(raw=raw,resource=resource,nodes=nodes))
for extra in [0,1]:
 raw='"'+'é'*524287+'"'+(' '*extra)
 assert len(raw.encode())==1048576+extra
 add(raw,'SourceBytes' if extra else None,1)
 for opening,closing,empty in [('[',']','[]'),('{"k":','}','{}'),('[{"k":','}]','[]')]:
  depth=256+extra
  if opening=='[{"k":':
   pairs=(depth-1)//2; raw=opening*pairs+('[' if depth%2==0 else '')+empty+(']' if depth%2==0 else '')+closing*pairs
  else: raw=opening*(depth-1)+empty+closing*(depth-1)
  pending=[(j.loads(raw),1)]; observed=0
  while pending:
   value,d=pending.pop()
   if isinstance(value,(list,dict)):
    observed=max(observed,d); pending.extend((v,d+1) for v in (value.values() if isinstance(value,dict) else value))
  assert observed==depth
  add(raw,'ContainerDepth' if extra else None,depth)
 for prefix,suffix,item,overhead in [('[',']','0',1),('[',']','[]',1),('{"x":[','],"x":0}','0',3)]:
  raw=prefix+','.join([item]*(262144-overhead+extra))+suffix
  assert len(raw.encode())<1048576
  add(raw,'Nodes' if extra else None,262144+extra)
import pathlib
h=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
raw_stdout=(json.dumps(rows)+'\n').encode()
compact=[dict(input=h['recipe'](row['raw'].encode('utf-8')),
              resource=row['resource'],nodes=row['nodes']) for row in rows]
print(json.dumps(h['document'](compact,raw_stdout),separators=(',',':')))
