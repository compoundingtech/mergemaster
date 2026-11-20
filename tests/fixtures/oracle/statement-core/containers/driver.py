
import json,runpy,struct,sys
assert sys.version_info[:3] == (3,14,7), sys.version
j=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
cases=[b'-0',b'',b'[]',b'{}',b'[{},[],true,null,1.5]',b'{"b":1,"a":2,"b":3}',
 b'{"x":[],"x":{}}',br'{"\ud800":1,"\ud800":2,"\udfff":3}',
 br'{"x":[NaN,Infinity,-Infinity,"\ud800"]}',b'[1,]',b'{"a":1,}',
 b'[1 2]',b'{"a" 1}',b'{"a":}',b'{1:2}',b'[,1]',b'{,}',b'[}',b'{]',
 b'[',b'{"a":',b'[truefalse]',b'01',b'{}[]',b'null?',b'[]x',b'[]\xff',
 b'{} '+b'9'*4301,b' [0] \t\r\n',b'"hello"',b'false']
# Syntax fixtures exercise the accelerated scanner used by the pinned oracle.
texts=[' ', '\n\t', '{', '{ ', '[ ', '{"a"', '{"a" ', '{"a": ',
 '[1', '[1 ', '[1,', '{"a":1,', '[1, ]', '{"a":1, }',
 '{"a":}', '{"a": ]', '{"a",1}', '{"a":1 "b":2}', '{"a":1 "',
 '{?', '{1', '{NaN', '{9'+'9'*4300, '[1 "',
 '"', '"abc', '"abc\\', '"\\q"', '"\\u"', '"\\u12"',
 '"\\u12g4"', '"\\u１２３４"', '"\\ud800\\u12g4"',
 '"a\nb"', '"a\x00b"', '"a\tb"', '["🌍",\n {"é": ?}]',
 '["🌍",\n {"é" ?}]', '["🌍",\n 1, ]', '"🌍" ?',
 '"\ud800" ?', '["\udfff",\n?]', '"🌍\\q"', '"🌍\\u12g4"',
 '0.', '0.e1', '1e', '1e+', '1e-', '-1.e2', '-',
 '-NaN', '--1', '+1', '00', '-01', '[01]', '[1.]', '[1e+]',
 '{"a":1e}', '[truefalse]', 'null?', '[] "unterminated',
 '{"a":1} '+'9'*4301, '\u00a0null']
for control in range(32): texts.append('"🌍'+chr(control)+'"')
for text in ['"🌍" ?', '["é",\n?]', '"\\ud800\\u12g4"']:
 for encoding in ['utf-8-sig','utf-16-le','utf-16-be','utf-32-le','utf-32-be']:
  cases.append(text.encode(encoding,'surrogatepass'))
cases.extend(text.encode('utf-8','surrogatepass') for text in texts)
for depth in [2000,50000]: cases.append(b'['*depth+b'0'+b']'*depth)
cases.append(b'{"k":'*2000+b'null'+b'}'*2000)
results=[]
for blob in cases:
 depth=0
 try:
  value=j.loads(blob); flat=[]; stack=[(value,1)]
  while stack:
   v,d=stack.pop()
   if isinstance(v,(list,dict)): depth=max(depth,d)
   if isinstance(v,list): flat.append(['array',len(v)]); stack.extend((c,d+1) for c in reversed(v))
   elif isinstance(v,dict):
    flat.append(['object',[list(map(ord,k)) for k in v]]); stack.extend((c,d+1) for c in reversed(v.values()))
   elif v is None: flat.append(['null'])
   elif isinstance(v,bool): flat.append(['bool',v])
   elif isinstance(v,int): flat.append(['integer',str(v)])
   elif isinstance(v,float): flat.append(['float',struct.pack('>d',v).hex()])
   else: flat.append(['string',list(map(ord,v))])
  result=['ok',flat]
 except j.JSONDecodeError as e: result=['syntax',e.msg,e.pos,e.lineno,e.colno,str(e)]
 except UnicodeError: result=['encoding']
 except RecursionError: result=['recursion']
 results.append(dict(bytes=list(blob),result=result,depth=depth))
import pathlib
h=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
raw_stdout=(json.dumps(results)+'\n').encode()
rows=[dict(input=h['recipe'](bytes(row['bytes'])),result=h['identity'](row['result']),
           depth=row['depth'],result_kind=row['result'][0]) for row in results]
print(json.dumps(h['document'](rows,raw_stdout),separators=(',',':')))
