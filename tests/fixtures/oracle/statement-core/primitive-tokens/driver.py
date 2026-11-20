
import json,runpy,struct,sys
j=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
cases=[]
for name,text in {
 'null':'null','true':'true','false':'false','zero':'0','negative-zero':'-0','integer':'-123',
 'float':'1.25','float-negative-zero':'-0.0','exponent':'1E+2','overflow':'1e400','underflow':'-1e-400','rounding':'9007199254740993.0','rounding-int':'9007199254740993',
 'nan':'NaN','infinity':'Infinity','negative-infinity':'-Infinity','whitespace':' \t\r\n0 ',
 'empty-string':'""','escapes':r'"\u0000\b\f\n\r\t\"\\\/"',
 'high':r'"\ud800"','low':r'"\udfff"','pair':r'"\ud800\udc00"','nonpair':r'"\ud800\u0041"',
 'literal-backslash':r'"\\ud800"','bad-escape':r'"\x20"','bad-hex':r'"\u12g4"','unicode-hex':r'"\u１２３４"','truncated-string':'"abc',
 'leading-zero':'01','plus':'+1','missing-fraction':'1.','missing-exponent':'1e','double-sign':'--1',
 'negative-nan':'-NaN','word-suffix':'Infinityx','two-values':'nulltrue','unicode-space':'\u00a0null'
}.items(): cases.append((name,text.encode()))
for name,data in {'raw-high':'22eda08022','raw-pair':'22eda080edb08022','mixed-pair':'225c7564383030edb08022','raw-control':'220122','invalid-utf8':'ff'}.items():
 cases.append((name,bytes.fromhex(data)))
for encoding in ['utf-8-sig','utf-16-le','utf-16-be','utf-32-le','utf-32-be']:
 cases.append(('encoded-'+encoding,'"x🌍\ud800"'.encode(encoding,'surrogatepass')))
for n in [4300,4301]:
 cases.extend([('digits-'+str(n),b'9'*n),('float-digits-'+str(n),b'9'*n+b'e0')])
results=[]
for name,blob in cases:
 try:
  v=j.loads(blob)
  if v is None: value=['null']
  elif isinstance(v,bool): value=['bool',v]
  elif isinstance(v,int): value=['integer',str(v)]
  elif isinstance(v,float): value=['float',struct.pack('>d',v).hex()]
  else: value=['string',list(map(ord,v))]
 except ValueError: value=None
 results.append(dict(name=name,bytes=list(blob),value=value))
print(json.dumps(results))
