
import json,re,sys
assert sys.version_info[:3] == (3,14,7), sys.version
texts=['?', '-', '-NaN', '+1', 'nul', '"', '"abc', '"abc\\',
 '"\\q"', '"\\u"', '"\\u12"', '"\\u12g4"', '"\\u１２３４"',
 '"\\ud800\\u12g4"', '"\\ud800\\u"', '"\\ud800\\udc00',
 ' \n"🌍\\q"', ' \r\n"🌍\\u12g4"', '"\ud800\\q"',
 '0.', '1e', '1e+', '1e-', '-1.e2', '01', '-01', '1.2e+',
 '1.2', '1E+2', '-0', 'Infinityx', '-Infinityx', 'nulltrue']
texts.extend('"🌍'+chr(control)+'"' for control in range(32))
results=[]
for text in texts:
 try:
  _,end=json.JSONDecoder().raw_decode(text,re.match(r'[ \t\r\n]*',text).end())
  result=['ok',end]
 except json.JSONDecodeError as e:
  result=['syntax',e.msg,e.pos,e.lineno,e.colno,str(e)]
 results.append(dict(bytes=list(text.encode('utf-8','surrogatepass')),result=result))
print(json.dumps(results))
