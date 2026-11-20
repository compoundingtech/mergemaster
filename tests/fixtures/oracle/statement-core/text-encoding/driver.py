
import json,sys
assert sys.version_info[:3]==(3,14,7)
cases=[]
for base in ['{}','0','"x"']:
 for encoding in ['utf-16-le','utf-16-be','utf-32-le','utf-32-be']:
  blob=base.encode(encoding);cases.append((blob.decode('latin1'),blob))
for text in ['{}','\ufeff{}','"\ufeff"',r'"\u0000"']:
 cases.append((text,text.encode()))
out=[]
for text,blob in cases:
 def accepts(value):
  try: json.loads(value);return True
  except ValueError:return False
 out.append(dict(text=text,bytes=list(blob),str_ok=accepts(text),bytes_ok=accepts(blob)))
print(json.dumps(out))
