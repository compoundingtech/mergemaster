
import argparse,json,sys
assert sys.version_info[:3]==(3,14,7)
p=argparse.ArgumentParser(exit_on_error=False); action=p.add_argument('--max-age',type=int)
r=[]
for points in json.load(sys.stdin):
 text=''.join(map(chr,points))
 try:
  v=p._get_value(action,text); r.append(dict(negative=v<0,digits=str(abs(v))))
 except argparse.ArgumentError as e:
  try: int(text)
  except ValueError as cause: kind='limit' if str(cause).startswith('Exceeds the limit') else 'literal'
  r.append(dict(error=kind,diagnostic=e.message,complete=str(e)))
print(json.dumps(r))
