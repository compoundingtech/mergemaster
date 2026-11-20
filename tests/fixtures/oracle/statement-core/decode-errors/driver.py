
import json,pathlib,random,runpy,sys
assert sys.version_info[:3]==(3,14,7)
samples=[bytes([i]) for i in range(256)]
for lead in [0xc0,0xc2,0xdf,0xe0,0xed,0xef,0xf0,0xf4,0xf5]:
 for second in range(256):
  for suffix in [b'',b'x',b'\x80',b'\xbf\x80']:
   samples.append(bytes([lead,second])+suffix)
rng=random.Random(735)
for bom in [b'',b'\xef\xbb\xbf',b'\xff\xfe',b'\xfe\xff',b'\xff\xfe\0\0',b'\0\0\xfe\xff']:
 for n in range(500):
  samples.append(bom+rng.randbytes(n%17))
for encoding,bom in [('utf-16-le',b'\xff\xfe'),('utf-16-be',b'\xfe\xff'),('utf-32-le',b'\xff\xfe\0\0'),('utf-32-be',b'\0\0\xfe\xff')]:
 for point in [0,0xd7ff,0xd800,0xdbff,0xdc00,0xdfff,0xe000,0x10ffff]:
  blob=bom+chr(point).encode(encoding,'surrogatepass')
  samples += [blob,blob+b'x',blob+b'\0']
cases=[]
for blob in samples:
 try: expected={'points':list(map(ord,blob.decode(json.detect_encoding(blob),'surrogatepass')))}
 except UnicodeDecodeError as e: expected={'error':str(e)}
 cases.append([list(blob),expected])
raw_stdout=(json.dumps(cases)+'\n').encode()
h=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
expected_pool=[]
expected_indices={}
rows=[]
for blob,expected in cases:
 key=json.dumps(expected,sort_keys=True,separators=(',',':'))
 if key not in expected_indices:
  expected_indices[key]=len(expected_pool)
  expected_pool.append(h['identity'](expected))
 rows.append(dict(input=h['recipe'](bytes(blob)),expected=expected_indices[key]))
print(json.dumps(h['document'](dict(cases=rows,expected=expected_pool),raw_stdout),separators=(',',':')))
