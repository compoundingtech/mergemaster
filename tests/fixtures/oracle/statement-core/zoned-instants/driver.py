
import datetime,json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
cases=['0001-01-01T00:00:00+23:59:59.999999',
 '9999-12-31T23:59:59.999999-23:59:59.999999',
 '9999-12-30T24:00Z','9999-12-31T24:00Z',
 '1969-12-31T23:59:59.999999Z','1970-01-01T00:00:00Z',
 '2026-01-01\ud80012:30Z','2026-01-01🌍12:30Z','2026-01-01Z12:30Z',
 '2026-01-01','2026-01-01T12:30','2026-W01','0000-01-01T00:00Z',
 '2026-01-01T24:00:00.000001Z','2026-01-01T24:00:00.0000009Z',
 '2026-01-01T12:30:00+00:00:00.000001',
 '2026-01-01T12:30:00-00:00:00.000001',
 '2026-01-01T12:30:00+00:00:00.999999','2026-01-01T12:30:00-00:00:00.999999']
for date in ['2026-01-01','20260101','2026-W01-4','2026W014','2026-W01','2026W01']:
 for clock in ['12','1230','12:30','123045','12:30:45','12:30:45.123456789','12:30:45,0000009','24:00']:
  for offset in ['Z','+01','-0130','+01:02:03.123456789','-00:00:00.000001','+00:60','+24:00']:
   cases.append(date+'T'+clock+offset)
out=[]
for text in cases:
 try:
  d=o['parse_time'](text); offset=d.utcoffset()
  if offset is None: result=None
  else:
   local=d.replace(tzinfo=None)-datetime.datetime(1970,1,1)
   result=((local.days*86400+local.seconds)*1000000+local.microseconds
           -(offset.days*86400+offset.seconds)*1000000-offset.microseconds)
 except (ValueError,OverflowError): result=None
 out.append(([ord(c) for c in text],result))
assert out[0][1]==-62135683199999999 and out[1][1]==253402387199999998
assert out[3][1] is None and out[4][1]==-1 and out[5][1]==0
assert out[6][1]==out[7][1] and out[14][1] is not None
print(json.dumps(out))
