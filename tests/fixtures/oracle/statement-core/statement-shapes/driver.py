
import json,runpy,sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
print(json.dumps([o['statement_of'](s.encode(),sys.argv[2]) is not None for s in json.load(sys.stdin)]))
