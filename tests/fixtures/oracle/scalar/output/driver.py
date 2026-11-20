
import runpy,sys
json=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
cases=[{},[],{'z':[], '\ud800😀':[True,False,None,-170141183460469231731687303715884105728,{'empty':{},'s':'quote"\\\n'}]}, [[[]],{}]]
for value in cases: print(json.dumps(value,indent=2))
