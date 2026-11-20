
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');cases=[]
for literal in ['0','-0','0.0','-0.0','0e5']:
 entry=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'],by_level='TOKEN')))
 text=json.dumps(dict(version=1,checks=dict(check=entry))).replace('"TOKEN"',literal)
 rules=v['policy_rules'](text,'check','org/repo')
 assert rules['kinds']['wrapper']['by_level']=={}
 value=json.loads(literal)
 cases.append(dict(literal=literal,text=text,integer=type(value) is int))
print(json.dumps(cases))
