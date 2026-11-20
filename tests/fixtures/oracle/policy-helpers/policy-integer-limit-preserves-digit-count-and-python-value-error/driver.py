import json,runpy,sys
assert json.load(sys.stdin) is None
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');cases=[]
for digits in [4300,4301,5000]:
 for negative in [False,True]:
  for placement in ['ignored','age']:
   entry=dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=['run'])))
   checks=dict(check=entry)
   if placement=='age':entry['max_age_s']='TOKEN'
   else:checks['ignored']='TOKEN'
   decimal=('-' if negative else '')+'9'*digits
   text=json.dumps(dict(version=1,checks=checks)).replace('"TOKEN"',decimal)
   if digits>4300:
    try:json.loads(text)
    except ValueError as error:
     assert type(error) is ValueError
     assert str(error)==f'Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit'
    else:raise AssertionError('expected integer conversion limit')
   case=dict(text=text,digits=digits,limit=digits>4300)
   try:
    result=v['policy_rules'](text,'check','org/repo')
    case.update(accepted=True,seconds=None if result['max_age_s'] is None else str(result['max_age_s']))
   except v['Failure'] as error:
    case.update(accepted=False,reason=error.reason,detail=list(map(ord,error.detail)))
   cases.append(case)
print(json.dumps(cases))
