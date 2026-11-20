
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for kinds in json.load(sys.stdin):
    try:
        policy = dict(version=1, checks=dict(check=dict(kinds=kinds, trust_levels=['agent'])))
        results.append(oracle['policy_rules'](json.dumps(policy), 'check', 'owner/{check}'))
    except (oracle['Failure'], TypeError, AttributeError, KeyError):
        results.append(dict(reason='error'))
print(json.dumps(results))
