
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for overrides in json.load(sys.stdin):
    try:
        entry = dict(trust_levels=['agent'], kinds=dict(wrapper=dict(command=['true'], by_level=overrides)))
        policy = dict(version=1, checks=dict(check=entry))
        results.append(oracle['policy_rules'](json.dumps(policy), 'check', 'owner/{check}')['kinds']['wrapper']['by_level'])
    except (oracle['Failure'], TypeError):
        results.append(dict(reason='error'))
print(json.dumps(results))
