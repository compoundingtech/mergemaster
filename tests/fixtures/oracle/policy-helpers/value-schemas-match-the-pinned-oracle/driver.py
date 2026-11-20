import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule in json.load(sys.stdin):
    try:
        order, shards = oracle['checked_value_rules'](rule, 'fixture')
        results.append(dict(input_order=order, shard_inputs=shards))
    except (oracle['Failure'], TypeError):
        results.append({'reason': 'error'})
print(json.dumps(results))
