import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
reasons = []
payload = json.load(sys.stdin)
for original, parsed in zip(payload['original'], payload['parsed']):
    for base in (original['base_inputs'], parsed):
        try:
            oracle['value_checks']({'base_inputs': base}, {'z': 'wrong'}, {'z': 'expected'}, 1)
        except oracle['Failure'] as failure:
            reasons.append(failure.reason)
print(json.dumps(reasons))
