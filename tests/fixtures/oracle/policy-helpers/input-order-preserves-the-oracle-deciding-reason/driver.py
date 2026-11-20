import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
originals, parsed_rules = json.load(sys.stdin)
reasons = []
for original, parsed in zip(originals, parsed_rules):
    for rule in (original, parsed):
        try:
            oracle['value_checks'](rule, {'z': 'wrong'}, {'z': 'strong'}, 1)
        except oracle['Failure'] as failure:
            reasons.append(failure.reason)
print(json.dumps(reasons))
