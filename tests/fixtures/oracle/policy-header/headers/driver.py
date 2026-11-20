import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for text in json.load(sys.stdin):
    try:
        header = oracle['policy_rules'](text, 'unit', 'fixture/repo')
        del header['kinds']
        if header['max_age_s'] is not None: header['max_age_s']=str(header['max_age_s'])
        results.append(header)
    except oracle['Failure'] as failure:
        results.append({'reason': failure.reason})
print(json.dumps(results))
