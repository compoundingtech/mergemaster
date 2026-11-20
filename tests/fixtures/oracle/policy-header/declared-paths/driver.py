import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for case in json.load(sys.stdin):
    try:
        paths = oracle['declared_paths'](case['value'], 'fixture', case['selectors'])
        results.append({'paths': paths})
    except oracle['Failure'] as failure:
        results.append({'reason': failure.reason})
print(json.dumps(results))
