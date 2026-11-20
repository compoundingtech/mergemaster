import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule in json.load(sys.stdin):
    try:
        command, required, bind = oracle['checked_command_inputs'](rule, 'fixture')
        base = oracle['checked_base_inputs'](rule, 'fixture')
        results.append(dict(command=command, required_inputs=required, bind_inputs=bind, base_inputs=base))
    except (oracle['Failure'], KeyError):  # Missing command reaches the CLI's error handler.
        results.append({'reason': 'error'})
print(json.dumps(results))
