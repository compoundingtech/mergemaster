import json, runpy, sys
oracle, rule = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify'), json.load(sys.stdin)
_, _, binds = oracle['checked_command_inputs'](rule, 'fixture')
base = oracle['checked_base_inputs'](rule, 'fixture')
order, _ = oracle['checked_value_rules'](rule, 'fixture')
print(json.dumps([list(value.items()) for value in (binds, base, order)]))
