import ast, json, runpy, sys
root = sys.argv[1]
policy, cases = json.load(sys.stdin)
ns = runpy.run_path(root + '/scripts/evidence-verify')
rules = ns['policy_rules'](policy, 'unit', 'owner/repo')
module = ast.parse(open(root + '/scripts/evidence-verify').read())
verified = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'verified')
body = [n for n in verified.body if 1012 <= n.lineno <= 1048]
body += ast.parse("return dict(commits=[c[0] for c in with_check], attempts=attempts, accepted=sorted(accepted))").body
fn = ast.FunctionDef(name='probe', args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=n) for n in ('with_check','rules','check')], kwonlyargs=[], kw_defaults=[], defaults=[]), body=body, decorator_list=[])
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<pinned-prelude>', 'exec'), ns)
actual = []
for case in cases:
    entries = [('a' if i == 0 else 'b', json.loads(s), 'agent/key') for i,s in enumerate(case)]
    try: actual.append(ns['probe'](entries, rules, 'unit'))
    except ns['Failure'] as e: actual.append(dict(reason=e.reason, detail=str(e), attempts=e.extra['attempts']))
print(json.dumps(actual))
