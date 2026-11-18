//! Owned caller restrictions after the original main preflight, before any I/O.
use super::{
    argparse_parse::ParsedArguments,
    inputs::AgeLimit,
    statement_document::{Document, Node},
    value_inputs::TextRef,
};

pub struct Options {
    pub command: Option<Vec<Vec<u32>>>,
    pub kinds: Vec<Vec<u32>>,
    pub trust: Option<Vec<Vec<u32>>>,
    pub prefer: Option<Vec<Vec<u32>>>,
    pub runner: Option<Vec<u32>>,
    pub age: Option<AgeLimit>,
    pub bindings: Vec<(Vec<u32>, Vec<u32>)>,
}
fn list(text: TextRef<'_>) -> Vec<Vec<u32>> {
    let mut rest = text;
    let mut result = Vec::new();
    loop {
        let (item, next) = rest
            .split_once(",")
            .map_or((rest, None), |(a, b)| (a, Some(b)));
        if !item.equals("") {
            result.push(item.points().collect());
        }
        let Some(next) = next else {
            return result;
        };
        rest = next;
    }
}
impl Options {
    pub fn read(args: &ParsedArguments<'_>) -> Result<Self, &'static str> {
        args.preflight()?;
        let command = args
            .value("--command")
            .map(|text| {
                let doc = match text {
                    TextRef::Str(s) => Document::from_text(s),
                    TextRef::Points(p) => Document::from_points(p.to_vec()),
                }
                .map_err(|_| "--command must be a JSON array of strings")?;
                let Node::Array(items) = doc.root() else {
                    return Err("--command must be a JSON array of strings");
                };
                items
                    .iter()
                    .map(|id| match doc.node(*id) {
                        Node::String(s) => Ok(s.clone()),
                        _ => Err("--command must be a JSON array of strings"),
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let bindings = args
            .appended("--bind-input")
            .iter()
            .map(|item| {
                let (key, path) = item
                    .split_once("=")
                    .ok_or("--bind-input must be KEY=PATH")?;
                Ok((key.points().collect(), path.points().collect()))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            command,
            kinds: list(
                args.value("--kinds")
                    .unwrap_or(TextRef::Str("nix,wrapper,sekrets,observed")),
            ),
            trust: args.value("--trust-levels").map(list),
            prefer: args.value("--prefer-levels").map(list),
            runner: args.value("--runner-prefix").map(|s| s.points().collect()),
            age: args.max_age.as_ref().map(|n| {
                n.digits
                    .parse()
                    .map_or(AgeLimit::Overflow, AgeLimit::Seconds)
            }),
            bindings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restrictions_match_original_main_values() {
        let script = r#"
import ast,json,pathlib,runpy,sys
p=pathlib.Path(__import__('os').environ['MERGEMASTER_PYTHON_ORACLE'])/'scripts/evidence-verify';v=runpy.run_path(str(p));m=ast.parse(p.read_text());f=next(n for n in m.body if isinstance(n,ast.FunctionDef) and n.name=='main')
i=next(i for i,n in enumerate(f.body) if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='keyfile')
f.body=f.body[:i]+ast.parse('return dict(command=command,kinds=kinds,trust=trust_levels,prefer=prefer_levels,runner=args.runner_prefix,age=args.max_age,bindings=bind)').body
exec(compile(ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[])),str(p),'exec'),v)
cases=[[],['--command','["true","\\ud800","é"]'],['--kinds',',wrapper,,nix,wrapper,'],['--trust-levels',',agent,,raw'+chr(0xdcff)],['--prefer-levels','host,agent'],['--runner-prefix','raw'+chr(0xdcff)],['--max-age','９_０'],['--max-age','9'*100],['--bind-input','raw'+chr(0xdcff)+'=path=tail','--bind-input','x='+chr(0xdcff)]]
for extra in cases:
 argv=['--tree','0'*40,'--check','x','--keys','unused',*extra];result=v['main'](argv)
 def points(s): return list(map(ord,s))
 for k in ['command','kinds','trust','prefer']:
  if result[k] is not None:result[k]=[points(s) for s in result[k]]
 if result['runner'] is not None:result['runner']=points(result['runner'])
 result['bindings']=[[points(k),points(p)] for k,p in result['bindings']]
 if result['age'] is not None: result['age']=str(result['age'])
 print(json.dumps(dict(argv=[points(s) for s in argv],value=result)))
"#;
        let out = crate::pinned_python::command()
            .args(["-c", script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        for line in String::from_utf8(out.stdout).unwrap().lines() {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            let owned: Vec<Vec<u32>> = serde_json::from_value(row["argv"].clone()).unwrap();
            let argv: Vec<_> = owned.iter().map(|p| TextRef::Points(p)).collect();
            let super::super::argparse_parse::ParseOutcome::Parsed(args) =
                super::super::argparse_parse::parse(&argv).ok().unwrap()
            else {
                panic!()
            };
            let options = Options::read(&args).unwrap();
            let age = options.age.map(|a| match a {
                AgeLimit::Seconds(n) => n.to_string(),
                AgeLimit::Overflow => args.max_age.as_ref().unwrap().digits.clone(),
            });
            assert_eq!(
                serde_json::json!({"command":options.command,"kinds":options.kinds,"trust":options.trust,"prefer":options.prefer,"runner":options.runner,"age":age,"bindings":options.bindings}),
                row["value"]
            );
        }
    }
}
