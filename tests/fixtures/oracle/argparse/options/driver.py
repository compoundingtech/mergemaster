
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify'))
def capture(self,argv):
 actions=[]
 for a in self._actions:
  action='Integer' if a.type is int else {'_HelpAction':'Help','_StoreAction':'Store','_StoreTrueAction':'Flag','_AppendAction':'Append'}[type(a).__name__]
  actions.append(dict(name=a.option_strings[-1],aliases=a.option_strings,dest=a.dest,metavar=None if action in ('Help','Flag') else a.metavar or a.dest.upper(),help=a.help or '',action=action,nargs=a.nargs,default=a.default,required=a.required,group=next((i for i,g in enumerate(self._mutually_exclusive_groups) if a in g._group_actions),None)))
 print(json.dumps(dict(description=self.description,actions=actions,groups=[g.required for g in self._mutually_exclusive_groups])))
 raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture
v['main']([])
