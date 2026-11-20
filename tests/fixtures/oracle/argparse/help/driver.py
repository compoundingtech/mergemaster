
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify'))
rows=[]
def capture(self,argv):
 for width in list(range(0,120))+[150,200,1000]:
  self.prog='evidence-verify'
  self.formatter_class=lambda prog:argparse.HelpFormatter(prog,width=width)
  rows.append(dict(width=width,help=self.format_help()))
 raw_stdout=(json.dumps(rows)+'\n').encode()
 h=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[4]/'oracle_digest.py'))
 compact=[dict(width=row['width'],help=h['identity'](row['help'])) for row in rows]
 print(json.dumps(h['document'](compact,raw_stdout),separators=(',',':'))); raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture
v['main']([])
