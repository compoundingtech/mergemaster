
import argparse,json,pathlib,runpy,sys
assert sys.version_info[:3]==(3,14,7)
v=runpy.run_path(str(pathlib.Path(sys.argv[1])/'scripts/evidence-verify'))
rows=[]
def capture(self,argv):
 for width in [0,1,10,20,30,40,60,78,100,200,1000]:
  for prog in ['evidence-verify','','é😀','x'*90,'x\ny','x\n\n\ny','\udc80']:
   self.prog=prog
   self.formatter_class=lambda prog:argparse.HelpFormatter(prog,width=width)
   rows.append(dict(width=width,prog=list(map(ord,prog)),usage=list(map(ord,self.format_usage()))))
 print(json.dumps(rows)); raise SystemExit(0)
argparse.ArgumentParser.parse_args=capture
v['main']([])
