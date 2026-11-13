"""Verify two retained public/fixed-core schema-163 parity certificates."""
from __future__ import annotations
import argparse,json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from epm_core.postgres_schema163_functional_parity import verify_pair

def main()->None:
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--left',type=Path,required=True);p.add_argument('--right',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 result=verify_pair(json.loads(a.left.read_text()),json.loads(a.right.read_text()))
 a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'output':str(a.output.resolve()),'equal':True,
  'activationAuthorized':False}))
if __name__=='__main__':main()
