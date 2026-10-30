#!/usr/bin/env python3
"""Copy original sparse-test inputs and lane-layout witnesses from the pinned tree."""
import json
from pathlib import Path
import shutil
import sys

source, destination = map(Path, sys.argv[1:])
files = sorted(path.relative_to(source).as_posix() for path in source.rglob('*')
               if path.is_file() or path.is_symlink())
file_set = set(files)
policy = json.loads((source / '.st/evidence-skip-policy.json').read_text())
lanes = json.loads((source / '.st/required-lanes.json').read_text())['lanes']
# Preserve the original ci-script-tests sparse tree and complete web detector
# coverage, plus the code that defines each lane. These are source witnesses,
# not tests that this extraction adds to the moving suite.
inputs = set(policy['checks']['ci-script-tests']['inputs']) | {'apps/fractal-web'}
inputs.update(path.split('::', 1)[0] for lane in lanes.values()
              for path in lane.get('definition_paths', []))
for check in policy['checks'].values():
    for path in check.get('inputs', []):
        if path in file_set:
            inputs.add(path)
        else:
            # Other lanes assert that their declared input directories exist;
            # one genuine source member is enough for that assertion.
            witness = next((name for name in files if name.startswith(path + '/')), None)
            if witness is not None:
                inputs.add(witness)
selected = set()
for path in inputs:
    if path in file_set:
        selected.add(path)
    else:
        selected.update(name for name in files if name.startswith(path + '/'))
for name in sorted(selected):
    target = destination / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / name, target, follow_symlinks=False)
print(f'Prepared {len(selected)} original Fractal input files from the pinned source')
