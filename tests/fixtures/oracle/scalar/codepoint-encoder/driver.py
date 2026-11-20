"""Capture exact stream identities and fixed-domain block diagnostics from the pin."""
import hashlib
import json
import runpy
import sys

oracle = runpy.run_path(sys.argv[1] + "/scripts/evidence-verify")["json"]
BLOCK = 4096
streams = []
for scalars_only in (False, True):
    def text(start, stop):
        return "".join(chr(point) for point in range(start, stop)
                       if not scalars_only or not 0xd800 <= point <= 0xdfff)

    raw = oracle.dumps(text(0, 0x110000)).encode() + b"\n"
    blocks = []
    for start in range(0, 0x110000, BLOCK):
        encoded = oracle.dumps(text(start, start + BLOCK)).encode()
        blocks.append({"start": start, "bytes": len(encoded),
                       "sha256": hashlib.sha256(encoded).hexdigest()})
    streams.append({"name": "scalars" if scalars_only else "codepoints",
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "blocks": blocks})
print(json.dumps({"block_codepoints": BLOCK, "streams": streams}, indent=2))
