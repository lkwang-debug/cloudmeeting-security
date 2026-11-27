"""从 JS chunk/知识库挖掘 H5 对象接口。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
ROOT = 'configured-path'
paths = set()
chunks = os.path.join(ROOT, 'tools_cache', 'chunks')
if os.path.isdir(chunks):
    for fn in os.listdir(chunks):
        if not fn.endswith('.js'):
            continue
        t = open(os.path.join(chunks, fn), encoding='utf-8', errors='replace').read()
        for m in re.finditer('/meeting-resource-server/[A-Za-z0-9_/${}.\\-]+', t):
            p = m.group(0).rstrip('"\'`,);')
            if len(p) < 120:
                paths.add(p)
for rel in ('knowledge/endpoints.json', 'knowledge/all_backend_endpoints.json'):
    p = os.path.join(ROOT, rel)
    if os.path.exists(p):
        t = open(p, encoding='utf-8', errors='replace').read()
        for m in re.finditer('/meeting-resource-server/[A-Za-z0-9_/${}.\\-]+', t):
            paths.add(m.group(0).rstrip('"\',);'))
out = sorted(paths)
open(os.path.join(ROOT, 'knowledge', 'h5_object_endpoints.json'), 'w', encoding='utf-8').write(json.dumps({'endpoints': out}, ensure_ascii=False, indent=1))
print(len(out))
for x in out[:80]:
    print(x)
