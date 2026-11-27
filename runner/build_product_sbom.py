"""生成“仅产品组件”SBOM：排除 OS 系统包、容器基础镜像、ZooKeeper 等第三方中间件。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
ROOT = 'configured-path'
GATE = os.path.join(ROOT, 'reports', 'final', 'gate')
SRC = os.path.join(GATE, 'sbom_merged.json')
OUT = os.path.join(GATE, 'sbom_product.json')
CDX = os.path.join(GATE, 'sbom_product_cyclonedx.json')
PRODUCT_PREFIXES = ('/hst/tmp/fsp-base-', '/hst/tmp/ces_linux', '/hst/meeting/IceDBProxy', '/hst/paas/fsp-boss', '/hst/deploy/')

def main():
    data = json.load(open(SRC, encoding='utf-8'))
    (comps, seen) = ([], set())
    excluded = {}
    for c in data.get('components') or []:
        path = c.get('path') or c.get('location') or ''
        src = str(c.get('source') or '')
        is_product_path = any((path.startswith(p) for p in PRODUCT_PREFIXES))
        is_middleware_java = path.startswith('/hst/docker/overlay2/') and src.startswith('java')
        if not (is_product_path or is_middleware_java):
            key = '/'.join(path.split('/')[:4]) or 'unknown'
            excluded[key] = excluded.get(key, 0) + 1
            continue
        key = (c.get('name'), c.get('version'), path)
        if key in seen:
            continue
        seen.add(key)
        comps.append(c)
    out = {'generated_at': data.get('generated_at'), 'scope': 'product', 'product_prefixes': list(PRODUCT_PREFIXES), 'count': len(comps), 'excluded': excluded, 'components': comps}
    json.dump(out, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    cdx = {'bomFormat': 'CycloneDX', 'specVersion': '1.4', 'version': 1, 'components': []}
    for c in comps:
        (name, ver) = (str(c.get('name') or ''), str(c.get('version') or ''))
        if not name or not ver:
            continue
        item = {'type': 'library', 'name': name, 'version': ver}
        if ':' in name:
            (g, a) = name.split(':', 1)
            item['purl'] = f'pkg:maven/{g}/{a}@{ver}'
        else:
            item['purl'] = f'pkg:maven/unknown/{name}@{ver}'
        cdx['components'].append(item)
    json.dump(cdx, open(CDX, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('product components:', len(comps), '->', OUT)
    print('excluded buckets:', sorted(excluded.items(), key=lambda x: -x[1])[:8])
if __name__ == '__main__':
    main()
