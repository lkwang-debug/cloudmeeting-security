"""把合并 SBOM 导出为 CycloneDX，供 Grype/Trivy 扫描。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
ROOT = 'configured-path'
SRC = os.path.join(ROOT, 'reports', 'final', 'gate', 'sbom_merged.json')
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'sbom_cyclonedx.json')

def main():
    data = json.load(open(SRC, encoding='utf-8'))
    comps = []
    seen = set()
    for c in data.get('components') or []:
        name = str(c.get('name') or '')
        ver = str(c.get('version') or '')
        if not name or not ver:
            continue
        key = (name, ver)
        if key in seen:
            continue
        seen.add(key)
        src = str(c.get('source') or '')
        item = {'type': 'library', 'name': name, 'version': ver}
        if 'java-maven' in src and ':' in name:
            (g, a) = name.split(':', 1)
            item['purl'] = f'pkg:maven/{g}/{a}@{ver}'
        elif src:
            distro = 'openeuler-22.03' if 'container' in src else c.get('distro') or 'unknown'
            distro = str(distro).lower()
            item['purl'] = f'pkg:rpm/{distro}/{name}@{ver}?distro={distro}'
        comps.append(item)
    out = {'bomFormat': 'CycloneDX', 'specVersion': '1.4', 'version': 1, 'components': comps}
    json.dump(out, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('components:', len(comps), '->', OUT)
if __name__ == '__main__':
    main()
