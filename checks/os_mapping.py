"""多发行版 CVE 生态映射：Kylin/openEuler/CentOS/UOS/Debian/Ubuntu → OSV ecosystem。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAP = os.path.join(ROOT, 'knowledge', 'os_cve_mapping.yaml')

def mapping():
    if not os.path.exists(MAP):
        return {}
    return (yaml.safe_load(open(MAP, encoding='utf-8')) or {}).get('distros') or {}

def ecosystem_for(distro, version=''):
    """返回 (ecosystem, confidence, note)；无映射返回 (None, 'unknown', note)。"""
    distro = str(distro or '').lower()
    version = str(version or '')
    for (_, info) in mapping().items():
        if any((m.lower() in distro for m in info.get('match') or [])):
            eco = None
            by = info.get('ecosystems_by_version') or {}
            if by:
                for (v, e) in by.items():
                    if version.startswith(str(v)):
                        eco = e
                        break
                eco = eco or info.get('default')
            else:
                eco = (info.get('ecosystems') or [None])[0]
            return (eco, info.get('confidence', 'unknown'), info.get('note', ''))
    return (None, 'unknown', '无 OSV 生态映射，需厂商 CVE 库/人工确认')
if __name__ == '__main__':
    for (d, v) in (('openEuler', '22.03'), ('Kylin', '10'), ('CentOS', '7.9'), ('UOS', '20'), ('Debian', '11')):
        print(d, v, '->', ecosystem_for(d, v))
