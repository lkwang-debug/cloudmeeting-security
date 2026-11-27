"""资产清单：目标 URL、主机/端口、Web/登录入口（报告模板使用）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()

def main():
    (entries, probes) = ([], [])
    for (path, name) in (('/ui/login', '管理端登录'), ('/webapp/', 'H5/客户端'), ('/meeting-resource-server/oauth2/token', 'OAuth2 Token')):
        try:
            r = requests.get(BASE + path, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            probes.append({'path': path, 'http': r.status_code, 'len': len(r.text or '')})
            if r.status_code in (200, 302, 401, 403):
                entries.append({'name': name, 'url': BASE + path, 'http': r.status_code})
        except Exception as e:
            probes.append({'path': path, 'error': str(e)[:80]})
    data = {'target': BASE, 'hosts': [h.strip() for h in os.environ.get('GATE_ASSET_HOSTS', '' + _pub.shell('SEC_DB_HOST') + ',' + _pub.shell('SEC_DB_HOST') + '').split(',') if h.strip()], 'ports': [28443, 22, 22002, 22003, 22007, 25672], 'web_entries': entries, 'probes': probes}
    gc.emit('asset_inventory', 'application', 'PASS', [], summary=json.dumps(data, ensure_ascii=False)[:1500])
if __name__ == '__main__':
    main()
