"""应用安全：URL 重定向（开放跳转）检查。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import re
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
KEYS = ['url', 'redirect', 'redirectUrl', 'next', 'returnUrl', 'callback', 'target']
PAYLOAD = 'https://evil.example/secauto'

def main():
    tok = gc.token('admin02')
    paths = [p for p in gc.all_endpoints() if '?' not in p][:20]
    (findings, tested) = ([], [])
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok}
    for path in paths:
        for key in KEYS:
            try:
                r = requests.get(BASE + path, headers=h, params={'t': str(int(time.time() * 1000)), key: PAYLOAD}, timeout=10, verify=False, allow_redirects=False)
            except Exception:
                continue
            loc = r.headers.get('Location', '')
            tested.append({'path': path, 'key': key, 'http': r.status_code, 'location': loc[:160]})
            if r.status_code in (301, 302, 303, 307, 308) and re.match('https?://evil\\.example', loc):
                findings.append(gc.finding('REDIRECT-OPEN', 'medium', f'开放重定向：{path} 参数 {key}', evidence=json.dumps(tested[-1], ensure_ascii=False)[:300], remediation='跳转白名单；禁止外部 URL'))
    gc.emit('open_redirect', 'application', 'PASS', findings, summary=json.dumps({'tested': len(tested)}, ensure_ascii=False)[:300])
if __name__ == '__main__':
    main()
