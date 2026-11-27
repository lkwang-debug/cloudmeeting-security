"""应用安全：NoSQL/LDAP/HTML 注入扩展（只读差分）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
PAYLOADS = [('nosql', '{"$ne": null}'), ('nosql', "' || '1'=='1"), ('ldap', '*)(uid=*)'), ('ldap', '*)(|(uid=*'), ('html', '<h1>secauto</h1>')]
ERR = ('nosql', 'mongo', 'ldap', 'syntax', 'invalid', 'exception', 'html')

def main():
    tok = gc.token('admin02')
    (findings, tested) = ([], [])
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    eps = [e for e in gc.endpoint_keys() if e.get('method') in ('GET', 'POST')][:10]
    for ep in eps:
        keys = (ep.get('query_keys') or []) + (ep.get('body_keys') or [])
        keys = [k for k in keys if k != 't'][:2]
        for key in keys:
            for (kind, pl) in PAYLOADS:
                body = {k: '' for k in keys}
                body[key] = pl
                try:
                    if ep['method'] == 'POST':
                        r = requests.post(BASE + ep['path'], headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=12, verify=False)
                    else:
                        r = requests.get(BASE + ep['path'], headers=h, params={'t': str(int(time.time() * 1000)), key: pl}, timeout=12, verify=False)
                except Exception:
                    continue
                text = (r.text or '')[:2000]
                low = text.lower()
                tested.append({'path': ep['path'], 'param': key, 'kind': kind, 'http': r.status_code, 'len': len(text)})
                if pl in text or any((s in low for s in ERR)):
                    if kind == 'html' and pl in text:
                        findings.append(gc.finding('HTML-INJECTION', 'medium', f"HTML 注入：{ep['path']} 参数 {key}", evidence=text[:250], remediation='输出编码'))
                    elif kind in ('nosql', 'ldap') and any((s in low for s in ERR)):
                        findings.append(gc.finding('NOSQL-INJECTION' if kind == 'nosql' else 'LDAP-INJECTION', 'high', f"{kind} 注入特征：{ep['path']} 参数 {key}", evidence=text[:250], remediation='参数化/转义/白名单'))
    gc.emit('injection_extended', 'application', 'PASS', findings, summary=json.dumps({'tested': len(tested)}, ensure_ascii=False)[:400])
if __name__ == '__main__':
    main()
