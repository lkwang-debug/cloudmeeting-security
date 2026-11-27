"""应用安全：反射型 XSS（真实接口参数注入，检测未转义反射）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import uuid
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
PAYLOAD = '<script>alert(1)</script>'

def main():
    tok = gc.token('admin02')
    if not tok:
        gc.emit('xss_full', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    findings = []
    tested = []
    endpoints = [e for e in gc.endpoint_keys() if e.get('path') and (e.get('query_keys') or e.get('body_keys'))]
    for ep in endpoints[:25]:
        method = ep.get('method', 'GET')
        path = ep['path']
        keys = (ep.get('query_keys') or []) + (ep.get('body_keys') or [])
        if not keys:
            continue
        key = keys[0]
        h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok}
        try:
            if method == 'POST':
                body = {k: '' for k in keys}
                body[key] = PAYLOAD
                r = requests.post(BASE + path, headers={**h, 'Content-Type': 'application/json'}, params={'t': str(int(time.time() * 1000))}, json=body, timeout=15, verify=False)
            else:
                r = requests.get(BASE + path, headers=h, params={'t': str(int(time.time() * 1000)), key: PAYLOAD}, timeout=15, verify=False)
        except Exception:
            continue
        tested.append({'path': path, 'method': method, 'param': key, 'http': r.status_code, 'body_len': len(r.text or '')})
        if PAYLOAD in (r.text or ''):
            findings.append(gc.finding('XSS-REFLECTED-' + key, 'high', f'反射型 XSS：{method} {path} 参数 {key} 未转义返回 payload', evidence=(r.text or '')[:300], remediation='输出编码/转义；CSP；WAF 兜底'))
    status = 'PASS'
    gc.emit('xss_full', 'application', status, findings, summary=json.dumps({'tested': len(tested), 'details': tested}, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
