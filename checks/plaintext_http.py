"""加密安全：明文 HTTP（28080）与强制跳转检查。"""
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
ROOT = gc.ROOT

def probe(url):
    out = {'url': url, 'reachable': False}
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=False, headers={'User-Agent': 'Mozilla/5.0'})
        out.update({'reachable': True, 'http': r.status_code, 'location': r.headers.get('Location'), 'body_len': len(r.text or ''), 'content_type': r.headers.get('Content-Type')})
        if r.status_code == 200 and ('json' in (r.headers.get('Content-Type') or '') or 'html' in (r.headers.get('Content-Type') or '')):
            out['plaintext_payload'] = (r.text or '')[:200]
    except Exception as e:
        out['error'] = str(e)[:120]
    return out

def main():
    env_targets = os.environ.get('GATE_HTTP_TARGETS', '')
    candidates = [x.strip() for x in env_targets.split(',') if x.strip()]
    if not candidates:
        for host in (_pub.env('SEC_SSH_HOST', ''), _pub.env('SEC_SSH_HOST', '')):
            for port in (28080, 80):
                candidates.append(f'http://{host}:{port}/')
    results = [probe(u) for u in candidates]
    findings = []
    for r in results:
        if not r.get('reachable'):
            continue
        if r.get('http') == 200 and (not r.get('location')):
            findings.append(gc.finding('CRYPTO-PLAINTEXT-HTTP', 'high', f"明文 HTTP 可访问且未跳转 HTTPS：{r['url']}", evidence=json.dumps(r, ensure_ascii=False)[:300], remediation='关闭 28080/80 或强制 301 到 HTTPS；配置 HSTS'))
        elif r.get('http') in (301, 302, 307, 308) and str(r.get('location', '')).startswith('https://'):
            findings.append(gc.finding('CRYPTO-HTTP-REDIRECT', 'info', f"HTTP 已跳转 HTTPS：{r['url']}", evidence=str(r.get('location'))[:200]))
    reachable = [r for r in results if r.get('reachable')]
    gc.emit('plaintext_http', 'crypto', 'PASS', findings, summary=json.dumps({'probes': len(results), 'reachable': len(reachable), 'detail': results}, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
