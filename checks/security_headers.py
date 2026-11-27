"""应用安全：安全响应头/CORS 检查（AppScan 常见发现项）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
PATHS = ['/', '/ui/login', '/webapp/']

def main():
    findings = []
    tested = []
    for path in PATHS:
        try:
            r = requests.get(BASE + path, timeout=12, verify=False, headers={'User-Agent': 'Mozilla/5.0', 'Origin': 'https://evil.example'})
        except Exception:
            continue
        h = {k.lower(): v for (k, v) in r.headers.items()}
        tested.append({'path': path, 'http': r.status_code, 'headers': {k: h.get(k) for k in ('strict-transport-security', 'x-content-type-options', 'referrer-policy', 'content-security-policy', 'x-frame-options', 'access-control-allow-origin')}})
        if not h.get('strict-transport-security'):
            findings.append(gc.finding('HDR-HSTS', 'medium', f'{path} 缺少 HSTS', evidence='Strict-Transport-Security 缺失'))
        if h.get('x-content-type-options', '').lower() != 'nosniff':
            findings.append(gc.finding('HDR-NOSNIFF', 'low', f'{path} 缺少 X-Content-Type-Options: nosniff'))
        if not h.get('referrer-policy'):
            findings.append(gc.finding('HDR-REFERRER', 'low', f'{path} 缺少 Referrer-Policy'))
        if not h.get('content-security-policy'):
            findings.append(gc.finding('HDR-CSP', 'low', f'{path} 缺少 Content-Security-Policy'))
        if not h.get('x-frame-options'):
            findings.append(gc.finding('HDR-FRAME', 'low', f'{path} 缺少 X-Frame-Options/frame-ancestors'))
        acao = (h.get('access-control-allow-origin') or '').strip()
        if acao == '*' or acao == 'https://evil.example':
            findings.append(gc.finding('HDR-CORS', 'medium', f'{path} CORS 允许任意来源', evidence=f'Access-Control-Allow-Origin={acao}'))
        for (name, fid) in (('x-permitted-cross-domain-policies', 'HDR-XPCDP'), ('x-download-options', 'HDR-XDO'), ('x-xss-protection', 'HDR-XXSS')):
            if not h.get(name):
                findings.append(gc.finding(fid, 'low', f'{path} 缺少 {name}'))
        try:
            ro = requests.options(BASE + path, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            allow = ro.headers.get('Allow', '')
            tested[-1]['options'] = {'http': ro.status_code, 'allow': allow}
            if ro.status_code in (200, 204) and allow:
                findings.append(gc.finding('HDR-OPTIONS', 'low', f'{path} 启用 OPTIONS 方法', evidence=f'Allow={allow[:200]}'))
        except Exception:
            pass
    try:
        rt = requests.request('TRACE', BASE + '/', timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        if rt.status_code == 200 and 'TRACE' in (rt.text or '').upper():
            findings.append(gc.finding('HDR-TRACE', 'low', '启用 TRACE 方法', evidence=(rt.text or '')[:200], remediation='禁用 TRACE'))
    except Exception:
        pass
    gc.emit('security_headers', 'application', 'PASS', findings, summary=json.dumps({'probes': tested}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
