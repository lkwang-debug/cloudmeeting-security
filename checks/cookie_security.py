"""应用安全：Cookie 安全属性与 JS 可读 Cookie 检查。"""
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
CHUNKS = os.environ.get('GATE_CHUNKS_DIR') or os.path.join(gc.ROOT, 'tools_cache', 'chunks')

def main():
    (findings, probes) = ([], [])
    for path in ('/', '/ui/login', '/webapp/'):
        try:
            r = requests.get(BASE + path, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        except Exception:
            continue
        cookies = r.headers.get('Set-Cookie', '')
        if not cookies:
            continue
        low = cookies.lower()
        probes.append({'path': path, 'set_cookie': cookies[:300]})
        if 'secure' not in low:
            findings.append(gc.finding('COOKIE-NO-SECURE', 'medium', f'{path} Cookie 缺少 Secure', evidence=cookies[:250], remediation='加 Secure/HttpOnly/SameSite'))
        if 'httponly' not in low:
            findings.append(gc.finding('COOKIE-NO-HTTPONLY', 'medium', f'{path} Cookie 缺少 HttpOnly', evidence=cookies[:250], remediation='加 HttpOnly'))
        if 'samesite' not in low:
            findings.append(gc.finding('COOKIE-NO-SAMESITE', 'low', f'{path} Cookie 缺少 SameSite', evidence=cookies[:250], remediation='加 SameSite=Lax/Strict'))
    js_hits = []
    if os.path.isdir(CHUNKS):
        for fn in os.listdir(CHUNKS):
            if fn.endswith('.js'):
                try:
                    t = open(os.path.join(CHUNKS, fn), encoding='utf-8', errors='replace').read()
                    if 'document.cookie' in t:
                        js_hits.append(fn)
                except Exception:
                    pass
    if js_hits:
        findings.append(gc.finding('COOKIE-JS-ACCESS', 'low', '前端 JS 使用 document.cookie', evidence=json.dumps(js_hits[:8], ensure_ascii=False), remediation='敏感 Cookie 加 HttpOnly'))
    gc.emit('cookie_security', 'application', 'PASS', findings, summary=json.dumps({'probes': probes, 'js_cookie_files': js_hits[:10]}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
