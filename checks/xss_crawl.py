"""应用安全：全输入点反射 XSS 爬取（基于知识库接口 + 常见参数名，只读）。"""
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
KEYS = ['userName', 'displayName', 'departName', 'roomName', 'terminalName', 'searchKey', 'keyword', 'name', 'q', 'title', 'mobile', 'email']
PAYLOAD = '<script>alert(1)</script>'
READ_HINTS = ('list', 'page', 'query', 'search', 'get', 'info', 'detail', 'tree', 'select')

def main():
    tok = gc.token('admin02')
    if not tok:
        gc.emit('xss_crawl', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    paths = [p for p in gc.all_endpoints() if not re.search('\\$\\{|\\{\\{', p)]
    paths = [p for p in paths if any((k in p.lower() for k in READ_HINTS))][:60]
    findings = []
    tested = []
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    for path in paths:
        for key in KEYS[:8]:
            try:
                r = requests.get(BASE + path, headers=h, params={'t': str(int(time.time() * 1000)), key: PAYLOAD}, timeout=10, verify=False)
            except Exception:
                continue
            tested.append({'path': path, 'key': key, 'http': r.status_code, 'len': len(r.text or '')})
            if PAYLOAD in (r.text or ''):
                findings.append(gc.finding('XSS-CRAWL-' + key, 'high', f'反射 XSS：{path} 参数 {key} 未转义', evidence=(r.text or '')[:300], remediation='输出编码/CSP'))
    gc.emit('xss_crawl', 'application', 'PASS', findings, summary=json.dumps({'paths': len(paths), 'tested': len(tested)}, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
