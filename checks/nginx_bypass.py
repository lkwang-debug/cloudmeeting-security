"""应用安全：nginx 403 绕过/NULL 字节/路径规范化差异检查。

基线：请求受保护路径，若返回 403。
变体：%00、%2e%2e/、..;/、//、%2f、X-Original-URL、X-Rewrite-URL。
变体返回 200 且出现目标资源特征 → 记录绕过。
"""
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
PATHS = ['/actuator', '/actuator/env', '/swagger-ui/index.html', '/.git/config', '/api/v1/user/list']
VARIANTS = [('null-byte', lambda p: p + '%00'), ('null-byte-php', lambda p: p + '%00.php'), ('dotdot-semicolon', lambda p: p.replace('/', '/..;/', 1)), ('double-slash', lambda p: '//' + p.lstrip('/')), ('encoded-slash', lambda p: p.replace('/', '%2f')), ('trailing-dot', lambda p: p + '.')]
HEADER_VARIANTS = [('X-Original-URL', lambda p: p), ('X-Rewrite-URL', lambda p: p)]
MARKERS = {'/actuator': ('_links', 'health', 'status', 'actuator'), '/actuator/env': ('propertySources', 'systemProperties', 'activeProfiles'), '/.git/config': ('repositoryformatversion', '[core]', 'filemode'), '/swagger-ui/index.html': ('swagger', 'openapi'), '/api/v1/user/list': ('"code":"0"', '"records"')}

def is_error(body):
    low = (body or '').lower()
    return any((x in low for x in ('403 forbidden', 'access denied', '请求失败', 'not found', '<title>403')))

def is_bypass(path, r):
    if r.status_code != 200 or is_error(r.text):
        return False
    body = r.text or ''
    markers = MARKERS.get(path, ())
    if not markers:
        return len(body) > 50
    if path == '/.git/config':
        return any((m in body for m in ('[core]', 'repositoryformatversion')))
    if path == '/swagger-ui/index.html':
        return any((m in body.lower() for m in ('swagger', 'openapi')))
    is_json = 'json' in (r.headers.get('Content-Type', '') or '').lower() or body.lstrip().startswith('{')
    return is_json and any((m.lower() in body.lower() for m in markers))

def main():
    (findings, probes) = ([], [])
    for path in PATHS:
        try:
            base = requests.get(BASE + path, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        except Exception:
            continue
        if base.status_code != 403:
            continue
        probes.append({'path': path, 'base': base.status_code, 'len': len(base.text or '')})
        for (name, fn) in VARIANTS:
            p = fn(path)
            try:
                r = requests.get(BASE + p, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            except Exception:
                continue
            probes.append({'path': path, 'variant': name, 'url': p, 'http': r.status_code, 'len': len(r.text or '')})
            if is_bypass(path, r):
                findings.append(gc.finding('NGINX-403-BYPASS', 'high', f'403 绕过：{path} -> {name}', evidence=(r.text or '')[:300], remediation='规范化路径；拒绝编码 NULL/..;/；统一鉴权在后端'))
        for (name, fn) in HEADER_VARIANTS:
            try:
                r = requests.get(BASE + '/', timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0', name: fn(path)})
            except Exception:
                continue
            probes.append({'path': path, 'header': name, 'http': r.status_code, 'len': len(r.text or '')})
            if is_bypass(path, r):
                findings.append(gc.finding('NGINX-HEADER-BYPASS', 'medium', f'路径覆盖头可能绕过：{path} via {name}', evidence=(r.text or '')[:300], remediation='禁用 X-Original-URL/X-Rewrite-URL 覆盖'))
    gc.emit('nginx_bypass', 'application', 'PASS', findings, summary=json.dumps({'probes': probes}, ensure_ascii=False)[:900])
if __name__ == '__main__':
    main()
