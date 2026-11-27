"""P0：用 Playwright 注入后台 token，遍历 SPA 路由，采集真实后台接口（/serv /basis /api）。
输出 knowledge/backend_endpoints.json（方法+路径模板+来源页面）。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import time
from playwright.sync_api import sync_playwright
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
TOKEN_FILE = os.path.join(ROOT, 'evidence', 'tokens', 'admin.txt')
OUT = os.path.join(ROOT, 'knowledge', 'backend_endpoints.json')
ROUTES = ['/ui/organizational-management/user-management', '/ui/organizational-management/department-management', '/ui/organizational-management/terminal-management', '/ui/organizational-management/contact-whitelist', '/ui/conference-management/conference-room-info', '/ui/conference-management/online-conference', '/ui/conference-management/conference-record', '/ui/conference-management/conference-statistics', '/ui/recording/recording-task', '/ui/log-management/conference-log', '/ui/log-management/operation-log', '/ui/log-management/terminal-log', '/ui/host-management/host-list', '/ui/host-management/global-setting', '/ui/host-management/account-authentication-management', '/ui/feature-permission/background-permission', '/ui/feature-permission/client-feature', '/ui/configuration-center/product-information', '/ui/configuration-center/property-management', '/ui/system-info/node-authorization-information', '/ui/ai-model', '/ui/developer', '/ui/developer/sso', '/ui/face-management/face-database-management']

def main():
    token = open(TOKEN_FILE, encoding='utf-8').read().strip()
    captured = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=os.environ.get('SEC_CHROME', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'), args=['--ignore-certificate-errors'])
        ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 900})
        page = ctx.new_page()

        def on_request(req):
            u = req.url
            if not re.search('/(serv|basis|auth)/v1/|/api/v1/', u):
                return
            if not u.startswith(BASE):
                return
            path = u[len(BASE):].split('?')[0]
            key = f'{req.method} {path}'
            item = captured.setdefault(key, {'method': req.method, 'path': path, 'count': 0, 'pages': [], 'query_keys': []})
            item['count'] += 1
            try:
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(u).query)
                for k in q:
                    if k not in item['query_keys'] and k != 't':
                        item['query_keys'].append(k)
            except Exception:
                pass
            if page.url not in item['pages']:
                item['pages'].append(page.url.split('#')[-1] if '#' in page.url else page.url)
        page.on('request', on_request)
        page.goto(BASE + '/', wait_until='domcontentloaded', timeout=60000)
        page.evaluate("(t)=>{localStorage.setItem('token',t);}", token)
        page.wait_for_timeout(1500)
        for r in ROUTES:
            try:
                page.goto(BASE + '/#' + r, wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(1800)
            except Exception:
                pass
        try:
            page.goto(BASE + '/#/ui/organizational-management/user-management', wait_until='domcontentloaded', timeout=30000)
            page.wait_for_timeout(1500)
        except Exception:
            pass
        browser.close()
    data = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'endpoints': sorted(captured.values(), key=lambda x: x['path'])}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(data, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('captured:', len(data['endpoints']))
    for e in data['endpoints']:
        print(f"  {e['method']:6} {e['path']:70} pages={len(e['pages'])}")
if __name__ == '__main__':
    main()
