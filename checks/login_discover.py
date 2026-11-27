"""真实登录（验证码 OCR）+ SPA 遍历，采集后台管理接口（含请求体字段）。
复用 legacy admin_login.py 的 CaptchaSolver/click 逻辑，不修改原件。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import importlib.util
import json
import os
import re
import sys
import time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
OUT = os.path.join(ROOT, 'knowledge', 'backend_endpoints.json')
TOK_OUT = os.path.join(ROOT, 'evidence', 'tokens', 'admin_fresh.txt')
MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
ROUTES = ['/ui/organizational-management/user-management', '/ui/organizational-management/department-management', '/ui/organizational-management/terminal-management', '/ui/organizational-management/contact-whitelist', '/ui/conference-management/conference-room-info', '/ui/conference-management/online-conference', '/ui/conference-management/conference-record', '/ui/conference-management/conference-statistics', '/ui/recording/recording-task', '/ui/log-management/conference-log', '/ui/log-management/operation-log', '/ui/log-management/terminal-log', '/ui/host-management/host-list', '/ui/host-management/global-setting', '/ui/host-management/account-authentication-management', '/ui/feature-permission/background-permission', '/ui/feature-permission/client-feature', '/ui/configuration-center/product-information', '/ui/configuration-center/property-management', '/ui/system-info/node-authorization-information', '/ui/ai-model', '/ui/developer', '/ui/developer/sso', '/ui/face-management/face-database-management']

def load_admin_login():
    spec = importlib.util.spec_from_file_location('admin_login_mod', MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main():
    from playwright.sync_api import sync_playwright
    al = load_admin_login()
    password = os.environ.get('SEC_BACKEND_PASS', '')
    username = os.environ.get('SEC_BACKEND_USER', 'sysmanager')
    if not password:
        print('缺少 SEC_BACKEND_PASS', file=sys.stderr)
        return 2
    chrome = al.find_chrome('')
    solver = al.CaptchaSolver()
    captured = {}
    logins = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=chrome, args=['--ignore-certificate-errors', '--no-sandbox'])
        ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
        page = ctx.new_page()

        def on_request(req):
            u = req.url
            if not re.search('/(serv|basis|auth)/v1/|/api/v1/', u) or not u.startswith(BASE):
                return
            path = u[len(BASE):].split('?')[0]
            key = f'{req.method} {path}'
            it = captured.setdefault(key, {'method': req.method, 'path': path, 'count': 0, 'pages': [], 'query_keys': [], 'body_keys': []})
            it['count'] += 1
            if page.url not in it['pages']:
                it['pages'].append(page.url.split('#')[-1] if '#' in page.url else page.url)
            try:
                from urllib.parse import urlparse, parse_qs
                for k in parse_qs(urlparse(u).query):
                    if k != 't' and k not in it['query_keys']:
                        it['query_keys'].append(k)
            except Exception:
                pass
            if req.post_data:
                try:
                    j = json.loads(req.post_data)
                    if isinstance(j, dict):
                        for k in j:
                            if k not in it['body_keys']:
                                it['body_keys'].append(k)
                except Exception:
                    pass
        page.on('request', on_request)

        def on_response(resp):
            if '/auth/v1/login' in resp.url and resp.request.method == 'POST':
                try:
                    logins.update({'body': resp.text(), 'status': resp.status})
                except Exception:
                    pass
        page.on('response', on_response)
        url = BASE.rstrip('/') + '/#/ui/login'
        token = ''
        for attempt in range(1, 5):
            if attempt > 1:
                try:
                    page.reload(wait_until='networkidle', timeout=60000)
                except Exception:
                    page.goto(url, wait_until='networkidle', timeout=60000)
            else:
                page.goto(url, wait_until='networkidle', timeout=60000)
            page.wait_for_timeout(1500)
            try:
                page.fill('input[placeholder*="用户名"]', username)
            except Exception:
                page.fill('input[type="text"]', username)
            page.fill('input[type="password"]', password)
            page.click('button:has-text("登")')
            page.wait_for_selector(al.CAPTCHA_SELECTOR, timeout=25000)
            page.wait_for_timeout(700)
            imgs = page.locator(al.CAPTCHA_SELECTOR)
            best_src = ''
            for i in range(imgs.count()):
                src = imgs.nth(i).get_attribute('src') or ''
                if len(src) > len(best_src):
                    best_src = src
            import base64
            img_bytes = base64.b64decode(best_src.split(',', 1)[1])
            (boxes, size) = solver.solve(img_bytes)
            page_text = page.inner_text('body')
            m = al.TARGET_RE.search(page_text)
            target = al.HANZI_RE.sub('', m.group(1)) if m else ''
            points = al.match_points(target, boxes) if target else None
            if not points or len(points) != len(target):
                print('验证码 OCR 不匹配，重试')
                continue
            al.click_points(page, points, size)
            page.wait_for_timeout(5000)
            if logins.get('body') or '/#/ui/login' not in page.url:
                break
        if logins.get('body'):
            try:
                token = (json.loads(logins['body']).get('data') or {}).get('token') or ''
            except Exception:
                token = ''
        if not token:
            try:
                token = page.evaluate("() => localStorage.getItem('token') || (document.cookie.match(/token=([^;]+)/)||[])[1]") or ''
            except Exception:
                token = ''
        for r in ROUTES:
            try:
                page.goto(BASE + '/#' + r, wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(2000)
            except Exception:
                pass
        browser.close()
    os.makedirs(os.path.dirname(TOK_OUT), exist_ok=True)
    if token:
        open(TOK_OUT, 'w', encoding='utf-8').write(token.strip() + '\n')
    data = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'token_saved': bool(token), 'endpoints': sorted(captured.values(), key=lambda x: x['path'])}
    json.dump(data, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('token_len:', len(token), 'captured:', len(data['endpoints']))
    for e in data['endpoints'][:40]:
        print(f"  {e['method']:5} {e['path']:60} q={e['query_keys']} b={e['body_keys']}")
    return 0
if __name__ == '__main__':
    sys.exit(main())
