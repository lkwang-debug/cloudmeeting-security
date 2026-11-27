"""真实登录后收集 SPA 加载的 JS chunk，静态提取全部后台接口（含写接口）。不产生写操作。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import importlib.util
import json
import os
import re
import sys
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
OUT = os.path.join(ROOT, 'knowledge', 'all_backend_endpoints.json')
TDIR = os.path.join(ROOT, 'tools_cache', 'chunks')
MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
PAGES = ['/ui/organizational-management/user-management', '/ui/organizational-management/department-management', '/ui/organizational-management/terminal-management', '/ui/conference-management/conference-room-info', '/ui/recording/recording-task', '/ui/log-management/operation-log', '/ui/host-management/host-list', '/ui/feature-permission/background-permission']

def load():
    spec = importlib.util.spec_from_file_location('al', MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    from playwright.sync_api import sync_playwright
    al = load()
    pwd = os.environ.get('SEC_BACKEND_PASS', '')
    if not pwd:
        print('缺少 SEC_BACKEND_PASS', file=sys.stderr)
        return 2
    chrome = al.find_chrome('')
    solver = al.CaptchaSolver()
    resources = set()
    token = ''
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, executable_path=chrome, args=['--ignore-certificate-errors', '--no-sandbox'])
        ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
        page = ctx.new_page()

        def on_req(req):
            u = req.url
            if u.startswith(BASE) and re.search('\\.js(\\?|$)', u):
                resources.add(u.split('?')[0])
        page.on('request', on_req)
        for attempt in range(1, 6):
            url = BASE + '/?r=%d#/ui/login' % attempt
            page.goto(url, wait_until='networkidle', timeout=60000)
            page.wait_for_timeout(1500)
            try:
                page.fill('input[placeholder*="用户名"]', 'sysmanager')
            except Exception:
                try:
                    page.fill('input[type="text"]', 'sysmanager')
                except Exception:
                    continue
            try:
                page.fill('input[type="password"]', pwd)
                page.click('button:has-text("登")')
            except Exception:
                continue
            page.wait_for_selector(al.CAPTCHA_SELECTOR, timeout=25000)
            page.wait_for_timeout(700)
            imgs = page.locator(al.CAPTCHA_SELECTOR)
            src = ''
            for i in range(imgs.count()):
                s = imgs.nth(i).get_attribute('src') or ''
                if len(s) > len(src):
                    src = s
            try:
                img = base64.b64decode(src.split(',', 1)[1])
            except Exception:
                continue
            (boxes, size) = solver.solve(img)
            txt = page.inner_text('body')
            m = al.TARGET_RE.search(txt)
            target = al.HANZI_RE.sub('', m.group(1)) if m else ''
            pts = al.match_points(target, boxes) if target else None
            if not pts or len(pts) != len(target):
                continue
            al.click_points(page, pts, size)
            page.wait_for_timeout(5000)
            try:
                token = page.evaluate("() => localStorage.getItem('token') || ''") or ''
            except Exception:
                token = ''
            if token:
                break
        for r in PAGES:
            try:
                page.goto(BASE + '/#' + r, wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(2500)
            except Exception:
                pass
        try:
            page.goto(BASE + '/', wait_until='domcontentloaded', timeout=30000)
            page.wait_for_timeout(2000)
        except Exception:
            pass
        try:
            for u in page.evaluate("() => performance.getEntriesByType('resource').map(e=>e.name)"):
                if u.startswith(BASE) and '.js' in u:
                    resources.add(u.split('?')[0])
        except Exception:
            pass
        b.close()
    os.makedirs(TDIR, exist_ok=True)
    paths = set()
    h = {'User-Agent': 'Mozilla/5.0', 'Referer': BASE + '/ui/login'}
    n = 0
    for u in sorted(resources):
        rel = u[len(BASE):]
        try:
            r = requests.get(u, headers=h, timeout=20, verify=False)
            if r.status_code != 200 or 'javascript' not in r.headers.get('content-type', ''):
                continue
            fn = os.path.join(TDIR, rel.replace('/', '_'))
            open(fn, 'w', encoding='utf-8', errors='replace').write(r.text)
            n += 1
            for m in re.finditer('["\\\'](/(?:serv|basis|auth)/v1/[A-Za-z0-9_/{}$.-]+)["\\\']', r.text):
                paths.add(m.group(1))
        except Exception:
            pass
    data = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'chunks_downloaded': n, 'endpoints': sorted(paths)}
    json.dump(data, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('chunks:', n, 'endpoints:', len(paths))
    for x in sorted(paths):
        print(' ', x)
if __name__ == '__main__':
    sys.exit(main())
