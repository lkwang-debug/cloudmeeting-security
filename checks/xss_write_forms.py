"""应用安全：新增写表单存储型 XSS（会议室/用户/部门；只创建并清理测试对象）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import importlib.util
import json
import os
import time
import requests
import urllib3
import yaml
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
try:
    from checks import web_auth
except ImportError:
    import web_auth
urllib3.disable_warnings()
BASE = gc.base_url()
CFG = os.path.join(gc.ROOT, 'configs', 'web_automation.yaml')
CHROME = os.environ.get('GATE_CHROME') or 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
LOGIN_MODULE = os.path.join(gc.ROOT, 'adapters', 'browser', 'admin_login.py')

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def api(method, path, body, headers):
    r = requests.request(method, BASE + path, headers={**headers, 'Content-Type': 'application/json'}, json=body, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {})

def load_login():
    spec = importlib.util.spec_from_file_location('al', LOGIN_MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def ui_login(user, pwd, page, al):
    solver = al.CaptchaSolver()
    for attempt in range(1, 4):
        page.goto(BASE + '/?r=%d#/ui/login' % attempt, wait_until='networkidle', timeout=60000)
        page.wait_for_timeout(1200)
        try:
            page.fill('input[placeholder*="用户名"]', user)
            page.fill('input[type="password"]', pwd)
            page.click('button:has-text("登")')
        except Exception:
            continue
        try:
            page.wait_for_selector(al.CAPTCHA_SELECTOR, timeout=25000)
            page.wait_for_timeout(500)
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
            return True
        except Exception:
            continue
    return False

def ui_render(page, route, marker, evidence, findings):
    try:
        page.goto(BASE + '/#' + route, wait_until='domcontentloaded', timeout=30000)
        page.wait_for_timeout(2500)
        try:
            inp = page.locator('input[placeholder*="搜索"], input[placeholder*="名称"], input[placeholder*="用户"], input[placeholder*="部门"]').first
            inp.fill(marker)
            page.keyboard.press('Enter')
            page.wait_for_timeout(2500)
        except Exception:
            pass
        xss = page.evaluate('window.__xss || 0')
        evidence.setdefault('ui', []).append({'route': route, 'xss': xss, 'url': page.url})
        gc.screenshot(page, 'xss_write_forms', route.strip('/').replace('/', '_'))
        if xss:
            findings.append(gc.finding('XSS-WRITE-STORED-UI', 'high', f'新增写表单在 {route} 触发存储型 XSS', evidence=json.dumps(evidence['ui'], ensure_ascii=False)[:400], remediation='输出编码；CSP；富文本过滤'))
    except Exception as e:
        evidence.setdefault('ui_errors', []).append({'route': route, 'error': str(e)[:100]})

def main():
    root = load_cfg()
    cfg = root.get('write_xss') or {}
    if not cfg.get('enabled'):
        gc.emit('xss_write_forms', 'application', 'PASS', [gc.finding('XSS-WRITE-DISABLED', 'info', '写表单 XSS 未启用')], summary='disabled')
        return
    admin = web_auth.headers(root)
    payload = cfg.get('payload') or '<img src=x onerror=window.__xss=1>'
    marker = 'secauto_xss_%d' % int(time.time())
    (created, findings, evidence) = ([], [], {'objects': {}})

    def add_object(kind, name, body, add_path, id_key, cleanup_path, cleanup_body, route):
        (st, j) = api('POST', add_path, body, admin)
        oid = (j.get('data') or {}).get(id_key) if isinstance(j.get('data'), dict) else None
        evidence['objects'][kind] = {'create': {'http': st, 'body': j}, 'id': oid, 'name': name}
        if oid:
            created.append((kind, oid, cleanup_path, cleanup_body(oid, name)))
            if payload in json.dumps(j, ensure_ascii=False):
                findings.append(gc.finding('XSS-WRITE-STORED-API', 'medium', f'新增{kind}名称中的 XSS payload 被 API 原样返回', evidence=json.dumps(j, ensure_ascii=False)[:400], remediation='输出编码/富文本白名单'))
    room_name = marker + '_room' + payload
    add_object('room', room_name, {'enableInvite': True, 'autoRecord': 0, 'password': '123456', 'enableChairPwd': '1', 'verifyMode': '1', 'roomMode': 'standard', 'departId': 1, 'maxUserCount': 10, 'chairPassword': '123456', 'source': '', 'menteeAdvance': True, 'roomName': room_name}, '/api/v1/room/addRoomInfo', 'roomId', '/api/v1/room/delRoomInfo', lambda i, n: {'roomId': i}, '/ui/conference-management/conference-room-info')
    user_name = marker + '_user'
    add_object('user', user_name, {'userName': user_name, 'password': 'Test123456', 'departId': 1, 'adminRole': 2, 'displayName': marker + payload}, '/api/v1/user/add', 'userId', '/api/v1/user/del', lambda i, n: {'userName': n}, '/ui/organizational-management/user-management')
    dept_name = marker + '_dept' + payload
    add_object('department', dept_name, {'parentDepartId': 1, 'departName': dept_name}, '/api/v1/department/add', 'departId', '/api/v1/department/delete', lambda i, n: {'departId': i}, '/ui/organizational-management/department-management')
    if os.path.exists(CHROME) and created:
        try:
            from playwright.sync_api import sync_playwright
            al = load_login()
            user = (cfg.get('user') or {}).get('username', 'sysmanager')
            pwd = os.environ.get((cfg.get('user') or {}).get('password_env', 'SEC_BACKEND_PASS'), _pub.env('SEC_TEST_PASSWORD', ''))
            routes = {'room': '/ui/conference-management/conference-room-info', 'user': '/ui/organizational-management/user-management', 'department': '/ui/organizational-management/department-management'}
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True, executable_path=CHROME, args=['--ignore-certificate-errors', '--no-sandbox'])
                ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
                page = ctx.new_page()
                if ui_login(user, pwd, page, al):
                    for (kind, oid, _, _) in created:
                        ui_render(page, routes.get(kind, '/'), marker, evidence, findings)
                b.close()
        except Exception as e:
            evidence['ui_error'] = str(e)[:120]
    for (kind, oid, path, body) in created:
        try:
            api('POST', path, body, admin)
        except Exception:
            pass
    detail = os.path.join(gc.ROOT, 'reports', 'final', 'gate', 'xss_write_forms_details.json')
    json.dump(evidence, open(detail, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    gc.emit('xss_write_forms', 'application', 'PASS', findings, summary=json.dumps({'objects': list(evidence.get('objects', {}).keys()), 'ui': evidence.get('ui'), 'ui_error': evidence.get('ui_error'), 'findings': len(findings)}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
