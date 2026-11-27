"""应用安全：基于 Cookie/UI 会话的 CSRF 自动化。

配置 configs/web_automation.yaml -> csrf_ui：
- 登录 URL/账号/密码
- 一个状态变更请求（action）与 cleanup
流程：Playwright 登录 -> 取得 Cookie -> 用 Cookie 重放 action（不带 Origin/Referer/Authorization）
若 action 成功，说明存在基于 Cookie 的 CSRF 风险。
"""
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
ROOT = gc.ROOT
MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
CHROME = os.environ.get('GATE_CHROME') or 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
CFG = os.environ.get('GATE_WEB_AUTOMATION') or os.path.join(ROOT, 'configs', 'web_automation.yaml')

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def load_login():
    spec = importlib.util.spec_from_file_location('al', MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def login(page, al, user, pwd):
    solver = al.CaptchaSolver()
    for attempt in range(1, 4):
        page.goto(gc.base_url() + '/?r=%d#/ui/login' % attempt, wait_until='networkidle', timeout=60000)
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

def main():
    root = load_cfg()
    cfg = root.get('csrf_ui') or {}
    if not cfg.get('enabled'):
        gc.emit('csrf_ui_check', 'application', 'PASS', [gc.finding('CSRF-UI-MANUAL', 'info', 'csrf_ui 未启用')], summary='csrf_ui disabled')
        return
    if not os.path.exists(CHROME):
        gc.emit('csrf_ui_check', 'application', 'BLOCKED', [], blocked_reason='未找到 Chrome')
        return
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        gc.emit('csrf_ui_check', 'application', 'BLOCKED', [], blocked_reason='playwright 不可用: ' + str(e)[:100])
        return
    user = cfg.get('username') or os.environ.get('SEC_BACKEND_USER', 'sysmanager')
    pwd = os.environ.get(cfg.get('password_env', 'SEC_BACKEND_PASS'), '') or _pub.env('SEC_TEST_PASSWORD', '')
    action = cfg.get('action') or {}
    if not action.get('path'):
        gc.emit('csrf_ui_check', 'application', 'BLOCKED', [], blocked_reason='csrf_ui.action.path 未配置')
        return
    run_id = time.strftime('%Y%m%d%H%M%S')

    def sub(v):
        if isinstance(v, dict):
            return {k: sub(x) for (k, x) in v.items()}
        if isinstance(v, list):
            return [sub(x) for x in v]
        if isinstance(v, str):
            return v.replace('${run_id}', run_id)
        return v
    al = load_login()
    cookies = []
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, executable_path=CHROME, args=['--ignore-certificate-errors', '--no-sandbox'])
        ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
        page = ctx.new_page()
        if not login(page, al, user, pwd):
            b.close()
            gc.emit('csrf_ui_check', 'application', 'BLOCKED', [], blocked_reason='UI 登录失败（验证码/账号）')
            return
        cookies = ctx.cookies()
        gc.screenshot(page, 'csrf_ui_check', 'after_login')
        b.close()
    cookie_header = '; '.join((f"{c['name']}={c['value']}" for c in cookies if c.get('name')))
    headers = {'Cookie': cookie_header, 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
    try:
        r = requests.request(action.get('method', 'POST'), gc.base_url() + action['path'], headers=headers, json=sub(action.get('json') or {}), timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        ok = r.status_code in (200, 201) and str(j.get('code')) in ('0', 'None')
        findings = []
        if ok:
            findings.append(gc.finding('CSRF-UI-CONFIRMED', 'high', '基于 Cookie 的 UI 会话请求在无 Origin/Referer 下仍成功', evidence=json.dumps({'http': r.status_code, 'body': (r.text or '')[:300]}, ensure_ascii=False), remediation='校验 Origin/Referer/CSRF token；SameSite'))
        gc.emit('csrf_ui_check', 'application', 'PASS', findings, summary=json.dumps({'cookies': len(cookies), 'http': r.status_code, 'body': (r.text or '')[:300]}, ensure_ascii=False)[:600])
        for c in cfg.get('cleanup') or []:
            try:
                requests.request(c.get('method', 'POST'), gc.base_url() + c['path'], headers={**web_auth.headers(root), **(c.get('headers') or {})}, json=sub(c.get('json')), timeout=10, verify=False)
            except Exception:
                pass
    except Exception as e:
        gc.emit('csrf_ui_check', 'application', 'BLOCKED', [], blocked_reason=str(e)[:150])
if __name__ == '__main__':
    main()
