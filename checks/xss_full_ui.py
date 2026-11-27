"""应用安全：管理后台全页面/表单 XSS 爬取（Playwright + 已登录会话）。
仅做只读搜索/查询注入，不提交新增/删除表单。"""
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
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
CHROME = os.environ.get('GATE_CHROME') or 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
PAYLOAD = '<img src=x onerror=window.__xss=1>'
PAYLOAD2 = '"><svg/onload=window.__xss=2>'
ROUTES = ['/ui/organizational-management/user-management', '/ui/conference-management/conference-room-info', '/ui/organizational-management/department-management', '/ui/system-management/system-info']

def load_login():
    spec = importlib.util.spec_from_file_location('al', MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def login(page, al):
    pwd = os.environ.get('SEC_BACKEND_PASS', '')
    solver = al.CaptchaSolver()
    for attempt in range(1, 4):
        page.goto(gc.base_url() + '/?r=%d#/ui/login' % attempt, wait_until='networkidle', timeout=60000)
        page.wait_for_timeout(1200)
        try:
            page.fill('input[placeholder*="用户名"]', 'sysmanager')
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
    if not os.path.exists(CHROME):
        gc.emit('xss_full_ui', 'application', 'BLOCKED', [], blocked_reason='未找到 Chrome')
        return
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        gc.emit('xss_full_ui', 'application', 'BLOCKED', [], blocked_reason='playwright 不可用: ' + str(e)[:100])
        return
    al = load_login()
    findings = []
    results = []
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, executable_path=CHROME, args=['--ignore-certificate-errors', '--no-sandbox'])
        ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
        page = ctx.new_page()
        if not login(page, al):
            b.close()
            gc.emit('xss_full_ui', 'application', 'BLOCKED', [], blocked_reason='后台登录失败（验证码/账号）')
            return
        routes = list(ROUTES)
        try:
            links = page.eval_on_selector_all('a[href*="#/"]', "els => els.map(e => e.getAttribute('href') || '')")
            for href in links:
                if '#/' in href:
                    r = '#' + href.split('#', 1)[1]
                    r = r.split('?', 1)[0]
                    if r not in routes:
                        routes.append(r)
        except Exception:
            pass
        for route in routes[:40]:
            try:
                page.goto(gc.base_url() + '/#' + route + '?xss=' + PAYLOAD, wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(2500)
                shot = gc.screenshot(page, 'xss_full_ui', route)
                px = page.evaluate('window.__xss || 0')
                html = page.content()
                raw = PAYLOAD in html
                results.append({'route': route, 'window_xss': px, 'raw_payload': raw, 'screenshot': shot})
                page.goto(gc.base_url() + '/#' + route + '?xss=' + PAYLOAD2, wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(1500)
                px2 = page.evaluate('window.__xss || 0')
                results.append({'route': route, 'payload': 2, 'window_xss': px2})
                if px2:
                    findings.append(gc.finding('XSS-UI-DOM', 'high', f'UI DOM XSS（payload2）：{route}', evidence=json.dumps(results[-1], ensure_ascii=False), remediation='输出编码/CSP'))
                if px:
                    findings.append(gc.finding('XSS-UI-DOM', 'high', f'UI DOM XSS：{route}', evidence=json.dumps(results[-1], ensure_ascii=False), remediation='输出编码/CSP'))
                inputs = page.locator('input[type="text"], input:not([type]), textarea')
                n = min(inputs.count(), 4)
                for i in range(n):
                    try:
                        inp = inputs.nth(i)
                        ph = (inp.get_attribute('placeholder') or '') + (inp.get_attribute('name') or '')
                        if not any((k in ph for k in ('搜索', '查询', 'search', '关键字', '名称'))):
                            continue
                        inp.fill(PAYLOAD)
                        page.keyboard.press('Enter')
                        page.wait_for_timeout(1200)
                        shot2 = gc.screenshot(page, 'xss_full_ui', route + '_search')
                        val = page.evaluate('window.__xss || 0')
                        results.append({'route': route, 'input': ph[:60], 'window_xss': val, 'screenshot': shot2})
                        if val:
                            findings.append(gc.finding('XSS-UI-SEARCH', 'high', f'搜索输入触发 XSS：{route} [{ph[:40]}]', evidence=json.dumps(results[-1], ensure_ascii=False), remediation='输出编码/CSP'))
                    except Exception:
                        continue
                for i in range(min(inputs.count(), 10)):
                    try:
                        inp = inputs.nth(i)
                        if not inp.is_visible():
                            continue
                        inp.fill(PAYLOAD)
                        page.wait_for_timeout(300)
                        val = page.evaluate('window.__xss || 0')
                        results.append({'route': route, 'all_input': i, 'window_xss': val})
                        if val:
                            findings.append(gc.finding('XSS-UI-INPUT', 'high', f'输入填充触发 DOM XSS：{route} input#{i}', evidence=json.dumps(results[-1], ensure_ascii=False), remediation='输出编码/CSP'))
                    except Exception:
                        continue
            except Exception as e:
                results.append({'route': route, 'error': str(e)[:120]})
        b.close()
    gc.emit('xss_full_ui', 'application', 'PASS', findings, summary=json.dumps({'results': results}, ensure_ascii=False)[:900])
if __name__ == '__main__':
    main()
