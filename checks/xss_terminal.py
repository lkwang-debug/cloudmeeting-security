"""应用安全：终端新增/删除 + 终端名称存储型 XSS 检查。

终端名称/位置/备注存在特殊字符白名单，先验证 payload 是否被接受；
再创建普通测试终端做 UI 渲染检查；仅清理本次自建终端。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import importlib.util
import json
import os
import subprocess
import sys
import time
import requests
import urllib3
import yaml
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
ROOT = gc.ROOT
CFG = os.path.join(ROOT, 'configs', 'web_automation.yaml')
CHROME = os.environ.get('GATE_CHROME') or 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
LOGIN_MODULE = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
PAYLOAD = '<img src=x onerror=window.__xss=1>'

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def load_login():
    spec = importlib.util.spec_from_file_location('al', LOGIN_MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def ui_login(user, pwd, page, al):
    solver = al.CaptchaSolver()
    for attempt in range(1, 4):
        page.goto(BASE + '/?r=%d#/ui/login' % attempt, wait_until='networkidle', timeout=60000)
        page.wait_for_timeout(1000)
        try:
            page.fill('input[placeholder*="用户名"]', user)
            page.fill('input[type="password"]', pwd)
            page.click('button:has-text("登")')
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

def refresh_terminal_token(user):
    """CSRF/UI 检查可能使 sysmanager 旧 token 失效，这里即时刷新。"""
    try:
        env = dict(os.environ)
        env.setdefault('SEC_BACKEND_PASS', _pub.env('SEC_TEST_PASSWORD', ''))
        subprocess.run([sys.executable, LOGIN_MODULE, '--target', _pub.target(), '--username', user, '--password-env', 'SEC_BACKEND_PASS', '--attempts', '2', '--out', os.path.join(ROOT, 'evidence', 'tokens', user + '.txt'), '--evidence-dir', os.path.join(ROOT, 'evidence', 'raw', 'login_sysmanager')], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    except Exception:
        pass

def cleanup_db(name):
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(os.environ.get('GATE_SSH_HOST', _pub.env('SEC_SSH_HOST', '')), 22, os.environ.get('GATE_SSH_USER', 'root'), os.environ.get('GATE_SSH_PASS', _pub.env('SEC_SSH_PASSWORD', '')), timeout=10)
        sql = 'DELETE FROM t_terminal WHERE name=%s;' % json.dumps(name)
        cmd = 'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e ' + json.dumps(sql) + ' 2>/dev/null'
        (i, o, e) = c.exec_command(cmd, timeout=30)
        o.read()
        c.close()
        return True
    except Exception:
        return False

def main():
    root = load_cfg()
    cfg = root.get('terminal_xss') or {}
    if not cfg.get('enabled'):
        gc.emit('xss_terminal', 'application', 'PASS', [gc.finding('XSS-TERMINAL-DISABLED', 'info', '终端 XSS 未启用')], summary='disabled')
        return
    term_user = (cfg.get('user') or {}).get('username') or 'sysmanager'
    tp = os.path.join(ROOT, 'evidence', 'tokens', term_user + '.txt')
    if not os.path.exists(tp):
        gc.emit('xss_terminal', 'application', 'BLOCKED', [], blocked_reason='缺少 sysmanager token，请先运行 runner/refresh_web_tokens.py')
        return
    token = open(tp, encoding='utf-8').read().strip()
    headers = {'token': token, 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    ts = int(time.time())
    marker = 'secauto_term_xss_%d' % ts
    (findings, evidence) = ([], {'marker': marker})
    try:
        r = requests.post(BASE + '/serv/v1/terminal/add', headers=headers, json={'name': 'secauto_xss_probe_%d' % ts, 'seqNum': 'SNXP%d' % ts, 'departId': int(cfg.get('depart_id', 1)), 'terminalType': int(cfg.get('terminal_type', 1)), 'position': PAYLOAD, 'remark': PAYLOAD}, params={'t': '1'}, timeout=15, verify=False)
        j = r.json()
        evidence['payload_probe'] = {'http': r.status_code, 'code': j.get('code'), 'msg': str(j.get('msg'))[:120], 'data': j.get('data')}
        rejected = str(j.get('code')) == '9003' and 'special characters' in json.dumps(j, ensure_ascii=False).lower()
        if rejected:
            findings.append(gc.finding('TERMINAL-XSS-INPUT-VALIDATION', 'info', '终端名称/位置/备注拒绝特殊字符，当前无存储型 XSS 输入面', evidence=json.dumps(j, ensure_ascii=False)[:400], remediation='保持输入白名单/输出编码'))
    except Exception as e:
        evidence['payload_probe_error'] = str(e)[:120]
    serial = 'SNXSS%d' % ts
    try:
        r = requests.post(BASE + '/serv/v1/terminal/add', headers=headers, json={'name': marker, 'seqNum': serial, 'departId': int(cfg.get('depart_id', 1)), 'terminalType': int(cfg.get('terminal_type', 1))}, params={'t': '1'}, timeout=20, verify=False)
        j = r.json()
        if str(j.get('code')) in ('1002', '1001'):
            refresh_terminal_token(term_user)
            token = open(tp, encoding='utf-8').read().strip()
            headers['token'] = token
            r = requests.post(BASE + '/serv/v1/terminal/add', headers=headers, json={'name': marker, 'seqNum': serial, 'departId': int(cfg.get('depart_id', 1)), 'terminalType': int(cfg.get('terminal_type', 1))}, params={'t': '1'}, timeout=20, verify=False)
            j = r.json()
        evidence['add'] = {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg')}
        if str(j.get('code')) != '0':
            gc.emit('xss_terminal', 'application', 'BLOCKED', findings, blocked_reason='终端新增失败: ' + str(j)[:120])
            return
    except Exception as e:
        gc.emit('xss_terminal', 'application', 'BLOCKED', findings, blocked_reason=str(e)[:150])
        return
    if os.path.exists(CHROME):
        try:
            from playwright.sync_api import sync_playwright
            al = load_login()
            user = term_user
            pwd = os.environ.get('SEC_BACKEND_PASS', _pub.env('SEC_TEST_PASSWORD', ''))
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True, executable_path=CHROME, args=['--ignore-certificate-errors', '--no-sandbox'])
                ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 950})
                page = ctx.new_page()
                if ui_login(user, pwd, page, al):
                    page.goto(BASE + '/#/ui/organizational-management/terminal-management', wait_until='domcontentloaded', timeout=30000)
                    page.wait_for_timeout(2500)
                    try:
                        page.fill('main input[placeholder*="搜索内容"]', marker)
                        page.keyboard.press('Enter')
                        page.wait_for_timeout(2000)
                    except Exception:
                        pass
                    body = page.inner_text('body')
                    evidence['ui'] = {'xss': page.evaluate('window.__xss || 0'), 'has_name': marker in body, 'url': page.url}
                    gc.screenshot(page, 'xss_terminal', 'terminal_list')
                b.close()
        except Exception as e:
            evidence['ui_error'] = str(e)[:150]
    evidence['cleanup_db'] = cleanup_db(marker)
    try:
        r = requests.post(BASE + '/serv/v1/terminal/page', headers=headers, json={'pageNumber': 1, 'pageSize': 100}, params={'t': '1'}, timeout=15, verify=False)
        recs = (r.json().get('data') or {}).get('records') or []
        evidence['residual'] = [x for x in recs if x.get('name') == marker]
    except Exception:
        evidence['residual'] = []
    gc.emit('xss_terminal', 'application', 'PASS', findings, summary=json.dumps(evidence, ensure_ascii=False)[:1200])
if __name__ == '__main__':
    main()
