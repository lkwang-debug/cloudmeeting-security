"""应用安全：登录风控/弱口令策略检查（低速率，仅测试账号）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()

def main():
    findings = []
    checks = {}
    try:
        r = requests.get(BASE + '/ui/login', timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        text = r.text or ''
        checks['login_page_http'] = r.status_code
        checks['captcha_present'] = any((k in text.lower() for k in ('captcha', '验证码', 'verifycode')))
    except Exception as e:
        checks['login_page_error'] = str(e)[:100]
    for i in range(2):
        try:
            r = requests.post(BASE + '/auth/v1/login', timeout=10, verify=False, headers={'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}, json={'username': 'test00', 'password': 'gate-wrong-' + str(i), 'captcha': ''}, params={'t': str(int(time.time() * 1000))})
            try:
                j = r.json()
            except Exception:
                j = {}
            checks[f'wrong_login_{i}'] = {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg')}
        except Exception as e:
            checks[f'wrong_login_{i}'] = {'error': str(e)[:80]}
    if checks.get('login_page_http') == 200 and (not checks.get('captcha_present')):
        findings.append(gc.finding('LOGIN-NO-CAPTCHA', 'medium', '登录页未检测到验证码元素', evidence=json.dumps(checks, ensure_ascii=False)[:300], remediation='登录增加验证码/风险控制'))
    codes = [v.get('code') for v in checks.values() if isinstance(v, dict)]
    if codes and all((c == '0' for c in codes)):
        findings.append(gc.finding('LOGIN-WEAK-POLICY', 'high', '错误口令连续登录成功（口令策略异常）', evidence=json.dumps(checks, ensure_ascii=False)[:300], remediation='校验失败锁定/限速'))
    gc.emit('login_policy', 'application', 'PASS', findings, summary=json.dumps(checks, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
