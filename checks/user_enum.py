"""应用安全：用户枚举（OAuth2 登录错误响应差异，低速率）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import json
import os
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
CLIENT = _pub.env('SEC_CLIENT_ID') + ':' + _pub.env('SEC_CLIENT_SECRET')

def attempt(user, pwd):
    basic = 'Basic ' + base64.b64encode(CLIENT.encode()).decode()
    try:
        r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'password', 'username': user, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=12, verify=False)
        return {'http': r.status_code, 'body': (r.text or '')[:300]}
    except Exception as e:
        return {'error': str(e)[:100]}

def main():
    valid = os.environ.get('GATE_ENUM_USER', 'test_user_a')
    r1 = attempt(valid, 'GateWrong#2026!')
    r2 = attempt('secauto_notexist_' + str(int(time.time())), 'GateWrong#2026!')
    findings = []
    if r1.get('http') and r2.get('http'):
        if r1.get('http') != r2.get('http') or r1.get('body') != r2.get('body'):
            findings.append(gc.finding('AUTH-USER-ENUM', 'medium', '登录失败响应存在用户枚举差异', evidence=json.dumps({'valid_user': r1, 'invalid_user': r2}, ensure_ascii=False)[:500], remediation='统一失败提示/状态码；增加验证码/限速'))
    gc.emit('user_enum', 'application', 'PASS', findings, summary=json.dumps({'valid': r1, 'invalid': r2}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
