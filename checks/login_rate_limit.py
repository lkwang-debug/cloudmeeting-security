"""应用安全：登录限速/锁定实测（仅测试账号，限 3 次）。"""
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

def login(user, pwd):
    basic = 'Basic ' + base64.b64encode(CLIENT.encode()).decode()
    try:
        r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'password', 'username': user, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
        return {'http': r.status_code, 'token': bool((r.json() or {}).get('access_token')) if r.text else False}
    except Exception as e:
        return {'error': str(e)[:80]}

def main():
    users = [u.strip() for u in os.environ.get('GATE_LOGIN_TEST_USERS', '').split(',') if u.strip()]
    correct = os.environ.get('SEC_LOGIN_TEST_PASS', '')
    if not users or not correct:
        gc.emit('login_rate_limit', 'application', 'PASS', [gc.finding('LOGIN-RATE-SKIP', 'info', '未配置登录测试账号/口令，跳过')], summary='not configured')
        return
    findings = []
    observations = []
    for u in users[:1]:
        for i in range(3):
            observations.append({'user': u, 'attempt': 'wrong-%d' % (i + 1), **login(u, 'Wrong#123456')})
        ok = login(u, correct)
        observations.append({'user': u, 'attempt': 'correct', **ok})
        if ok.get('token') and (not any((o.get('http') == 429 or 'LOCK' in str(o) for o in observations))):
            findings.append(gc.finding('LOGIN-NO-RATE-LIMIT', 'medium', f'测试账号 {u} 连续 3 次错误后仍可正常登录（未观察到锁定/限速）', evidence=json.dumps(observations, ensure_ascii=False)[:400], remediation='登录失败锁定/验证码/频率限制'))
    gc.emit('login_rate_limit', 'application', 'PASS', findings, summary=json.dumps({'observations': observations}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
