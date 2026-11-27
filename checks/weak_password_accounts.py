"""应用安全：测试账号弱口令验证（仅使用用户提供的测试账号，不爆破真实账号）。"""
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

def main():
    users = [u.strip() for u in os.environ.get('GATE_WEAK_TEST_USERS', '').split(',') if u.strip()]
    pwd = os.environ.get('SEC_WEAK_TEST_PASS', '')
    if not users or not pwd:
        gc.emit('weak_password_accounts', 'application', 'PASS', [gc.finding('WEAK-TEST-SKIPPED', 'info', '未配置测试账号/口令，跳过弱口令验证')], summary='not configured')
        return
    findings = []
    checked = []
    basic = 'Basic ' + base64.b64encode(CLIENT.encode()).decode()
    for u in users[:10]:
        try:
            r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'password', 'username': u, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
            ok = r.status_code == 200 and bool((r.json() or {}).get('access_token'))
            checked.append({'user': u, 'ok': ok, 'http': r.status_code})
            if ok:
                findings.append(gc.finding('WEAK-ACCOUNT-PASSWORD', 'medium', f'测试账号 {u} 使用弱口令可登录', evidence='OAuth2 password grant success（测试账号）', remediation='测试账号上线前禁用/改强口令；产品不应内置弱口令账号'))
        except Exception as e:
            checked.append({'user': u, 'error': str(e)[:80]})
    gc.emit('weak_password_accounts', 'application', 'PASS', findings, summary=json.dumps({'checked': checked, 'password_used': '***'}, ensure_ascii=False))
if __name__ == '__main__':
    main()
