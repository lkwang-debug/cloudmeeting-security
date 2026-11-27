"""应用安全：H5/客户端 API 水平越权（普通用户 OAuth token vs 管理员）。"""
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
ENDPOINTS = ['/meeting-resource-server/security/company/users?pageSize=20', '/meeting-resource-server/security/company/departments']

def token(user, pwd):
    basic = 'Basic ' + base64.b64encode(CLIENT.encode()).decode()
    try:
        r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'password', 'username': user, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
        return (r.json() or {}).get('access_token', '')
    except Exception:
        return ''

def call(path, tok):
    try:
        r = requests.get(BASE + path, headers={'Authorization': 'Bearer ' + tok, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0'}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        items = (j.get('result') or {}).get('items') or j.get('items') or []
        return {'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'len': len(json.dumps(j, ensure_ascii=False)), 'items': len(items) if isinstance(items, list) else None}
    except Exception as e:
        return {'error': str(e)[:100]}

def main():
    admin_pwd = os.environ.get('SEC_ADMIN_OAUTH_PASS', _pub.env('SEC_TEST_PASSWORD', ''))
    user_pwd = os.environ.get('SEC_USER_OAUTH_PASS', 'Secauto#2026')
    a = token('admin00', admin_pwd)
    u = token('secauto_a1', user_pwd)
    if not a or not u:
        gc.emit('idor_h5', 'application', 'BLOCKED', [], blocked_reason='OAuth token 获取失败')
        return
    findings = []
    checks = []
    for path in ENDPOINTS:
        (ra, ru) = (call(path, a), call(path, u))
        checks.append({'path': path, 'admin': ra, 'user': ru})
        if ru.get('code') in (0, '0', 1, '1') and ra.get('code') in (0, '0', 1, '1'):
            if ru.get('len') and ra.get('len') and (abs(ru['len'] - ra['len']) < 50):
                findings.append(gc.finding('IDOR-H5-COMPANY', 'medium', f'普通用户与管理员返回相同数据（需确认通讯录设计）：{path}', evidence=json.dumps(checks[-1], ensure_ascii=False)[:400], remediation='按部门/角色过滤；敏感字段脱敏'))
    gc.emit('idor_h5', 'application', 'PASS', findings, summary=json.dumps({'checks': checks}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
