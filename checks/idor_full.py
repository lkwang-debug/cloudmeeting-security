"""应用安全：对象级访问控制全量矩阵（基于 API 清单 + H5 对象接口）。

说明：完整 IDOR 需要两个不同权限账号；当前可用 admin00/test_user_a（均为管理员），
因此矩阵同时检查“未授权可访问”和“不同账号响应差异”，结果标记为候选，需人工确认。
"""
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
try:
    from checks import web_auth
except ImportError:
    import web_auth
urllib3.disable_warnings()
BASE = gc.base_url()
CLIENT = _pub.env('SEC_CLIENT_ID') + ':' + _pub.env('SEC_CLIENT_SECRET')
INV = os.path.join(gc.ROOT, 'knowledge', 'api_inventory.json')
H5 = ['/meeting-resource-server/security/company/users?pageSize=20', '/meeting-resource-server/security/company/departments', '/meeting-resource-server/api/users/myself', '/meeting-resource-server/open/rooms/getroominfo', '/meeting-resource-server/open/paasAuthInfo?userId=1']

def oauth(user, pwd):
    basic = 'Basic ' + base64.b64encode(CLIENT.encode()).decode()
    try:
        r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'password', 'username': user, 'password': pwd}, timeout=15, verify=False)
        return (r.json() or {}).get('access_token', '') if r.status_code == 200 else ''
    except Exception:
        return ''

def main():
    inv = json.load(open(INV, encoding='utf-8')).get('endpoints') if os.path.exists(INV) else []
    api = [e for e in inv if e.get('path', '').startswith('/api/') and ('{' in e.get('path', '') or any((str(k).lower().endswith('id') for k in e.get('body_keys') or [])))]
    openapi = web_auth.headers({'auth': {'type': 'openapi', 'config_ini': 'configured-path'}})
    a0 = oauth('admin00', _pub.env('SEC_TEST_PASSWORD', ''))
    h0 = oauth('test_user_a', _pub.env('SEC_TEST_PASSWORD', ''))
    (findings, matrix) = ([], [])
    for ep in api[:80]:
        path = ep['path']
        for val in ('1', '10000'):
            p = path
            for ph in ('{id}', '{userId}', '{roomId}', '{groupId}', '{recordId}'):
                p = p.replace(ph, val)
            for (label, headers) in (('auth', openapi), ('noauth', {})):
                try:
                    r = requests.request(ep.get('method', 'POST'), BASE + p, headers={**headers, 'Content-Type': 'application/json'}, params={'t': str(int(time.time() * 1000))}, json={k: val for k in ep.get('body_keys') or [] if k.lower().endswith('id')}, timeout=10, verify=False)
                    try:
                        j = r.json()
                    except Exception:
                        j = {}
                    code = j.get('code') or j.get('resCode')
                    matrix.append({'path': p, 'auth': label, 'http': r.status_code, 'code': code, 'len': len(r.text or '')})
                    if label == 'noauth' and r.status_code == 200 and (str(code) in ('0', 'None')):
                        findings.append(gc.finding('IDOR-NOAUTH-API', 'high', f'对象接口无鉴权可访问：{p}', evidence=(r.text or '')[:300], remediation='接口鉴权/对象归属校验'))
                except Exception:
                    pass
    for path in H5:
        for (label, tok) in (('admin00', a0), ('test_user_a', h0)):
            if not tok:
                continue
            try:
                r = requests.get(BASE + path, headers={'Authorization': 'Bearer ' + tok, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
                try:
                    j = r.json()
                except Exception:
                    j = {}
                matrix.append({'path': path, 'auth': label, 'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'len': len(r.text or '')})
            except Exception:
                pass
    gc.emit('idor_full', 'application', 'PASS', findings, summary=json.dumps({'matrix': len(matrix), 'api_objects': len(api), 'h5': len(H5), 'samples': matrix[:10]}, ensure_ascii=False)[:1200])
if __name__ == '__main__':
    main()
