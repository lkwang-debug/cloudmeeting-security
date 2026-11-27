"""Week0 认证适配器 POC：OAuth2 Basic 与 fmapi MD5 签名。
凭据全部从环境变量读取，不写死、不落盘；结果中 token 打码。
只读认证测试：不写业务数据。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
from runner import public_config as _pub
import base64
import hashlib
import json
import os
import time
import urllib.parse
import requests
BASE = os.environ.get('SEC_TARGET', _pub.target())
GW = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1'}
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'reports', 'week0', 'auth_poc.json')
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def mask(s):
    if not s:
        return ''
    return s[:8] + '…' if len(s) > 8 else '***'

def oauth2_poc():
    cid = os.environ.get('SEC_CLIENT_ID', '')
    sec = os.environ.get('SEC_CLIENT_SECRET', '')
    user = os.environ.get('SEC_OAUTH_USER', '')
    pwd = os.environ.get('SEC_OAUTH_PASS', '')
    res = {'method': 'oauth2_basic', 'client_id_masked': mask(cid), 'checks': []}
    if not (cid and sec):
        res['status'] = 'blocked'
        res['blockers'] = ['SEC_CLIENT_ID/SEC_CLIENT_SECRET 未设置']
        return res
    basic = 'Basic ' + base64.b64encode(f'{cid}:{sec}'.encode()).decode()
    url = BASE + '/meeting-resource-server/oauth2/token'
    headers = dict(GW, **{'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': basic})
    body = {'grant_type': 'password', 'username': user, 'password': pwd, 'scope': 'all'}
    t0 = time.time()
    try:
        r = requests.post(url, data=body, headers=headers, timeout=20, verify=False)
        dt = time.time() - t0
        res['checks'].append({'name': 'password_grant', 'http': r.status_code, 'elapsed_ms': round(dt * 1000), 'has_token': 'access_token' in r.text})
        if r.status_code == 200:
            j = r.json()
            res['expires_in'] = j.get('expires_in')
            res['token_type'] = j.get('token_type')
            res['access_token_masked'] = mask(j.get('access_token', ''))
            tok_h = dict(GW, **{'Authorization': 'Bearer ' + j.get('access_token', '')})
            r2 = requests.get(BASE + '/meeting-resource-server/api/users/myself', headers=tok_h, timeout=20, verify=False)
            res['checks'].append({'name': 'token_use', 'http': r2.status_code, 'resCode': r2.json().get('resCode') if r2.headers.get('content-type', '').startswith('application/json') else None})
    except Exception as e:
        res['checks'].append({'name': 'password_grant', 'error': str(e)[:200]})
    try:
        r = requests.post(url, data={'grant_type': 'client_credentials', 'scope': 'all'}, headers=headers, timeout=20, verify=False)
        res['checks'].append({'name': 'client_credentials_negative', 'http': r.status_code})
    except Exception as e:
        res['checks'].append({'name': 'client_credentials_negative', 'error': str(e)[:200]})
    bad = 'Basic ' + base64.b64encode(f"{cid}:{'0' * 36}".encode()).decode()
    try:
        r = requests.post(url, data={'grant_type': 'password', 'username': user, 'password': pwd, 'scope': 'all'}, headers=dict(GW, **{'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': bad}), timeout=20, verify=False)
        res['checks'].append({'name': 'wrong_secret_negative', 'http': r.status_code})
    except Exception as e:
        res['checks'].append({'name': 'wrong_secret_negative', 'error': str(e)[:200]})
    strong = [c for c in res['checks'] if c.get('name') in ('password_grant', 'wrong_secret_negative') and c.get('http') in (200, 401)]
    res['status'] = 'ok' if len(strong) == 2 else 'partial'
    return res

def fmapi_poc():
    appkey = os.environ.get('SEC_FMAPI_APPKEY', '')
    res = {'method': 'fmapi_md5', 'checks': []}
    if not appkey:
        res['status'] = 'blocked'
        res['blockers'] = ['SEC_FMAPI_APPKEY 未设置']
        return res
    ver = os.environ.get('SEC_FMAPI_VERSION', '03.44.80.01')
    ts = str(int(time.time() * 1000))
    sign = hashlib.md5((appkey + appkey + ver + ts).encode()).hexdigest().upper()
    body = {'appkey': appkey, 'productId': os.environ.get('SEC_FMAPI_PRODUCT', 'FMS002ZXNRTA20200603'), 'version': ver, 'timestamp': ts, 'sign': sign}
    try:
        r = requests.post(BASE + '/fmapi/servers/addresses', json=body, headers=dict(GW, **{'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1'}), timeout=20, verify=False)
        j = {}
        try:
            j = r.json()
        except Exception:
            pass
        res['checks'].append({'name': 'signed_request', 'http': r.status_code, 'code': j.get('code'), 'groups': len(j.get('result') or [])})
        res['status'] = 'ok' if r.status_code == 200 else 'partial'
    except Exception as e:
        res['checks'].append({'name': 'signed_request', 'error': str(e)[:200]})
        res['status'] = 'error'
    return res

def main():
    import urllib3
    urllib3.disable_warnings()
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'oauth2': oauth2_poc(), 'fmapi': fmapi_poc()}
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v.get('status') for (k, v) in result.items() if isinstance(v, dict) and 'status' in v}, ensure_ascii=False))
    print('written:', OUT)
if __name__ == '__main__':
    main()
