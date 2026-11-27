"""应用安全：认证令牌专项（refresh_token 篡改、密码哈希/敏感字段泄露）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import json
import re
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
MD5_RE = re.compile('\\b[0-9a-fA-F]{32}\\b')

def basic():
    return 'Basic ' + base64.b64encode(CLIENT.encode()).decode()

def oauth_token():
    """用测试管理员取 OAuth2 token（仅测试环境）。"""
    for (user, pwd) in (('admin00', _pub.env('SEC_TEST_PASSWORD', '')), ('test00', _pub.env('SEC_TEST_PASSWORD', ''))):
        try:
            r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic(), 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'password', 'username': user, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
            if r.status_code == 200 and r.json().get('access_token'):
                return (r.json()['access_token'], user)
        except Exception:
            continue
    return ('', '')

def main():
    findings = []
    checks = {}
    for rt in ('admin', '', 'null'):
        try:
            r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers={'Authorization': basic(), 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'refresh_token', 'refresh_token': rt}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
            body = {}
            try:
                body = r.json()
            except Exception:
                pass
            checks[f"refresh_admin_{rt or 'empty'}"] = {'http': r.status_code, 'access_token': bool(body.get('access_token'))}
            if r.status_code == 200 and body.get('access_token'):
                findings.append(gc.finding('AUTH-REFRESH-BYPASS', 'critical', f"refresh_token='{rt}' 可换取 Token（认证绕过）", evidence=json.dumps(checks, ensure_ascii=False)[:300], remediation='严格校验 refresh_token 签名/绑定；禁止固定/空值'))
        except Exception as e:
            checks[f'refresh_{rt}'] = {'error': str(e)[:100]}
    (tok, user) = oauth_token()
    checks['oauth_user'] = user
    if tok:
        for path in ('/meeting-resource-server/api/users/myself', '/meeting-resource-server/security/company/users?pageSize=5'):
            try:
                r = requests.get(BASE + path, headers={'Authorization': 'Bearer ' + tok, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'User-Agent': 'Mozilla/5.0'}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
                text = r.text or ''
                hashes = MD5_RE.findall(text)
                pvals = [v for v in re.findall('"password"\\s*:\\s*"([^"]*)"', text) if v.strip()]
                checks[path] = {'http': r.status_code, 'md5_like': len(hashes), 'nonempty_password': len(pvals), 'has_password_field': '"password"' in text.lower()}
                if hashes or (pvals and r.status_code == 200):
                    findings.append(gc.finding('AUTH-HASH-LEAK', 'high', f'{path} 返回密码哈希/敏感字段', evidence=text[:300], remediation='响应脱敏；密码改用强哈希'))
            except Exception as e:
                checks[path] = {'error': str(e)[:100]}
    else:
        checks['oauth'] = 'no token'
    gc.emit('auth_token_checks', 'application', 'PASS', findings, summary=json.dumps(checks, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
