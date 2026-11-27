"""回归用例：自定义角色菜单权限 + 角色变更后的权限缓存失效验证。
期望（修复后）：
  Phase1: 菜单 9 角色 → 授权接口 0，未授权接口 1003（PASS）
  Phase2: 角色改为空菜单并重新登录 → 旧授权接口应返回 1003（PASS）；若仍返回 0 则 FAIL（缓存未失效缺陷）
用法：
  set SEC_BACKEND_PASS=...
  python checks/regression_role_cache.py
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import json
import os
import subprocess
import sys
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
TOK_ADMIN = os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt')
OUT = os.path.join(ROOT, 'reports', 'final', 'regression_role_cache.json')
TEST_USER = 'admin06'
TEST_UID = None
TS = time.strftime('%m%d%H%M%S')

def admin_headers():
    tok = open(TOK_ADMIN, encoding='utf-8').read().strip()
    return {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}

def post(path, body):
    r = requests.post(BASE + path, headers=admin_headers(), params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:150]})

def get(path, params=None):
    q = {'t': str(int(time.time() * 1000))}
    if params:
        q.update(params)
    r = requests.get(BASE + path, headers=admin_headers(), params=q, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:150]})

def find_role(name):
    (st, j) = post('/basis/v1/role/list', {'pageSize': 100, 'pageNumber': 1})
    for r in (j.get('data') or {}).get('records') or []:
        if r.get('name') == name:
            return r.get('id')
    return None

def create_role(priv):
    name = f"secauto_reg_{TS}_{('m9' if priv else 'empty')}"
    (st, j) = post('/basis/v1/role/add', {'id': '', 'name': name, 'desc': 'regression', 'privileges': priv})
    rid = find_role(name)
    return (rid, name, st, j)

def assign(rid, users):
    return post('/basis/v1/role/user', {'roleId': rid, 'users': users})

def login(username, tag):
    cmd = [sys.executable, os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py'), '--target', _pub.target(), '--username', username, '--password-env', 'SEC_BACKEND_PASS', '--attempts', '2', '--out', os.path.join(ROOT, 'evidence', 'tokens', f'reg_{username}.txt'), '--evidence-dir', os.path.join(ROOT, 'evidence', 'raw', f'reg_{username}_{tag}')]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)
    resp = os.path.join(ROOT, 'evidence', 'raw', f'reg_{username}_{tag}', 'login_response.json')
    code = None
    if os.path.exists(resp):
        try:
            code = json.load(open(resp, encoding='utf-8-sig')).get('code')
        except Exception:
            pass
    tok_path = os.path.join(ROOT, 'evidence', 'tokens', f'reg_{username}.txt')
    tok = open(tok_path, encoding='utf-8').read().strip() if os.path.exists(tok_path) else ''
    return {'login_code': code, 'token_len': len(tok), 'token': tok}

def api(tok, method, path, body=None):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    r = requests.request(method, BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        j = r.json()
    except Exception:
        j = {'raw': r.text[:150]}
    return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg')}

def sql_get_uid(username):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    cmd = f'''{'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + """ --ssl-mode=REQUIRED fastmeeting -N -e "SELECT UserID FROM t_userinfo WHERE UserName='"""}{username}';" 2>/dev/null'''
    (i, o, e) = c.exec_command(cmd, timeout=60)
    res = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
    c.close()
    return int(res.splitlines()[0]) if res.strip().isdigit() else None

def sql_get_adminrole(uid):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    cmd = f"""{'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e "SELECT AdminRole FROM t_userinfo WHERE UserID='}{uid};" 2>/dev/null"""
    (i, o, e) = c.exec_command(cmd, timeout=60)
    res = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
    c.close()
    return res

def sql_update_adminrole(uid, role):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    cmd = f'''{'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + """ --ssl-mode=REQUIRED fastmeeting -N -e "UPDATE t_userinfo SET AdminRole='"""}{role}' WHERE UserID={uid};" 2>&1 | grep -v Warning'''
    (i, o, e) = c.exec_command(cmd, timeout=60)
    res = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
    c.close()
    return res

def clear_cache(uid):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    R = 'docker exec hst-redis redis-cli -h ' + _pub.shell('SEC_DB_HOST') + ' -p 22002 -a ' + _pub.shell('SEC_REDIS_PASSWORD') + ' -n 0 '
    out = []
    for k in (f'AUTH::AUTH_PRI_{uid}', f'AUTH::AUTH_PRI_MENU_{uid}'):
        (i, o, e) = c.exec_command(R + f'del {k} 2>/dev/null', timeout=60)
        out.append((k, (o.read().decode() + e.read().decode()).strip()))
    c.close()
    return out

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    global TEST_UID
    TEST_UID = sql_get_uid(TEST_USER)
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'user': TEST_USER, 'uid': TEST_UID, 'steps': [], 'verdict': 'UNKNOWN'}
    try:
        (rid1, name1, st, j) = create_role([9])
        res['phase1'] = {'role_id': rid1, 'role_add': {'http': st, 'code': j.get('code')}}
        if rid1:
            assign(rid1, [TEST_UID])
            res['phase1']['db_adminrole_after_assign'] = sql_get_adminrole(TEST_UID)
            lg = login(TEST_USER, 'p1')
            res['phase1']['login'] = {'code': lg['login_code'], 'token_len': lg['token_len']}
            if lg['login_code'] == '0' and lg['token_len'] > 20:
                tests = {'granted_queryDepartTree': api(lg['token'], 'GET', '/basis/v1/departInfo/queryDepartTree'), 'granted_queryDepartPage': api(lg['token'], 'POST', '/basis/v1/departInfo/queryDepartPage', {'pageNumber': 1, 'pageSize': 10, 'parentDepartId': 0, 'departName': ''}), 'denied_conf_list': api(lg['token'], 'GET', '/serv/v1/conf/list'), 'denied_role_list': api(lg['token'], 'POST', '/basis/v1/role/list', {'pageSize': 10, 'pageNumber': 1})}
                res['phase1']['tests'] = tests
                ok = str(tests['granted_queryDepartTree']['code']) == '0' and str(tests['denied_conf_list']['code']) == '1003' and (str(tests['denied_role_list']['code']) == '1003')
                res['phase1']['pass'] = ok
            else:
                res['phase1']['pass'] = False
        (rid2, name2, st, j) = create_role([])
        res['phase2'] = {'role_id': rid2}
        if rid2 and rid1:
            assign(rid2, [TEST_UID])
            res['phase2']['db_adminrole_after_assign'] = sql_get_adminrole(TEST_UID)
            lg2 = login(TEST_USER, 'p2')
            res['phase2']['login'] = {'code': lg2['login_code'], 'token_len': lg2['token_len']}
            if lg2['login_code'] == '0' and lg2['token_len'] > 20:
                t = api(lg2['token'], 'GET', '/basis/v1/departInfo/queryDepartTree')
                res['phase2']['queryDepartTree_after_downgrade'] = t
                res['phase2']['pass'] = str(t['code']) == '1003'
            else:
                res['phase2']['pass'] = False
        if res.get('phase1', {}).get('pass') and res.get('phase2', {}).get('pass'):
            res['verdict'] = 'PASS'
        elif res.get('phase1', {}).get('pass') and res.get('phase2', {}).get('pass') is False:
            res['verdict'] = 'FAIL_CACHE_INVALIDATION'
        else:
            res['verdict'] = 'INCONCLUSIVE'
    finally:
        try:
            for (rid, nm) in ((locals().get('rid2'), locals().get('name2')), (locals().get('rid1'), locals().get('name1'))):
                if rid:
                    get('/basis/v1/role/del', {'id': rid})
            sql_update_adminrole(TEST_UID, 11)
            clear_cache(TEST_UID)
            res['cleanup'] = 'done'
        except Exception as e:
            res['cleanup'] = 'error: ' + str(e)[:200]
        json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(json.dumps(res, ensure_ascii=False, indent=1)[:2500])
if __name__ == '__main__':
    main()
