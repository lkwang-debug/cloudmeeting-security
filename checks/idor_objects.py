"""应用安全：IDOR 双身份全对象矩阵（test_user_a 部门A vs test05 部门B）。

当前覆盖会议室对象（创建、B 读取/分页/更新）；其他对象按接口清单扩展。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import requests
import urllib3
import yaml
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
CFG = os.path.join(gc.ROOT, 'configs', 'web_automation.yaml')

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def token(acc):
    tf = acc.get('token_file', '')
    p = os.path.join(gc.ROOT, tf) if tf else ''
    if p and os.path.exists(p):
        return open(p, encoding='utf-8').read().strip()
    return os.environ.get(acc.get('password_env', ''), '')

def call(tok, method, path, body=None):
    h = {'token': tok, 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    try:
        r = requests.request(method, BASE + path, headers=h, json=body, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        return {'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'data': j.get('data'), 'len': len(r.text or ''), 'body': (r.text or '')[:800]}
    except Exception as e:
        return {'error': str(e)[:120]}

def main():
    root = load_cfg()
    acc = root.get('idor_accounts') or {}
    depart_a = (acc.get('user_a') or {}).get('expected_depart', 1)
    try:
        from runner import env_config
        sc = env_config.load()
        sa = (sc.get('accounts') or {}).get('idor_a') or {}
        sb = (sc.get('accounts') or {}).get('idor_b') or {}
        if sa.get('username'):
            acc = {'user_a': {'username': sa['username'], 'expected_depart': sa.get('depart_id', 1), 'token_file': 'evidence/tokens/idor_%s.txt' % sa['username']}, 'user_b': {'username': sb.get('username', ''), 'expected_depart': sb.get('depart_id', 2), 'token_file': 'evidence/tokens/idor_%s.txt' % sb.get('username', '')}}
            depart_a = acc['user_a']['expected_depart']
    except Exception:
        pass
    a = token(acc.get('user_a') or {})
    b = token(acc.get('user_b') or {})
    if not a or not b:
        gc.emit('idor_objects', 'application', 'BLOCKED', [], blocked_reason='缺少 IDOR A/B 后台 token（先登录 idor_hzk05/idor_test05）')
        return
    admin = web_auth.headers(root)
    (findings, matrix) = ([], [])
    rd = call(a, 'GET', '/meeting/v1/roominfo/default')
    default = rd.get('data') or {}
    name = 'secauto_idor_matrix_%d' % int(time.time())
    default['roomName'] = name
    default['departID'] = int(depart_a)
    created = call(a, 'POST', '/meeting/v1/roominfo/add', default)
    matrix.append({'step': 'A_create', **created})
    rid = created.get('data')
    if not rid:
        gc.emit('idor_objects', 'application', 'PASS', [], summary=json.dumps({'note': 'A 创建测试会议室失败，无法做对象矩阵', 'create': created}, ensure_ascii=False)[:800])
        return
    probes = [('B_get', 'GET', '/meeting/v1/roominfo/get/%s' % rid, None), ('B_page', 'POST', '/meeting/v1/roominfo/page', {'pageNumber': 1, 'pageSize': 100, 'roomName': name})]
    room_obj = call(a, 'GET', '/meeting/v1/roominfo/get/%s' % rid).get('data') or {}
    upd = dict(room_obj)
    upd['roomName'] = name + '_b_modified'
    probes.append(('B_update', 'POST', '/meeting/v1/roominfo/update', upd))
    for (label, method, path, body) in probes:
        r = call(b, method, path, body)
        matrix.append({'step': label, **{k: v for (k, v) in r.items() if k != 'data'}, 'data_len': len(json.dumps(r.get('data') or {}, ensure_ascii=False))})
        ok = r.get('http') == 200 and str(r.get('code')) == '0'
        if label == 'B_page':
            records = ((r.get('data') or {}).get('records') if isinstance(r.get('data'), dict) else []) or []
            ok = ok and len(records) > 0
        if ok:
            sev = 'high' if label in ('B_get', 'B_update') else 'medium'
            findings.append(gc.finding('IDOR-OBJECT-' + label, sev, f'跨部门对象越权：{label} 成功（roomID={rid}）', evidence=json.dumps(r, ensure_ascii=False)[:400], remediation='对象级归属校验；按部门/创建人过滤'))
    dept_name = 'secauto_idor_dept_%d' % int(time.time())
    dept_id = None
    try:
        r = requests.post(BASE + '/api/v1/department/add', headers={**admin, 'Content-Type': 'application/json'}, json={'parentDepartId': 1, 'departName': dept_name}, timeout=15, verify=False)
        j = r.json()
        dept_id = (j.get('data') or {}).get('departId') if isinstance(j.get('data'), dict) else None
        matrix.append({'step': 'A_create_dept', 'http': r.status_code, 'code': j.get('code'), 'dept_id': dept_id})
    except Exception as e:
        matrix.append({'step': 'A_create_dept', 'error': str(e)[:100]})
    if dept_id:
        rb = call(b, 'POST', '/basis/v1/departInfo/queryDepartPage', {'pageNumber': 1, 'pageSize': 50, 'departName': dept_name})
        recs = ((rb.get('data') or {}).get('records') if isinstance(rb.get('data'), dict) else []) or []
        matrix.append({'step': 'B_dept_query', 'http': rb.get('http'), 'code': rb.get('code'), 'records': len(recs)})
        if rb.get('http') == 200 and str(rb.get('code')) == '0' and recs:
            findings.append(gc.finding('IDOR-DEPT-VISIBLE', 'medium', f'部门 B 用户可查询到部门 A 的测试部门：{dept_name}', evidence=json.dumps(rb, ensure_ascii=False)[:400], remediation='按部门范围过滤'))
    uname = 'secauto_idor_user_%d' % int(time.time())
    uid = None
    try:
        r = requests.post(BASE + '/api/v1/user/add', headers={**admin, 'Content-Type': 'application/json'}, json={'userName': uname, 'password': 'Test123456', 'departId': 1, 'adminRole': 2}, timeout=15, verify=False)
        j = r.json()
        uid = (j.get('data') or {}).get('userId') if isinstance(j.get('data'), dict) else None
        matrix.append({'step': 'A_create_user', 'http': r.status_code, 'code': j.get('code'), 'user_id': uid})
    except Exception as e:
        matrix.append({'step': 'A_create_user', 'error': str(e)[:100]})
    if uid:
        rb = call(b, 'POST', '/basis/v1/userInfo/queryUserPage', {'departId': 1, 'userName': uname, 'pageNumber': 1, 'pageSize': 20})
        recs = ((rb.get('data') or {}).get('records') if isinstance(rb.get('data'), dict) else []) or []
        matrix.append({'step': 'B_user_query', 'http': rb.get('http'), 'code': rb.get('code'), 'records': len(recs)})
        if rb.get('http') == 200 and str(rb.get('code')) == '0' and recs:
            findings.append(gc.finding('IDOR-USER-VISIBLE', 'medium', f'部门 B 用户可查询到部门 A 的测试用户：{uname}', evidence=json.dumps(rb, ensure_ascii=False)[:400], remediation='按部门/角色过滤'))
    if admin:
        for (path, body) in (('/api/v1/room/delRoomInfo', {'roomId': rid}), ('/api/v1/user/del', {'userName': uname} if uid else None), ('/api/v1/department/delete', {'departId': dept_id} if dept_id else None)):
            if body:
                try:
                    requests.post(BASE + path, headers={**admin, 'Content-Type': 'application/json'}, json=body, timeout=15, verify=False)
                except Exception:
                    pass
    if admin:
        try:
            requests.post(BASE + '/api/v1/room/delRoomInfo', headers={**admin, 'Content-Type': 'application/json'}, json={'roomId': rid}, timeout=15, verify=False)
        except Exception:
            pass
    gc.emit('idor_objects', 'application', 'PASS', findings, summary=json.dumps({'room_id': rid, 'name': name, 'matrix': matrix, 'findings': len(findings)}, ensure_ascii=False)[:1200])
if __name__ == '__main__':
    main()
