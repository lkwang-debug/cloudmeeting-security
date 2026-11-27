"""P0 写路径越权测试（只操作 secauto_* 对象）：
1) 对写接口用无效体探测 admin/普通用户权限判定；
2) 真实创建 1 个测试用户（admin），验证普通用户无法新增/修改，最后清理。
输出 reports/p0/write_path_rbac.json + WRITE_PATH.md
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
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
TOK = os.path.join(ROOT, 'evidence', 'tokens')
OUT = os.path.join(ROOT, 'reports', 'p0')
TS = time.strftime('%m%d%H%M%S')
NEW_USER = f'secauto_w1_{TS}'
WRITE_ENDPOINTS = [('POST', '/basis/v1/userInfo/addUser'), ('POST', '/basis/v1/userInfo/updateUser'), ('POST', '/basis/v1/userInfo/batchDelete'), ('POST', '/basis/v1/departInfo/addDepart'), ('POST', '/basis/v1/departInfo/updateDepart'), ('POST', '/basis/v1/departInfo/deleteDepartByIds'), ('POST', '/basis/v1/role/add'), ('POST', '/basis/v1/role/modify'), ('POST', '/serv/v1/terminal/add'), ('POST', '/serv/v1/terminal/update'), ('POST', '/serv/v1/terminal/delete'), ('POST', '/serv/v1/conf/add'), ('POST', '/serv/v1/conf/delete')]

def token(name):
    p = os.path.join(TOK, f'{name}.txt')
    return open(p, encoding='utf-8').read().strip() if os.path.exists(p) else ''

def call(method, path, tok, body):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'zh-CN,zh;q=0.9', 'Content-Type': 'application/json'}
    if tok:
        h['token'] = tok
    try:
        r = requests.request(method, BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body if body is not None else {}, timeout=20, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:200]}
        return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg') or j.get('resMessage'), 'body': json.dumps(j, ensure_ascii=False)[:400]}
    except Exception as e:
        return {'http': None, 'error': str(e)[:150]}

def main():
    admin = token('admin')
    ua = token('user_a')
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'probe': [], 'real_write': {}}
    print('== 写接口权限探测（无效体） ==')
    for (method, path) in WRITE_ENDPOINTS:
        a = call(method, path, admin, {})
        u = call(method, path, ua, {})
        row = {'method': method, 'path': path, 'admin': a, 'user_a': u}
        row['admin_reachable'] = str(a.get('code')) != '1002' and a.get('http') != 404
        row['user_denied'] = str(u.get('code')) == '1002'
        row['possible_write_priv'] = row['admin_reachable'] and (not row['user_denied'])
        result['probe'].append(row)
        print(f"  {path:42} admin={a.get('code')} user_a={u.get('code')} reachable={row['admin_reachable']} user_denied={row['user_denied']}")
    print('\n== 真实写路径（secauto 用户） ==')
    body = {'userName': NEW_USER, 'password': 'Secauto#2026', 'passwordType': 1, 'email': 'secauto@example.com', 'mobile': '13800000000', 'nickName': NEW_USER, 'sex': 0, 'telePhone': '0000000', 'departId': 355, 'adminRole': 2}
    add = call('POST', '/basis/v1/userInfo/addUser', admin, body)
    print('  admin addUser:', add.get('http'), add.get('code'), add.get('msg'))
    result['real_write']['admin_add'] = add
    uid = None
    try:
        q = call('POST', '/basis/v1/userInfo/queryUserPage', admin, {'departId': 355, 'userName': NEW_USER, 'pageNumber': 1, 'pageSize': 10})
        result['real_write']['admin_query'] = q
        import re
        m = re.search('"userId":\\s*(\\d+)', q.get('body', ''))
        if m:
            uid = int(m.group(1))
        print('  query userId:', uid)
        add2 = call('POST', '/basis/v1/userInfo/addUser', ua, body)
        result['real_write']['user_a_add'] = add2
        print('  user_a addUser:', add2.get('http'), add2.get('code'))
        if uid:
            upd = call('POST', '/basis/v1/userInfo/updateUser', ua, {'userId': uid, 'userName': NEW_USER, 'displayName': 'hacked'})
            result['real_write']['user_a_update'] = upd
            print('  user_a updateUser:', upd.get('http'), upd.get('code'))
            dele = call('POST', '/basis/v1/userInfo/batchDelete', ua, {'userIds': [uid]})
            result['real_write']['user_a_delete'] = dele
            print('  user_a batchDelete:', dele.get('http'), dele.get('code'))
    finally:
        if uid:
            d = call('POST', '/basis/v1/userInfo/batchDelete', admin, {'userIds': [uid]})
            result['real_write']['admin_cleanup'] = d
            print('  admin cleanup:', d.get('http'), d.get('code'))
            q2 = call('POST', '/basis/v1/userInfo/queryUserPage', admin, {'departId': 355, 'userName': NEW_USER, 'pageNumber': 1, 'pageSize': 10})
            result['real_write']['cleanup_verify'] = q2
            print('  cleanup verify contains user:', NEW_USER in q2.get('body', ''))
    json.dump(result, open(os.path.join(OUT, 'write_path_rbac.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# P0 写路径越权测试（secauto_* 数据）', '', f"- 时间：{result['generated_at']}", f'- 目标：{BASE}', '', '## 1. 写接口权限探测（无效体，不产生数据）', '', '| 接口 | admin | user_a | 管理员可达 | 普通用户被拒 | 疑似写越权 |', '|---|---|---|---|---|---|']
    for r in result['probe']:
        lines.append(f"| {r['method']} {r['path']} | {r['admin'].get('code')} | {r['user_a'].get('code')} | {r['admin_reachable']} | {r['user_denied']} | {r['possible_write_priv']} |")
    lines += ['', '## 2. 真实写路径（创建测试用户 secauto_w1）', '']
    for (k, v) in result['real_write'].items():
        lines.append(f"- {k}: http={v.get('http')} code={v.get('code')} msg={v.get('msg')}")
    open(os.path.join(OUT, 'WRITE_PATH.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print('written:', os.path.join(OUT, 'WRITE_PATH.md'))
if __name__ == '__main__':
    main()
