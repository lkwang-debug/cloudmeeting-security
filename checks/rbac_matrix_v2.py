"""P0 扩展越权矩阵：基于真实登录发现的 29 个后台接口，做 read-only 身份矩阵 + 水平探测。
不写业务数据。输出 reports/p0/rbac_matrix_v2.json + RBAC_MATRIX_V2.md
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
ENDPOINTS = [('GET', '/serv/v1/conf/list', {'type': '1'}), ('GET', '/serv/v1/conf/category', {}), ('GET', '/serv/v1/conf/initial', {'devType': '1'}), ('GET', '/serv/v1/sys/setting/logger', {}), ('GET', '/serv/v1/sys/setting/mail', {}), ('GET', '/serv/v1/sys/setting/mapping', {}), ('GET', '/serv/v1/sys/setting/port', {}), ('GET', '/basis/v1/nodeAuth/queryNodeAuthInfo', {}), ('GET', '/basis/v1/groups', {}), ('GET', '/basis/v1/client-functions', {}), ('GET', '/basis/v1/client-functions/defaults', {}), ('GET', '/basis/v1/departInfo/queryDepartTree', {}), ('GET', '/serv/v1/recording/getServerMemory/1', {}), ('GET', '/serv/v1/recording/paastask', {'curPage': '1', 'pageSize': '10'}), ('POST', '/basis/v1/userInfo/queryUserPage', {'departId': 0, 'userName': '', 'displayName': '', 'pageNumber': 1, 'pageSize': 10}), ('POST', '/basis/v1/departInfo/queryDepartPage', {'pageNumber': 1, 'pageSize': 10, 'parentDepartId': 0, 'departName': ''}), ('POST', '/basis/v1/departInfo/departTreeSearch', {'departId': 0, 'excludeSub': False, 'searchDeptName': ''}), ('POST', '/basis/v1/role/list', {'pageSize': 10, 'pageNumber': 1}), ('POST', '/serv/v1/terminal/page', {'pageNumber': 1, 'pageSize': 10, 'departId': 0, 'terminalName': '', 'terminalNum': ''}), ('POST', '/serv/v1/ai/model/page', {'pageNumber': 1, 'pageSize': 10}), ('POST', '/serv/v1/user/list', {'pageNumber': 1, 'pageSize': 10}), ('POST', '/serv/v1/role/list', {'pageNumber': 1, 'pageSize': 10})]
IDENTS = ['admin', 'user_a', 'user_b', 'cross_org_c']
ANON = 'anonymous'

def token(name):
    p = os.path.join(TOK, f'{name}.txt')
    return open(p, encoding='utf-8').read().strip() if os.path.exists(p) else ''

def call(method, path, tok, q=None, body=None):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'zh-CN,zh;q=0.9'}
    if tok:
        h['token'] = tok
    params = {'t': str(int(time.time() * 1000))}
    if q:
        params.update(q)
    try:
        if method == 'GET':
            r = requests.get(BASE + path, headers=h, params=params, timeout=20, verify=False)
        else:
            r = requests.post(BASE + path, headers=dict(h, **{'Content-Type': 'application/json'}), params=params, json=body or {}, timeout=20, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:200]}
        data = j.get('data')
        text = json.dumps(j, ensure_ascii=False)
        return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg') or j.get('resMessage'), 'n': len(text), 'has_secret': any((k in text for k in ('password', 'secret', 'token', 'sysmanager', 'test_user_a'))), 'body': text[:300]}
    except Exception as e:
        return {'http': None, 'error': str(e)[:150]}

def main():
    admin = token('admin')
    rows = []
    for (method, path, q) in ENDPOINTS:
        row = {'method': method, 'path': path, 'identities': {}}
        for ident in IDENTS:
            row['identities'][ident] = call(method, path, token(ident), q)
        row['identities'][ANON] = call(method, path, '', q)
        adm = row['identities']['admin']
        row['admin_ok'] = str(adm.get('code')) == '0'
        row['accessible_to_normal'] = [i for i in ('user_a', 'user_b', 'cross_org_c', ANON) if str(row['identities'][i].get('code')) == '0']
        rows.append(row)
        print(f"{method:5} {path:55} admin={adm.get('code')} normal_ok={row['accessible_to_normal']}")
    horiz = []
    cross = token('cross_org_c')
    for (name, method, path, q, body) in [('queryUserPage_departA', 'POST', '/basis/v1/userInfo/queryUserPage', None, {'departId': 355, 'pageNumber': 1, 'pageSize': 50}), ('queryDepartPage_departA', 'POST', '/basis/v1/departInfo/queryDepartPage', None, {'pageNumber': 1, 'pageSize': 50, 'parentDepartId': 355, 'departName': ''}), ('queryUserPage_all', 'POST', '/basis/v1/userInfo/queryUserPage', None, {'departId': 0, 'pageNumber': 1, 'pageSize': 10})]:
        r = call(method, path, cross, q, body)
        r['probe'] = name
        r['contains_secauto_a'] = 'secauto_a' in r.get('body', '')
        horiz.append(r)
        print(f"HORIZ {name}: code={r.get('code')} containsA={r['contains_secauto_a']}")
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'matrix': rows, 'horizontal': horiz}
    os.makedirs(OUT, exist_ok=True)
    json.dump(result, open(os.path.join(OUT, 'rbac_matrix_v2.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# P0 扩展越权矩阵（真实登录发现接口，只读）', '', f"- 时间：{result['generated_at']}", f'- 目标：{BASE}', '', '| 接口 | admin 正例 | 可访问的普通/匿名身份 | 判定 |', '|---|---|---|---|']
    for r in rows:
        if not r['admin_ok']:
            verdict = 'BASELINE_OR_UNKNOWN'
        elif not r['accessible_to_normal']:
            verdict = 'NO_FINDING（仅管理员可访问）'
        else:
            verdict = 'MANUAL_REVIEW（普通身份可访问）'
        lines.append(f"| {r['method']} {r['path']} | {r['identities']['admin'].get('code')} | {','.join(r['accessible_to_normal']) or '-'} | {verdict} |")
    lines += ['', '## 水平越权探测（cross_org_c 查询 A 部门 355）', '']
    for h in horiz:
        lines.append(f"- {h['probe']}: http={h.get('http')} code={h.get('code')} 含 secauto_a={h.get('contains_secauto_a')} body={h.get('body', '')[:160]}")
    lines += ['', '## 说明', '', '- admin code=0 视为正例有效；普通/匿名 code=0 计入 MANUAL_REVIEW（需核对返回数据是否越权）；', '- 水平探测：跨组织用户查询 A 部门数据，若返回 secauto_a 用户则可能水平越权。']
    open(os.path.join(OUT, 'RBAC_MATRIX_V2.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print('written:', os.path.join(OUT, 'RBAC_MATRIX_V2.md'))
if __name__ == '__main__':
    main()
