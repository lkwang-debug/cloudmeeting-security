"""P0 核心越权矩阵（只读 GET 管理接口，6 类身份）。
判定：正例 admin 必须成功；普通/跨组织/匿名/失效 token 不得获得管理数据。
输出：reports/p0/rbac_matrix.json + RBAC_MATRIX.md
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
TOKENS = os.path.join(ROOT, 'evidence', 'tokens')
OUT = os.path.join(ROOT, 'reports', 'p0')
IDENTITIES = {'admin': 'admin.txt', 'user_a': 'user_a.txt', 'user_b': 'user_b.txt', 'cross_org_c': 'cross_org_c.txt', 'anonymous': None, 'expired': os.path.join(ROOT, 'evidence', 'admin_token.p0.txt')}
ADMIN_ENDPOINTS = [('onlineUserEdit', 'GET', '/basis/v1/userInfo/onlineUserEdit', None), ('conf_oldCount', 'GET', '/serv/v1/conf/oldCount', None), ('conf_list', 'GET', '/serv/v1/conf/list', None), ('moduleVersions', 'GET', '/serv/v1/index/moduleVersions', None)]
HORIZONTAL_QUERIES = [('onlineUserEdit?userId=10000', '/basis/v1/userInfo/onlineUserEdit', {'userId': '10000'}), ('onlineUserEdit?userId=1000000011', '/basis/v1/userInfo/onlineUserEdit', {'userId': '1000000011'})]

def read_token(name):
    rel = IDENTITIES.get(name)
    if not rel:
        return ''
    p = rel if os.path.isabs(rel) else os.path.join(TOKENS, rel)
    if not os.path.exists(p):
        return ''
    return open(p, encoding='utf-8').read().strip()

def call(path, method='GET', token='', params=None):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'zh-CN,zh;q=0.9'}
    if token:
        h['token'] = token
    q = {'t': str(int(time.time() * 1000))}
    if params:
        q.update(params)
    try:
        r = requests.request(method, BASE + path, headers=h, params=q, timeout=20, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:200]}
        return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg') or j.get('resMessage'), 'keys': list(j.keys()), 'body': json.dumps(j, ensure_ascii=False)[:400]}
    except Exception as e:
        return {'http': None, 'error': str(e)[:200]}

def main():
    os.makedirs(OUT, exist_ok=True)
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'matrix': []}
    for (ep_name, method, path, params) in ADMIN_ENDPOINTS:
        row = {'endpoint': ep_name, 'path': path, 'method': method, 'identities': {}}
        for ident in IDENTITIES:
            tok = read_token(ident)
            r = call(path, method, tok, params)
            r['has_token'] = bool(tok)
            success = r.get('http') == 200 and str(r.get('code')) == '0'
            r['admin_data'] = success
            row['identities'][ident] = r
        admin_ok = row['identities']['admin'].get('admin_data')
        leaks = [i for i in ('user_a', 'user_b', 'cross_org_c', 'anonymous', 'expired') if row['identities'][i].get('admin_data')]
        row['positive_control_ok'] = bool(admin_ok)
        row['negative_leaks'] = leaks
        admin_only = ep_name in ('onlineUserEdit', 'conf_list')
        row['admin_only'] = admin_only
        if not admin_ok:
            row['verdict'] = 'BASELINE_PUBLIC_OR_BROKEN'
        elif not admin_only:
            row['verdict'] = 'BASELINE_PUBLIC'
        else:
            row['verdict'] = 'NO_FINDING' if not leaks else 'POSSIBLE_VERTICAL'
        result['matrix'].append(row)
    horiz = []
    for (name, path, params) in HORIZONTAL_QUERIES:
        row = {'probe': name, 'path': path, 'identities': {}}
        for ident in ('user_a', 'user_b', 'cross_org_c'):
            tok = read_token(ident)
            r = call(path, 'GET', tok, params)
            row['identities'][ident] = r
        horiz.append(row)
    result['horizontal'] = horiz
    with open(os.path.join(OUT, 'rbac_matrix.json'), 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    lines = ['# P0 核心越权矩阵（只读）', '', f"- 时间：{result['generated_at']}", f'- 目标：{BASE}', '', '| 接口 | admin 正例 | user_a | user_b | cross_org_c | anonymous | expired(旧token) | 判定 |', '|---|---|---|---|---|---|---|---|']
    for row in result['matrix']:

        def cell(i):
            r = row['identities'][i]
            if r.get('error'):
                return 'ERR'
            return f"{r.get('http')}/code={r.get('code')}"
        lines.append(f"| {row['endpoint']} | {cell('admin')} | {cell('user_a')} | {cell('user_b')} | {cell('cross_org_c')} | {cell('anonymous')} | {cell('expired')} | {row['verdict']} |")
    lines += ['', '## 水平越权探测（传他人 userId）', '']
    for row in horiz:
        lines.append(f"### {row['probe']}")
        for (ident, r) in row['identities'].items():
            lines.append(f"- {ident}: http={r.get('http')} code={r.get('code')} body={r.get('body', '')[:160]}")
    lines += ['', '## 说明', '', '- 正例：admin 调用成功（code=0）才说明接口与 token 有效；', '- 负例：普通/跨组织/匿名/失效 token 不得返回管理数据（code=0 视为可能垂直越权）；', '- 水平探测：普通用户携带他人 userId 时，若返回他人资料则为越权（需人工核对返回内容归属）。']
    open(os.path.join(OUT, 'RBAC_MATRIX.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    for row in result['matrix']:
        print(row['endpoint'], 'positive=', row['positive_control_ok'], 'leaks=', row['negative_leaks'], 'verdict=', row['verdict'])
    print('written:', os.path.join(OUT, 'RBAC_MATRIX.md'))
if __name__ == '__main__':
    main()
