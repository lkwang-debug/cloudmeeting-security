"""P0：后台管理接口探针（只读 GET/POST 空体），用 admin token 找真实接口，再用普通用户验证拒绝。
结果写入 reports/p0/backend_probe.json。
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
CANDIDATES = [('GET', '/serv/v1/user/list'), ('GET', '/serv/v1/user/query'), ('GET', '/serv/v1/user/page'), ('GET', '/serv/v1/users'), ('GET', '/serv/v1/depart/list'), ('GET', '/serv/v1/department/list'), ('GET', '/serv/v1/depart/tree'), ('GET', '/serv/v1/room/list'), ('GET', '/serv/v1/room/page'), ('GET', '/serv/v1/room/query'), ('GET', '/serv/v1/record/list'), ('GET', '/serv/v1/record/page'), ('GET', '/serv/v1/log/list'), ('GET', '/serv/v1/operationlog/list'), ('GET', '/serv/v1/terminal/list'), ('GET', '/serv/v1/role/list'), ('GET', '/serv/v1/conf/list'), ('GET', '/serv/v1/conf/query'), ('GET', '/serv/v1/meeting/list'), ('GET', '/serv/v1/statistics'), ('GET', '/serv/v1/index/count'), ('GET', '/serv/v1/userLevel/list'), ('GET', '/serv/v1/depart/user'), ('GET', '/serv/v1/online/list'), ('GET', '/basis/v1/userInfo/list'), ('GET', '/basis/v1/user/list'), ('GET', '/basis/v1/role/list'), ('POST', '/serv/v1/user/list'), ('POST', '/serv/v1/depart/list'), ('POST', '/serv/v1/room/list'), ('POST', '/serv/v1/record/list'), ('POST', '/serv/v1/log/list')]

def token(name):
    p = os.path.join(TOK, f'{name}.txt')
    return open(p, encoding='utf-8').read().strip() if os.path.exists(p) else ''

def call(method, path, tok):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0'}
    if tok:
        h['token'] = tok
    q = {'t': str(int(time.time() * 1000))}
    try:
        if method == 'GET':
            r = requests.get(BASE + path, headers=h, params=q, timeout=15, verify=False)
        else:
            r = requests.post(BASE + path, headers=dict(h, **{'Content-Type': 'application/json'}), params=q, json={}, timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:120]}
        return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg') or j.get('resMessage'), 'body': json.dumps(j, ensure_ascii=False)[:200]}
    except Exception as e:
        return {'http': None, 'error': str(e)[:150]}

def main():
    a = token('admin')
    found = []
    for (method, path) in CANDIDATES:
        r = call(method, path, a)
        if str(r.get('code')) == '0':
            ua = call(method, path, token('user_a'))
            an = call(method, path, '')
            found.append({'method': method, 'path': path, 'admin': r, 'user_a': ua, 'anonymous': an, 'leak': str(ua.get('code')) == '0' or str(an.get('code')) == '0'})
            print(f"FOUND {method} {path} admin={r.get('code')} user_a={ua.get('code')} anon={an.get('code')} leak={found[-1]['leak']}")
    out = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'found': found}
    p = os.path.join(ROOT, 'reports', 'p0', 'backend_probe.json')
    json.dump(out, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('found:', len(found), 'written:', p)
if __name__ == '__main__':
    main()
