"""P0 身份池：在测试环境创建 2 个部门 + 3 个普通用户（前缀 secauto_）。
认证：开放 API 自定义 SHA256 三段签名（key/secret 来自环境变量，不落盘）。
用法：
  set SEC_OPEN_KEY=... & set SEC_OPEN_SECRET=...
  python adapters/api/identity_pool.py --dry-run
  python adapters/api/identity_pool.py --create
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
from runner import public_config as _pub
import argparse
import base64
import hashlib
import json
import os
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = os.environ.get('SEC_TARGET', _pub.target())
OUT = os.path.join(ROOT, 'fixtures', 'identities.json')
TS = time.strftime('%m%d%H%M%S')
PREFIX = 'secauto'
DEPT_A = f'{PREFIX}_A_{TS}'
DEPT_B = f'{PREFIX}_B_{TS}'
PASSWORD = os.environ.get('SEC_IDENTITY_PASS', 'Secauto#2026')
USERS = [{'userName': f'{PREFIX}_a1', 'nickName': f'{PREFIX}_a1', 'departKey': 'A'}, {'userName': f'{PREFIX}_a2', 'nickName': f'{PREFIX}_a2', 'departKey': 'A'}, {'userName': f'{PREFIX}_c', 'nickName': f'{PREFIX}_c', 'departKey': 'B'}]

def make_auth():
    key = os.environ.get('SEC_OPEN_KEY', '')
    secret = os.environ.get('SEC_OPEN_SECRET', '')
    if not (key and secret):
        raise SystemExit('缺少 SEC_OPEN_KEY / SEC_OPEN_SECRET')
    ts = str(round(time.time() * 1000))
    h = base64.b64encode(b'{"alg": "SHA256"}').decode()
    p = base64.b64encode(json.dumps({'key': key, 'timestamp': int(ts)}).encode()).decode()
    sig = hashlib.sha256((h + p + secret).encode()).hexdigest()
    return f'{h}.{p}.{sig}'

def headers():
    return {'Authorization': make_auth(), 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'zh-CN,zh;q=0.9', 'Content-Language': 'zh-CN', 'Content-Type': 'application/json'}

def post(path, body):
    r = requests.post(BASE + path, json=body, headers=headers(), timeout=30, verify=False)
    try:
        j = r.json()
    except Exception:
        j = {'raw': r.text[:300]}
    return (r.status_code, j)

def list_departments():
    return post('/api/v1/department/list', {'parentDepartId': 0})

def list_users():
    return post('/api/v1/user/list', {'currentPage': 1, 'pageSize': 1000})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--create', action='store_true')
    args = ap.parse_args()
    if not (args.dry_run or args.create):
        args.dry_run = True
    (st, j) = list_departments()
    print('department/list:', st, 'code=', j.get('code'), 'total=', (j.get('data') or {}).get('total') if isinstance(j.get('data'), dict) else 'n/a')
    (st_u, ju) = list_users()
    total_u = (ju.get('data') or {}).get('total') if isinstance(ju.get('data'), dict) else 'n/a'
    print('user/list:', st_u, 'code=', ju.get('code'), 'total=', total_u)
    if not args.create:
        print('dry-run：未创建任何数据')
        return
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'password_env': 'SEC_IDENTITY_PASS', 'departments': {}, 'users': []}

    def find_dept(name):
        (st2, j2) = list_departments()
        for d in (j2.get('data') or {}).get('records', []) if isinstance(j2.get('data'), dict) else []:
            if d.get('departName') == name:
                return d.get('departId')
        return None
    for (key, name) in (('A', DEPT_A), ('B', DEPT_B)):
        (st, j) = post('/api/v1/department/add', {'parentDepartId': 1, 'departName': name})
        did = (j.get('data') or {}).get('departId') if isinstance(j.get('data'), dict) else None
        if not did:
            did = find_dept(name)
        print('department/add', name, '->', st, 'code=', j.get('code'), 'departId=', did)
        result['departments'][key] = {'name': name, 'departId': did, 'http': st, 'code': j.get('code')}
    dept_ids = {k: v.get('departId') for (k, v) in result['departments'].items()}
    for u in USERS:
        body = {'userName': u['userName'], 'password': PASSWORD, 'passwordType': 1, 'email': 'secauto@example.com', 'mobile': '13800000000', 'nickName': u['nickName'], 'sex': 0, 'telePhone': '0000000', 'departId': dept_ids[u['departKey']], 'adminRole': 2}
        (st, j) = post('/api/v1/user/add', body)
        uid = (j.get('data') or {}).get('userId') if isinstance(j.get('data'), dict) else None
        print('user/add', u['userName'], '->', st, 'code=', j.get('code'), 'userId=', uid)
        result['users'].append({'userName': u['userName'], 'departKey': u['departKey'], 'departId': dept_ids[u['departKey']], 'userId': uid, 'http': st, 'code': j.get('code')})
    (st2, j2) = list_users()
    names = {r.get('userName') for r in (j2.get('data') or {}).get('records', [])} if isinstance(j2.get('data'), dict) else set()
    for u in result['users']:
        u['verified_in_list'] = u['userName'] in names
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', OUT)
    print(json.dumps(result, ensure_ascii=False, indent=1)[:1500])
if __name__ == '__main__':
    main()
