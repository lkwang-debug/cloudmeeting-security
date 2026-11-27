"""清理 P0 身份池（删除 fixtures/identities.json 中创建的用户与部门）。
认证：开放 API SHA256（SEC_OPEN_KEY / SEC_OPEN_SECRET）。
用法：python adapters/api/cleanup_identities.py --execute   # 默认 dry-run
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
IDS = os.path.join(ROOT, 'fixtures', 'identities.json')
LOG_DIR = os.path.join(ROOT, 'reports', 'p0')

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

def post(path, body):
    h = {'Authorization': make_auth(), 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    r = requests.post(BASE + path, json=body, headers=h, timeout=30, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:200]})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--execute', action='store_true')
    args = ap.parse_args()
    ids = json.load(open(IDS, encoding='utf-8'))
    users = ids.get('users', [])
    depts = ids.get('departments', {})
    print('待删除用户:', [(u.get('userName'), u.get('userId')) for u in users])
    print('待删除部门:', [(k, v.get('departId')) for (k, v) in depts.items()])
    if not args.execute:
        print('dry-run：未删除任何数据')
        return
    os.makedirs(LOG_DIR, exist_ok=True)
    log = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'users': [], 'departments': []}
    for u in users:
        if not u.get('userId'):
            log['users'].append({'userName': u.get('userName'), 'skipped': 'no userId'})
            continue
        (st, j) = post('/api/v1/user/del', {'userId': u['userId']})
        log['users'].append({'userName': u['userName'], 'userId': u['userId'], 'http': st, 'code': j.get('code'), 'msg': j.get('msg')})
        print('del user', u['userName'], st, j.get('code'), j.get('msg'))
    for (k, v) in depts.items():
        if not v.get('departId'):
            continue
        (st, j) = post('/api/v1/department/delete', {'departId': v['departId']})
        log['departments'].append({'name': v.get('name'), 'departId': v['departId'], 'http': st, 'code': j.get('code'), 'msg': j.get('msg')})
        print('del dept', v.get('name'), st, j.get('code'), j.get('msg'))
    out = os.path.join(LOG_DIR, 'cleanup_%s.json' % time.strftime('%Y%m%d-%H%M%S'))
    json.dump(log, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', out)
if __name__ == '__main__':
    main()
