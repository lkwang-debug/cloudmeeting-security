"""P2 竞态测试：并发创建同名测试用户（open API），验证是否可能重复创建。
仅创建 secauto_race_* 用户，结束清理。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import concurrent.futures
import hashlib
import json
import os
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
OUT = os.path.join(ROOT, 'reports', 'p2', 'race_result.json')
TS = time.strftime('%m%d%H%M%S')
NAME = f'secauto_race_{TS}'
CTRL = f'secauto_race_ctrl_{TS}'
PWD = 'Secauto#2026'
DEPART = 355

def auth():
    key = os.environ.get('SEC_OPEN_KEY', '')
    sec = os.environ.get('SEC_OPEN_SECRET', '')
    ts = str(round(time.time() * 1000))
    h = base64.b64encode(b'{"alg": "SHA256"}').decode()
    p = base64.b64encode(json.dumps({'key': key, 'timestamp': int(ts)}).encode()).decode()
    return f'{h}.{p}.{hashlib.sha256((h + p + sec).encode()).hexdigest()}'

def post(path, body):
    h = {'Authorization': auth(), 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        j = r.json()
    except Exception:
        j = {'raw': r.text[:150]}
    return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg'), 'userId': (j.get('data') or {}).get('userId') if isinstance(j.get('data'), dict) else None}

def body(name):
    return {'userName': name, 'password': PWD, 'passwordType': 1, 'email': 'secauto@example.com', 'mobile': '13800000000', 'nickName': name, 'sex': 0, 'telePhone': '0000000', 'departId': DEPART, 'adminRole': 2}

def main():
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'name': NAME, 'control': [], 'race': []}
    res['control'].append({'step': 'first', **post('/api/v1/user/add', body(CTRL))})
    res['control'].append({'step': 'second', **post('/api/v1/user/add', body(CTRL))})
    print('control:', res['control'])

    def call(_):
        return post('/api/v1/user/add', body(NAME))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        res['race'] = list(ex.map(call, range(8)))
    ok = [r for r in res['race'] if str(r.get('code')) == '0']
    print('race success count:', len(ok), 'responses:', [r.get('code') for r in res['race']])
    res['race_success_count'] = len(ok)
    res['race_duplicate_possible'] = len(ok) > 1
    cleanup = []
    for name in (NAME, CTRL):
        cleanup.append({'name': name, **post('/api/v1/user/del', {'userName': name})})
    res['cleanup'] = cleanup
    print('cleanup:', cleanup)
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', OUT)
if __name__ == '__main__':
    main()
