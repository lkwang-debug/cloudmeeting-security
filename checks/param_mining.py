"""C 阶段（最小实现）：参数挖掘（只读）。
输入：knowledge/backend_endpoints.json 中各接口已采集的 query/body 字段；
方法：向接口追加候选参数（常见隐藏参数/越权参数），比较响应（code/长度/新字段）差异。
输出：reports/final/c_param_mining.json
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
BASE = _pub.target()
TOK = os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt')
OUT = os.path.join(ROOT, 'reports', 'final', 'c_param_mining.json')
CANDIDATES = [('debug', '1'), ('isAdmin', 'true'), ('is_admin', '1'), ('admin', '1'), ('roleId', '3'), ('role', '3'), ('adminRole', '3'), ('userLevel', '9'), ('departId', '0'), ('departID', '0'), ('deptId', '0'), ('userId', '1000000001'), ('userid', '1000000001'), ('pageSize', '1000'), ('pageNumber', '1'), ('sort', '1'), ('order', 'desc'), ('showAll', '1'), ('all', '1'), ('internal', '1')]
TARGETS = [('/basis/v1/userInfo/queryUserPage', {'departId': 1, 'userName': '', 'displayName': '', 'pageNumber': 1, 'pageSize': 10}), ('/basis/v1/departInfo/queryDepartPage', {'pageNumber': 1, 'pageSize': 10, 'parentDepartId': 0, 'departName': ''}), ('/serv/v1/terminal/page', {'pageNumber': 1, 'pageSize': 10, 'departId': 0, 'terminalName': '', 'terminalNum': ''}), ('/basis/v1/role/list', {'pageSize': 10, 'pageNumber': 1})]
_SESSION = None

def call(path, body):
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
    tok = open(TOK, encoding='utf-8').read().strip()
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    try:
        r = _SESSION.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:200]}
        return {'http': r.status_code, 'code': j.get('code'), 'len': len(json.dumps(j, ensure_ascii=False)), 'keys': sorted(j.keys()), 'data_len': len(str(j.get('data') or ''))}
    except Exception as e:
        return {'error': str(e)[:120]}

def main():
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'endpoints': []}
    for (path, base_body) in TARGETS:
        ep = {'path': path, 'baseline': call(path, base_body), 'probes': []}
        for (name, val) in CANDIDATES:
            body = dict(base_body)
            body[name] = val
            r = call(path, body)
            diff = r['code'] != ep['baseline']['code'] or abs(r['len'] - ep['baseline']['len']) > 50 or r['data_len'] != ep['baseline']['data_len']
            if diff:
                ep['probes'].append({'param': name, 'value': val, **r})
        result['endpoints'].append(ep)
        print(path, 'baseline:', ep['baseline']['code'], 'diff probes:', len(ep['probes']))
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', OUT)
if __name__ == '__main__':
    main()
