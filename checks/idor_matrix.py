"""应用安全：对象级越权（水平/垂直）矩阵（复用真实 token）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()

def call(method, path, tok, body=None):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    if tok:
        h['token'] = tok
    r = requests.request(method, BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=15, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {})

def main():
    admin = gc.token('admin02')
    user = gc.token('user_a')
    if not admin:
        gc.emit('idor_matrix', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    if not user:
        gc.emit('idor_matrix', 'application', 'BLOCKED', [], blocked_reason='缺少 user_a token（水平越权需要普通用户）')
        return
    findings = []
    checks = []
    probes = [('POST', '/basis/v1/userInfo/queryUserPage', {'departId': 1, 'pageNumber': 1, 'pageSize': 10}, 'list'), ('POST', '/serv/v1/role/list', {'pageNumber': 1, 'pageSize': 10}, 'list'), ('GET', '/basis/v1/departInfo/queryDepartTree', None, 'tree'), ('POST', '/serv/v1/terminal/page', {'pageNumber': 1, 'pageSize': 10, 'departId': 0}, 'list'), ('POST', '/serv/v1/user/list', {'pageNumber': 1, 'pageSize': 10}, 'list'), ('POST', '/serv/v1/recording/paastask', {'curPage': 1, 'pageSize': 10}, 'list'), ('GET', '/serv/v1/conf/list', {'type': '1'}, 'list'), ('GET', '/meeting/v1/roominfo/get/10000', None, 'object'), ('POST', '/meeting/v1/roominfo/online-user', {'roomID': 10000}, 'object'), ('GET', '/serv/v1/recording/getServerMemory/1', None, 'object'), ('GET', '/basis/v1/nodeAuth/queryNodeAuthInfo', None, 'object'), ('GET', '/basis/v1/groups', None, 'object')]
    for (method, path, body, ptype) in probes:
        (a_http, a) = call(method, path, admin, body)
        (u_http, u) = call(method, path, user, body)
        a_ok = str(a.get('code')) == '0'
        u_ok = str(u.get('code')) == '0'
        checks.append({'path': path, 'type': ptype, 'admin': a.get('code'), 'user': u.get('code'), 'admin_ok': a_ok, 'user_ok': u_ok})
        if u_ok and (not a_ok):
            findings.append(gc.finding('IDOR-VERTICAL', 'high', f'普通用户可访问管理员接口：{path}', evidence=json.dumps(checks[-1], ensure_ascii=False), remediation='服务端鉴权；RBAC 清理'))
        if u_ok and ptype in ('list', 'object'):
            data = u.get('data') or {}
            records = data.get('records') if isinstance(data, dict) else None
            if records and len(records) > 0:
                findings.append(gc.finding('IDOR-HORIZONTAL', 'high', f'普通/受限用户可拉取越权数据：{path} 返回 {len(records)} 条', evidence=json.dumps(records[:1], ensure_ascii=False)[:300], remediation='按身份/部门过滤数据'))
            elif ptype == 'object':
                findings.append(gc.finding('IDOR-OBJECT', 'medium', f'受限用户可访问敏感对象接口（候选）：{path}', evidence=json.dumps(checks[-1], ensure_ascii=False)[:250], remediation='对象级鉴权；按用户归属校验'))
    gc.emit('idor_matrix', 'application', 'PASS', findings, summary=json.dumps({'checks': checks, 'probes': len(probes)}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
