"""应用安全：新增类写接口注入（隔离测试对象，创建后立即清理）。"""
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
ERR = ('sql', 'syntax', 'exception', 'odbc', 'mysql', 'jdbc', 'unclosed', 'ora-', 'pg_')
PAYLOADS = ["'", "' OR '1'='1", "x' AND '1'='2"]

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def main():
    root = load_cfg()
    if not (root.get('write_injection') or {}).get('enabled'):
        gc.emit('injection_write_isolated', 'application', 'PASS', [gc.finding('WRITE-INJ-DISABLED', 'info', '写接口注入未启用')], summary='disabled')
        return
    admin = web_auth.headers(root)
    ts = int(time.time())
    (findings, probes) = ([], [])

    def req(path, body):
        try:
            r = requests.post(BASE + path, headers={**admin, 'Content-Type': 'application/json'}, json=body, timeout=15, verify=False)
            try:
                return (r.status_code, r.text or '', r.json())
            except Exception:
                return (r.status_code, r.text or '', {})
        except Exception as e:
            return (0, str(e), {})
    for pl in PAYLOADS:
        name = 'secauto_wr_%d%s' % (ts, pl)
        (st, txt, j) = req('/api/v1/department/add', {'parentDepartId': 1, 'departName': name})
        dept_id = (j.get('data') or {}).get('departId') if isinstance(j.get('data'), dict) else None
        probes.append({'object': 'department', 'payload': pl, 'http': st, 'code': j.get('code'), 'id': dept_id, 'error': any((s in txt.lower() for s in ERR))})
        if any((s in txt.lower() for s in ERR)):
            findings.append(gc.finding('WRITE-SQLI-DEPT', 'high', '部门新增接口返回数据库异常特征', evidence=txt[:300], remediation='参数化/校验'))
        if dept_id:
            req('/api/v1/department/delete', {'departId': dept_id})
    for pl in PAYLOADS:
        name = 'secauto_wr_%d_%s' % (ts, abs(hash(pl)) % 1000)
        (st, txt, j) = req('/api/v1/user/add', {'userName': name, 'password': 'Test123456', 'departId': 1, 'adminRole': 2, 'displayName': pl})
        probes.append({'object': 'user', 'payload': pl, 'http': st, 'code': j.get('code'), 'error': any((s in txt.lower() for s in ERR))})
        if any((s in txt.lower() for s in ERR)):
            findings.append(gc.finding('WRITE-SQLI-USER', 'high', '用户新增接口返回数据库异常特征', evidence=txt[:300], remediation='参数化/校验'))
        req('/api/v1/user/del', {'userName': name})
    for pl in PAYLOADS:
        name = 'secauto_wr_%d_room%s' % (ts, pl)
        (st, txt, j) = req('/api/v1/room/addRoomInfo', {'enableInvite': True, 'autoRecord': 0, 'password': '123456', 'enableChairPwd': '1', 'verifyMode': '1', 'roomMode': 'standard', 'departId': 1, 'maxUserCount': 10, 'chairPassword': '123456', 'source': '', 'menteeAdvance': True, 'roomName': name})
        rid = (j.get('data') or {}).get('roomId') if isinstance(j.get('data'), dict) else None
        probes.append({'object': 'room', 'payload': pl, 'http': st, 'code': j.get('code'), 'id': rid, 'error': any((s in txt.lower() for s in ERR))})
        if any((s in txt.lower() for s in ERR)):
            findings.append(gc.finding('WRITE-SQLI-ROOM', 'high', '会议室新增接口返回数据库异常特征', evidence=txt[:300], remediation='参数化/校验'))
        if rid:
            req('/api/v1/room/delRoomInfo', {'roomId': rid})
    gc.emit('injection_write_isolated', 'application', 'PASS', findings, summary=json.dumps({'probes': probes}, ensure_ascii=False)[:900])
if __name__ == '__main__':
    main()
