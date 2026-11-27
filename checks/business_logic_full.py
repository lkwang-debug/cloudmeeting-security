"""应用安全：业务逻辑扩展（部门重复创建；仅创建/清理测试对象）。"""
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

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def main():
    root = load_cfg()
    if not (root.get('business_logic_full') or {}).get('enabled'):
        gc.emit('business_logic_full', 'application', 'PASS', [gc.finding('BUSINESS-LOGIC-DISABLED', 'info', '业务逻辑扩展未启用')], summary='disabled')
        return
    admin = web_auth.headers(root)

    def req(path, body):
        r = requests.post(BASE + path, headers={**admin, 'Content-Type': 'application/json'}, json=body, timeout=15, verify=False)
        try:
            return (r.status_code, r.json())
        except Exception:
            return (r.status_code, {})
    ts = int(time.time())
    name = 'secauto_logic_dept_%d' % ts
    (findings, evidence) = ([], {})
    (st, j) = req('/api/v1/department/add', {'parentDepartId': 1, 'departName': name})
    dept_id = (j.get('data') or {}).get('departId') if isinstance(j.get('data'), dict) else None
    evidence['baseline'] = {'http': st, 'code': j.get('code'), 'id': dept_id}
    (st2, j2) = req('/api/v1/department/add', {'parentDepartId': 1, 'departName': name})
    evidence['duplicate'] = {'http': st2, 'code': j2.get('code'), 'body': str(j2)[:300]}
    if st == 200 and st2 == 200 and (str(j.get('code')) == '0') and (str(j2.get('code')) == '0'):
        dup_id = (j2.get('data') or {}).get('departId') if isinstance(j2.get('data'), dict) else None
        findings.append(gc.finding('LOGIC-DEPT-DUP', 'medium', '同名部门重复创建成功（预期应拒绝）', evidence=json.dumps(evidence, ensure_ascii=False)[:400], remediation='唯一性校验'))
        if dup_id:
            req('/api/v1/department/delete', {'departId': dup_id})
    if dept_id:
        req('/api/v1/department/delete', {'departId': dept_id})
    gc.emit('business_logic_full', 'application', 'PASS', findings, summary=json.dumps(evidence, ensure_ascii=False)[:700])
if __name__ == '__main__':
    main()
