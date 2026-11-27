"""F-01 修复验证：运行 role_permission_lifecycle 场景并输出 FIXED / NOT_FIXED。
用法：python runner/verify_f01_fix.py
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import subprocess
import sys
import time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCEN = os.path.join(ROOT, 'fixtures', 'scenarios', 'role_permission_lifecycle.yaml')
RES = os.path.join(ROOT, 'reports', 'final', 'scenarios', 'role_permission_lifecycle.json')
OUT = os.path.join(ROOT, 'reports', 'final', 'f01_fix_status.json')

def main():
    py = os.environ.get('SCEN_LOGIN_PYTHON') or __import__('sys').executable
    if not os.path.exists(py):
        py = sys.executable
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'runner', 'scenario_engine.py'), SCEN], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=600)
    data = {}
    if os.path.exists(RES):
        data = json.load(open(RES, encoding='utf-8'))
    phase2 = None
    for s in data.get('steps', []):
        if s.get('name') == 'user_after_downgrade_should_deny':
            phase2 = s.get('code')
    fixed = str(phase2) == '1003'
    out = {'checked_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'phase2_queryDepartTree_code': phase2, 'status': 'FIXED' if fixed else 'NOT_FIXED', 'scenario_verdict': data.get('verdict'), 'note': 'FIXED 表示降权后旧接口返回 1003（缓存已失效）；NOT_FIXED 表示仍返回 0（缺陷存在）'}
    json.dump(out, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if fixed else 1
if __name__ == '__main__':
    sys.exit(main())
