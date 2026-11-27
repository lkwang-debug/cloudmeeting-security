"""按 scan.local.yaml 刷新 IDOR A/B 与 sysmanager 后台 token。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
import subprocess
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
try:
    from runner import env_config
    CFG = env_config.load()
    env_config.export_env(CFG)
except Exception:
    CFG = {}
LOGIN = os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py')
TOKENS = os.path.join(ROOT, 'evidence', 'tokens')

def main():
    accounts = CFG.get('accounts') or {} if CFG else {}
    a = accounts.get('idor_a') or {}
    b = accounts.get('idor_b') or {}
    admin = accounts.get('admin') or {}
    users = []
    if a.get('username'):
        users.append((a['username'], 'idor_' + a['username'], 'SEC_IDOR_A_PASS'))
    if b.get('username'):
        users.append((b['username'], 'idor_' + b['username'], 'SEC_IDOR_B_PASS'))
    if admin.get('username'):
        users.append((admin['username'], 'sysmanager', 'SEC_BACKEND_PASS'))
    if not users:
        users = [('test_user_a', 'idor_hzk05', 'SEC_IDOR_PASS'), ('test05', 'idor_test05', 'SEC_IDOR_PASS'), ('sysmanager', 'sysmanager', 'SEC_BACKEND_PASS')]
    os.makedirs(TOKENS, exist_ok=True)
    for (user, out, pass_env) in users:
        cmd = [sys.executable, LOGIN, '--target', _pub.target(), '--username', user, '--password-env', pass_env, '--attempts', '2', '--out', os.path.join(TOKENS, out + '.txt'), '--evidence-dir', os.path.join(ROOT, 'evidence', 'raw', 'login_' + user)]
        print('refresh', user)
        p = subprocess.run(cmd, cwd=ROOT, env=dict(os.environ), capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            print('WARN refresh failed', user, p.returncode)
if __name__ == '__main__':
    main()
