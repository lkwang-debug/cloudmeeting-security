"""编排层 preflight：按 scan.local.yaml 刷新后台 token。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
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

def main():
    user = os.environ.get('SEC_PREFLIGHT_USER') or 'admin02'
    pass_env = 'SEC_PREFLIGHT_PASS' if os.environ.get('SEC_PREFLIGHT_PASS') else 'SEC_BACKEND_PASS'
    out_token = os.path.join(ROOT, 'evidence', 'tokens', (user if user != 'admin02' else 'admin02') + '.txt')
    ev_dir = os.path.join(ROOT, 'evidence', 'raw', 'preflight_' + user)
    candidates = [os.environ.get('SCEN_LOGIN_PYTHON', ''), __import__('sys').executable, __import__('sys').executable]
    py = next((x for x in candidates if x and os.path.exists(x)), sys.executable)
    cmd = [py, os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py'), '--target', _pub.target(), '--username', user, '--password-env', pass_env, '--attempts', '2', '--out', out_token, '--evidence-dir', ev_dir]
    subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)
    resp = os.path.join(ev_dir, 'login_response.json')
    code = None
    if os.path.exists(resp):
        try:
            code = json.load(open(resp, encoding='utf-8-sig')).get('code')
        except Exception:
            pass
    tok = open(out_token, encoding='utf-8').read().strip() if os.path.exists(out_token) else ''
    ok = code == '0' and len(tok) > 20
    print(json.dumps({'login_code': code, 'token_len': len(tok), 'ok': ok, 'user': user}, ensure_ascii=False))
    return 0 if ok else 1
if __name__ == '__main__':
    sys.exit(main())
