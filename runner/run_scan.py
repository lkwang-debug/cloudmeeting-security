"""一键扫描入口：读取 scan.local.yaml，预检，执行 preflight + release gate。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import argparse
import os
import subprocess
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from runner import env_config

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', default='release', choices=['quick', 'release'])
    ap.add_argument('--check-only', action='store_true')
    ap.add_argument('--skip-check', action='store_true')
    args = ap.parse_args()
    cfg = env_config.load()
    env_config.export_env(cfg)
    print('config:', env_config.config_path())
    py = sys.executable
    if not args.skip_check:
        rc = subprocess.run([py, os.path.join(ROOT, 'runner', 'env_check.py')], cwd=ROOT).returncode
        if rc != 0:
            print('环境预检未通过，已停止扫描')
            return rc
    if args.check_only:
        return 0
    refresh_rc = subprocess.run([py, os.path.join(ROOT, 'runner', 'refresh_web_tokens.py')], cwd=ROOT).returncode
    if refresh_rc != 0:
        return refresh_rc
    rc = subprocess.run([py, os.path.join(ROOT, 'runner', 'preflight.py')], cwd=ROOT).returncode
    if rc != 0:
        print('preflight 失败，已停止扫描')
        return rc
    rc = subprocess.run([py, os.path.join(ROOT, 'runner', 'release_gate.py'), '--profile', args.profile], cwd=ROOT).returncode
    return rc
if __name__ == '__main__':
    sys.exit(main())
