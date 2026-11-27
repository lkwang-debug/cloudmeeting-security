"""从产品 /hst/meeting/readme.txt 读取 ServerVersion，写入 reports/final/gate/server_version.txt。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
import re
import paramiko
ROOT = 'configured-path'
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'server_version.txt')
HOST = os.environ.get('GATE_SERVER_HOST', _pub.env('SEC_SSH_HOST', ''))
USER = os.environ.get('GATE_SERVER_USER', 'root')
PWD = os.environ.get('GATE_SERVER_PASS', _pub.env('SEC_SSH_PASSWORD', ''))

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, 22, USER, PWD, timeout=10)
    (i, o, e) = c.exec_command('cat /hst/meeting/readme.txt', timeout=20)
    text = o.read().decode('utf-8', 'replace')
    c.close()
    m = re.search('ServerVersion\\s*:\\s*([0-9A-Za-z._-]+)', text)
    if not m:
        raise SystemExit('未找到 ServerVersion')
    ver = m.group(1)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, 'w', encoding='utf-8').write(ver)
    print('ServerVersion:', ver)
if __name__ == '__main__':
    main()
