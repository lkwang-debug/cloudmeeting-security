"""记录 Trivy/Grype 漏洞库版本与新鲜度（报告附录）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import subprocess
import time
import paramiko
ROOT = 'configured-path'
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'vuln_db_status.json')
LOCAL_TRIVY = 'configured-path'
HOST = _pub.env('SEC_SSH_HOST', '')

def main():
    status = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'trivy': {}, 'grype': {}}
    p = os.environ.get('TRIVY_DB_METADATA', LOCAL_TRIVY)
    if os.path.exists(p):
        status['trivy'] = json.load(open(p, encoding='utf-8'))
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(HOST, 22, 'root', os.environ.get('GATE_SSH_PASS', 'FsMeeting.com'), timeout=10)
        (i, o, e) = c.exec_command('grype db status 2>&1 | head -20', timeout=30)
        status['grype']['status_text'] = o.read().decode('utf-8', 'replace').strip()
        (i, o, e) = c.exec_command('cat /root/.cache/trivy/db/metadata.json 2>/dev/null', timeout=20)
        t = o.read().decode('utf-8', 'replace').strip()
        if t:
            status['trivy_worker'] = json.loads(t)
        c.close()
    except Exception as e:
        status['error'] = str(e)[:200]
    json.dump(status, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', OUT)
    print(status.get('trivy', {}).get('UpdatedAt'), '|', status.get('trivy', {}).get('NextUpdate'))
if __name__ == '__main__':
    main()
