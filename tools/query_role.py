import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)

def run(cmd, t=30):
    (i, o, e) = c.exec_command(cmd, timeout=t)
    return (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
MY = 'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e '
sql = 'SELECT Menu_ID,Menu_Name,Url FROM t_menu WHERE Menu_ID IN (14,48,49,50,51,52,53,96,108,153,150,149,93,94,131,3,5,99,104,147,9,33,34);'
print(run(MY + json.dumps(sql) + ' 2>/dev/null'))
