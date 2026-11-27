"""应用安全：上传内容深度（EICAR/webshell 标记/内容类型混淆/图片 polyglot）。"""
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
ENDPOINTS = ['/basis/v1/userInfo/importUser', '/serv/v1/recording/img/upload', '/serv/v1/terminal/import', '/serv/v1/terminal/log/upload']
EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
PNG = bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000154a24f5f0000000049454e44ae426082')
VARIANTS = [('eicar.com', EICAR.encode(), 'application/octet-stream'), ('webshell.php', b"<?php system($_GET['c']); ?>", 'image/png'), ('polyglot.png', PNG + b"<?php echo 'secauto'; ?>", 'image/png'), ('archive.zip', b'PK\x03\x04secauto', 'application/zip')]

def main():
    tok = gc.token('admin02')
    if not tok:
        gc.emit('upload_content', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    findings = []
    tested = []
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok}
    for path in ENDPOINTS:
        for (fn, content, ctype) in VARIANTS:
            try:
                r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, files={'file': (fn, content, ctype)}, timeout=20, verify=False)
            except Exception:
                continue
            try:
                j = r.json()
            except Exception:
                j = {}
            code = j.get('code')
            tested.append({'path': path, 'file': fn, 'http': r.status_code, 'code': code, 'msg': j.get('msg')})
            if str(code) == '0':
                findings.append(gc.finding('UPLOAD-CONTENT-ACCEPTED', 'high', f'危险内容被上传接受：{path} {fn}', evidence=json.dumps(j, ensure_ascii=False)[:250], remediation='AV/YARA 内容检测；图片重编码；上传目录不可执行'))
                break
    gc.emit('upload_content', 'application', 'PASS', findings, summary=json.dumps({'tested': tested}, ensure_ascii=False)[:700])
if __name__ == '__main__':
    main()
