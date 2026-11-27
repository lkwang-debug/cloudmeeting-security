"""应用安全：文件上传（webshell/脚本内容）检测（仅测试环境，无害内容）。"""
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
CONTENTS = [('shell.php', "<?php echo 'secauto'; ?>", 'application/x-php'), ('shell.jsp', '<% out.print("secauto"); %>', 'application/x-jsp'), ('shell.png.php', "<?php echo 'secauto'; ?>", 'image/png'), ('shell.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'image/svg+xml'), ('shell.html', '<script>alert(1)</script>', 'text/html'), ('polyglot.png', "\x89PNG\r\n\x1a\n<?php echo 'secauto'; ?>", 'image/png'), ('archive.zip', 'PK\x03\x04secauto', 'application/zip')]

def main():
    tok = gc.token('admin02')
    if not tok:
        gc.emit('upload_webshell', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    findings = []
    tested = []
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok}
    for path in ENDPOINTS:
        for (fn, content, ctype) in CONTENTS:
            try:
                r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, files={'file': (fn, content if isinstance(content, bytes) else content.encode(), ctype)}, timeout=20, verify=False)
            except Exception:
                continue
            try:
                j = r.json()
            except Exception:
                j = {}
            code = j.get('code')
            text = json.dumps(j, ensure_ascii=False)
            tested.append({'path': path, 'filename': fn, 'http': r.status_code, 'code': code, 'msg': j.get('msg')})
            accepted = str(code) == '0' or (r.status_code == 200 and ('url' in text.lower() or 'path' in text.lower()))
            if accepted:
                findings.append(gc.finding('UPLOAD-WEBSHELL', 'high', f'上传脚本文件被接受：{path} {fn}', evidence=text[:300], remediation='后缀/内容双重校验；图片重编码；上传目录不可执行'))
                break
    gc.emit('upload_webshell', 'application', 'PASS', findings, summary=json.dumps({'tested': len(tested), 'details': tested}, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
