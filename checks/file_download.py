"""应用安全：任意文件下载/路径穿越检查。"""
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
MARKERS = ['root:x:0:0', '[extensions]', '[fonts]', 'boot loader']
PAYLOADS = ['../../../../etc/passwd', '..%2f..%2f..%2fetc%2fpasswd', '/etc/passwd', '../../../../windows/win.ini']

def main():
    tok = gc.token('admin02')
    if not tok:
        gc.emit('file_download', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    paths = [p for p in gc.all_endpoints() if any((k in p.lower() for k in ('download', 'export', 'attachment', 'file')))]
    paths = ['/register/toDownload.do'] + paths
    paths = paths[:13]
    if not paths:
        gc.emit('file_download', 'application', 'BLOCKED', [], blocked_reason='知识库中没有下载/导出类接口')
        return
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok}
    findings = []
    tested = []
    for path in paths:
        for field in ('fileName', 'filePath', 'path', 'file', 'name', 'url'):
            for pl in PAYLOADS[:2]:
                try:
                    r = requests.get(BASE + path, headers=h, params={'t': str(int(time.time() * 1000)), field: pl}, timeout=12, verify=False)
                except Exception:
                    continue
                text = r.text or ''
                tested.append({'path': path, 'field': field, 'payload': pl, 'http': r.status_code, 'len': len(text)})
                if any((m in text for m in MARKERS)):
                    findings.append(gc.finding('DOWNLOAD-TRAVERSAL', 'high', f'路径穿越下载：{path} 参数 {field} 读取系统文件', evidence=text[:300], remediation='规范化路径并限制下载目录；白名单后缀'))
    gc.emit('file_download', 'application', 'PASS', findings, summary=json.dumps({'tested': len(tested), 'paths': len(paths)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
