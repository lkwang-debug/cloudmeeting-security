"""应用安全：OAuth2/客户端凭据与默认账号泄露（仅前端 JS）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
CHUNKS = os.environ.get('GATE_CHUNKS_DIR') or os.path.join(gc.ROOT, 'tools_cache', 'chunks')
PATTERNS = [('client_secret', re.compile('client[_-]?secret\\s*[:=]\\s*[\\"\']([^\\"\']{6,})', re.I)), ('client_id', re.compile('client[_-]?id\\s*[:=]\\s*[\\"\']([^\\"\']{6,})', re.I)), ('appkey', re.compile('app[_-]?key\\s*[:=]\\s*[\\"\']([^\\"\']{6,})', re.I)), ('default_password', re.compile('default[_-]?password\\s*[:=]\\s*[\\"\']([^\\"\']{4,})', re.I))]

def main():
    (findings, hits) = ([], [])
    if os.path.isdir(CHUNKS):
        for fn in os.listdir(CHUNKS):
            if not fn.endswith('.js'):
                continue
            try:
                text = open(os.path.join(CHUNKS, fn), encoding='utf-8', errors='replace').read()
            except Exception:
                continue
            for (name, pat) in PATTERNS:
                for m in pat.finditer(text):
                    val = m.group(1)
                    hits.append({'file': fn, 'type': name, 'masked': val[:4] + '****' + val[-4:]})
                    break
    if hits:
        findings.append(gc.finding('OAUTH-CLIENT-SECRET', 'high', f'前端 JS 发现 OAuth/客户端凭据或默认口令 {len(hits)} 处', evidence=json.dumps(hits[:8], ensure_ascii=False)[:500], remediation='移出前端；轮换 client_secret；默认账号强制修改'))
    gc.emit('oauth_secret_check', 'application', 'PASS', findings, summary=json.dumps({'hits': len(hits), 'samples': hits[:10]}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
