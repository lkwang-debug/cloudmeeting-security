"""客户端/前端加密：JS 中 DES/3DES/AES 密钥、IV、硬编码凭据检测。"""
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
ROOT = gc.ROOT
CHUNKS = os.environ.get('GATE_CHUNKS_DIR') or os.path.join(ROOT, 'tools_cache', 'chunks')
KEY_PATTERNS = [('3des_key', re.compile('8f071f3441a847e88f071f3441a847e8', re.I)), ('des_key', re.compile('(?i)(?:des|3des)[^;{}]{0,80}?[\'\\"]([0-9a-f]{16,24})[\'\\"]')), ('aes_key', re.compile('(?i)(?:aes|sm4)[^;{}]{0,80}?[\'\\"]([0-9a-f]{16,64})[\'\\"]')), ('iv', re.compile('(?i)\\biv\\b[^;{}]{0,40}?[\'\\"]([0-9a-f]{8,32})[\'\\"]')), ('appkey', re.compile('(?i)(?:appkey|keyen)\\s*[:=]\\s*[\'\\"]([0-9a-fA-F]{16,64})[\'\\"]'))]

def main():
    findings = []
    hits = []
    if not os.path.isdir(CHUNKS):
        gc.emit('client_crypto', 'crypto', 'BLOCKED', [], blocked_reason='tools_cache/chunks 不存在')
        return
    for fn in os.listdir(CHUNKS):
        p = os.path.join(CHUNKS, fn)
        if not os.path.isfile(p):
            continue
        try:
            t = open(p, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for (name, rx) in KEY_PATTERNS:
            for m in rx.finditer(t):
                val = m.group(1) if m.groups() else m.group(0)
                hits.append({'file': fn, 'type': name, 'value_masked': val[:4] + '****' + val[-2:] if len(val) > 8 else '****', 'context': t[max(0, m.start() - 40):m.start() + 60].replace('\n', ' ')[:120]})
    if hits:
        findings.append(gc.finding('CLIENT-HARDCODED-CRYPTO', 'high', f'前端 JS 发现 {len(hits)} 处硬编码密钥/IV（DES/3DES/AES/AppKey）', evidence=json.dumps(hits[:8], ensure_ascii=False)[:600], remediation='密钥移出前端；改用服务端下发临时密钥或国密/平台密钥管理'))
    gc.emit('client_crypto', 'crypto', 'PASS', findings, summary=json.dumps({'files': len(os.listdir(CHUNKS)), 'hits': len(hits)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
