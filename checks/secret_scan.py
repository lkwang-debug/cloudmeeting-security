"""加密安全：代码/配置/JS 明文密码与密钥扫描（脱敏）。"""
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
SCAN_DIRS = (os.environ.get('GATE_SECRET_DIRS') or 'configs,tools_cache/chunks,fixtures/client_samples').split(',')
SKIP_EXT = {'.docx', '.pdf', '.zip', '.jsonl', '.pcap', '.png', '.jpg', '.jar', '.gz', '.bak'}
PATTERNS = [('password', re.compile('(?i)(password|passwd|pwd)\\s*[:=]\\s*[\'\\"]([^\'\\"]{4,64})[\'\\"]')), ('secret', re.compile('(?i)(secret|private[_-]?key|client_secret|appkey)\\s*[:=]\\s*[\'\\"]([^\'\\"]{6,64})[\'\\"]')), ('token', re.compile('(?i)(access[_-]?token|refresh[_-]?token)\\s*[:=]\\s*[\'\\"]([A-Za-z0-9._-]{8,80})[\'\\"]')), ('md5key', re.compile('(?i)[\'\\"][0-9a-f]{32}[\'\\"]'))]
PLACEHOLDERS = {'password', 'passwd', 'pwd', 'secret', 'changeme', 'xxx', 'test', _pub.env('SEC_TEST_PASSWORD', ''), '<password>'}

def mask(s):
    if len(s) <= 4:
        return '****'
    return s[:2] + '****' + s[-2:]

def main():
    findings = []
    scanned = 0
    hits = []
    for rel in SCAN_DIRS:
        base = os.path.join(ROOT, rel)
        if not os.path.isdir(base):
            continue
        for fn in os.listdir(base):
            p = os.path.join(base, fn)
            if not os.path.isfile(p) or os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            try:
                t = open(p, encoding='utf-8', errors='replace').read()
            except Exception:
                continue
            scanned += 1
            for (name, rx) in PATTERNS:
                for m in rx.finditer(t):
                    val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                    if name == 'md5key':
                        val = m.group(0).strip('\'"')
                    if val.lower() in PLACEHOLDERS:
                        continue
                    hits.append({'file': os.path.join(rel, fn), 'type': name, 'masked': mask(val), 'context': t[max(0, m.start() - 30):m.start() + 60].replace('\n', ' ')[:120]})
                    if len(hits) >= 30:
                        break
    if hits:
        findings.append(gc.finding('CRYPTO-PLAINTEXT-SECRET', 'high', f'发现 {len(hits)} 处疑似明文密码/密钥', evidence=json.dumps(hits[:8], ensure_ascii=False)[:600], remediation='移入密钥库/环境变量；轮换历史凭据；禁止前端下发 client_secret'))
    gc.emit('secret_scan', 'crypto', 'PASS', findings, summary=json.dumps({'files_scanned': scanned, 'hits': len(hits)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
