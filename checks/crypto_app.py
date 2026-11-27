"""加密安全：应用层密码算法/密钥长度/密钥管理清单（前端 JS + TLS）。"""
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
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'CRYPTO_APP_INVENTORY.md')

def analyze(text):
    t = text or ''
    low = t.lower()
    out = {a: low.count(a.lower()) for a in ('sm2', 'sm3', 'sm4', 'aes', 'des', '3des', 'rsa', 'ecc', 'md5', 'sha1', 'sha256', 'hmac')}
    sizes = sorted({int(x) for x in re.findall('(?i)(?:rsa|modulus)[^\\d]{0,40}(1024|2048|3072|4096)', t)})
    out['rsa_sizes'] = sizes
    out['aes_ecb'] = len(re.findall('(?i)aes[^.;,]{0,40}ecb', t))
    return out

def main():
    files = []
    if os.path.isdir(CHUNKS):
        files = [os.path.join(CHUNKS, f) for f in os.listdir(CHUNKS) if f.endswith('.js')]
    agg = {k: 0 for k in ('sm2', 'sm3', 'sm4', 'aes', 'des', '3des', 'rsa', 'ecc', 'md5', 'sha1', 'sha256', 'hmac', 'aes_ecb')}
    sizes = set()
    for p in files:
        try:
            r = analyze(open(p, encoding='utf-8', errors='replace').read())
        except Exception:
            continue
        for k in agg:
            agg[k] += r.get(k, 0)
        sizes.update(r.get('rsa_sizes') or [])
    findings = []
    if agg.get('des') or agg.get('3des'):
        findings.append(gc.finding('CRYPTO-APP-DES', 'medium', '前端使用 DES/3DES（弱算法）', evidence=json.dumps(agg, ensure_ascii=False)[:300], remediation='AES-GCM/SM4；密钥不下发前端'))
    if agg.get('md5') or agg.get('sha1'):
        findings.append(gc.finding('CRYPTO-APP-HASH', 'medium', '前端使用 MD5/SHA1', evidence=json.dumps(agg, ensure_ascii=False)[:300], remediation='SHA256+ / SM3'))
    if sizes and min(sizes) < 2048:
        findings.append(gc.finding('CRYPTO-APP-RSA', 'high', '前端 RSA 密钥长度 <2048', evidence=str(sorted(sizes)), remediation='RSA≥2048/ECC≥256'))
    if not any((agg.get(k) for k in ('sm2', 'sm3', 'sm4'))):
        findings.append(gc.finding('CRYPTO-APP-SM-MISSING', 'medium', '前端未发现国密算法使用', evidence=json.dumps(agg, ensure_ascii=False)[:300], remediation='按客户要求评估国密改造'))
    scenarios = [{'场景': 'TLS 传输', '算法': 'TLS1.2/1.3 AEAD（见 TLS 清单）'}, {'场景': '前端加密', '算法': f"AES={agg['aes']}, DES={agg['des']}, 3DES={agg['3des']}, ECB={agg['aes_ecb']}"}, {'场景': '签名/摘要', '算法': f"MD5={agg['md5']}, SHA1={agg['sha1']}, SHA256={agg['sha256']}, HMAC={agg['hmac']}"}, {'场景': '非对称', '算法': f"RSA={agg['rsa']}, ECC={agg['ecc']}, RSA尺寸={sorted(sizes)}"}, {'场景': '国密', '算法': f"SM2={agg['sm2']}, SM3={agg['sm3']}, SM4={agg['sm4']}"}]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    lines = ['# 应用层密码算法/密钥管理清单', '', '| 场景 | 算法/使用情况 |', '|---|---|']
    lines += [f"| {s['场景']} | {s['算法']} |" for s in scenarios]
    lines += ['', '> 基于前端 JS 静态统计；密钥管理实现需人工确认。']
    open(OUT, 'w', encoding='utf-8').write('\n'.join(lines))
    gc.emit('crypto_app', 'crypto', 'PASS', findings, summary=json.dumps({'files': len(files), 'counts': agg, 'rsa_sizes': sorted(sizes)}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
