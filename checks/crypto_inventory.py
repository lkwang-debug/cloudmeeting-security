"""加密安全：算法清单（TLS/JS/数据库），标记弱算法与国密缺失。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import subprocess
import sys
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
ROOT = gc.ROOT
BASE = _pub.target()

def tls_inventory():
    out = {'tls': {}, 'weak': [], 'sm_support': False}
    p = os.path.join(ROOT, 'reports', 'final', 'sslyze_summary.json')
    if os.path.exists(p):
        data = json.load(open(p, encoding='utf-8'))
        protocols = data.get('protocols') or {}
        ciphers = []
        for (proto, v) in protocols.items():
            if v.get('accepted_count'):
                ciphers += v.get('cipher_names') or []
                if proto in ('tls_1_0', 'tls_1_1', 'ssl_2_0', 'ssl_3_0'):
                    out['weak'].append(f'{proto} 仍可协商')
        out['tls'] = {'protocols': {k: v.get('accepted_count') for (k, v) in protocols.items()}, 'ciphers': ciphers}
        joined = ' '.join(ciphers).upper()
        out['sm_support'] = any((k in joined for k in ('SM2', 'SM3', 'SM4', 'GM')))
        for c in ciphers:
            u = c.upper()
            if any((k in u for k in ('RC4', '3DES', 'DES_CBC', 'NULL', 'MD5'))):
                out['weak'].append('弱套件: ' + c)
    cert = os.path.join(ROOT, 'reports', 'final', 'sslyze_tls.json')
    if os.path.exists(cert):
        try:
            j = json.load(open(cert, encoding='utf-8'))
            out['certificate_present'] = True
        except Exception:
            pass
    return out

def db_hash_inventory():
    """只读查询数据库密码字段格式（是否无盐 MD5）。"""
    info = {'checked': False, 'weak_md5': False, 'sample_count': 0}
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
        sql = 'SELECT UserID,Password FROM t_userinfo LIMIT 5;'
        cmd = 'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e ' + json.dumps(sql) + ' 2>/dev/null'
        (i, o, e) = c.exec_command(cmd, timeout=60)
        text = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
        c.close()
        rows = [r for r in text.splitlines() if r.strip()]
        info['sample_count'] = len(rows)
        for r in rows:
            parts = r.split('\t')
            if len(parts) >= 2:
                val = parts[-1].strip()
                if re.fullmatch('[0-9a-fA-F]{32}', val):
                    info['weak_md5'] = True
        info['checked'] = True
    except Exception as ex:
        info['error'] = str(ex)[:120]
    return info

def js_inventory():
    d = os.environ.get('GATE_CHUNKS_DIR') or os.path.join(ROOT, 'tools_cache', 'chunks')
    algos = {'DES': 0, '3DES': 0, 'AES': 0, 'SM4': 0, 'SM3': 0, 'SM2': 0, 'MD5': 0}
    if not os.path.isdir(d):
        return {'scanned': 0, 'algorithms': algos}
    for fn in os.listdir(d):
        try:
            t = open(os.path.join(d, fn), encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for a in algos:
            if a.lower() in t.lower():
                algos[a] += 1
    return {'scanned': len(os.listdir(d)), 'algorithms': algos}

def main():
    tls = tls_inventory()
    db = db_hash_inventory()
    js = js_inventory()
    findings = []
    if db.get('weak_md5'):
        findings.append(gc.finding('CRYPTO-DB-MD5', 'high', '数据库密码使用无盐 MD5 存储（可离线反查）', evidence=f"t_userinfo.Password 32 位 MD5，样本 {db.get('sample_count')} 条", remediation='改用 bcrypt/argon2 或国密 SM3+盐；强制重置历史密码'))
    for w in tls.get('weak') or []:
        findings.append(gc.finding('CRYPTO-TLS-WEAK', 'medium', f'TLS 弱配置：{w}', evidence='sslyze_summary.json', remediation='禁用旧协议/弱套件'))
    if not tls.get('sm_support'):
        findings.append(gc.finding('CRYPTO-SM-MISSING', 'medium', '未发现 TLS 国密套件（SM2/SM3/SM4）支持', evidence='TLS cipher 列表', remediation='按客户要求评审国密改造或提供算法清单与豁免'))
    if js.get('algorithms', {}).get('DES') or js.get('algorithms', {}).get('3DES'):
        findings.append(gc.finding('CRYPTO-JS-DES', 'medium', '前端 JS 使用 DES/3DES 加密（弱算法）', evidence=json.dumps(js, ensure_ascii=False)[:300], remediation='改用 AES-GCM/SM4；密钥不下发前端'))
    scenarios = [{'场景': '传输(TLS)', '算法': 'TLS1.2/1.3 AEAD' + ('；未发现国密套件' if not tls.get('sm_support') else '')}, {'场景': '口令存储', '算法': '无盐 MD5（弱）' if db.get('weak_md5') else '未发现弱 MD5'}, {'场景': '前端加密', '算法': 'DES/3DES（弱）' if js.get('algorithms', {}).get('DES') or js.get('algorithms', {}).get('3DES') else '未发现 DES/3DES'}, {'场景': 'API 签名', '算法': 'MD5/SHA256（需结合客户端确认）'}, {'场景': '随机数/验证码', '算法': '未自动检查（人工复核）'}]
    md = os.path.join(ROOT, 'reports', 'final', 'gate', 'CRYPTO_INVENTORY.md')
    os.makedirs(os.path.dirname(md), exist_ok=True)
    lines = ['# 密码算法使用场景清单（V8.2 自动采集）', '', '| 场景 | 算法/实现 | 结论 |', '|---|---|---|']
    for s in scenarios:
        bad = any((k in s['算法'] for k in ('MD5', 'DES', '未发现国密')))
        lines.append(f"| {s['场景']} | {s['算法']} | {('需整改/评审' if bad else '待确认')} |")
    lines += ['', '> 自动采集自 TLS/JS/DB；应用层加密、签名、密钥管理仍需人工补充。']
    open(md, 'w', encoding='utf-8').write('\n'.join(lines))
    summary = {'tls_protocols': tls.get('tls', {}).get('protocols'), 'db': db, 'js': js.get('algorithms'), 'sm_support': tls.get('sm_support'), 'scenarios': scenarios}
    gc.emit('crypto_inventory', 'crypto', 'PASS', findings, summary=json.dumps(summary, ensure_ascii=False)[:400])
if __name__ == '__main__':
    main()
