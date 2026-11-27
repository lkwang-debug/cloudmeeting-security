"""加密安全：TLS/SSL 深度（协议版本、3DES、RSA 密钥交换、证书有效期/主机名）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
BASE = gc.base_url()
U = urlparse(BASE)
HOST = U.hostname or ''
PORT = U.port or (443 if U.scheme == 'https' else 80)

def handshake(version=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version:
        ctx.minimum_version = version
        ctx.maximum_version = version
    elif ciphers:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except Exception:
            return {'ok': False}
    try:
        with socket.create_connection((HOST, PORT), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
                return {'ok': True, 'cipher': ss.cipher(), 'version': ss.version()}
    except Exception:
        return {'ok': False}

def main():
    if not HOST:
        gc.emit('tls_ssl_deep', 'crypto', 'BLOCKED', [], blocked_reason='无法解析目标主机')
        return
    findings = []
    out = {'host': HOST, 'port': PORT, 'versions': {}, 'ciphers': {}, 'cert': {}}
    probes = {'tls1.0': getattr(ssl.TLSVersion, 'TLSv1', None), 'tls1.1': getattr(ssl.TLSVersion, 'TLSv1_1', None), 'tls1.2': ssl.TLSVersion.TLSv1_2, 'tls1.3': ssl.TLSVersion.TLSv1_3}
    for (name, v) in probes.items():
        if v is None:
            continue
        r = handshake(version=v)
        out['versions'][name] = r
        if r.get('ok') and name in ('tls1.0', 'tls1.1'):
            findings.append(gc.finding('TLS-' + name.upper(), 'low', f'启用不安全的 {name}', evidence=json.dumps(r, ensure_ascii=False), remediation='禁用 TLS1.0/1.1，仅保留 TLS1.2/1.3'))
    for (label, ciphers, sev, note) in (('3des', '3DES:@SECLEVEL=0', 'medium', '支持 3DES（SWEET32）'), ('rsa-kex', 'kRSA:@SECLEVEL=0', 'low', '支持 RSA 密钥交换（无前向保密）')):
        r = handshake(ciphers=ciphers)
        out['ciphers'][label] = r
        if r.get('ok'):
            findings.append(gc.finding('TLS-' + label.upper(), sev, note, evidence=json.dumps(r, ensure_ascii=False), remediation='禁用 3DES/RSA 密钥交换，优先 ECDHE + AEAD'))
    try:
        pem = ssl.get_server_certificate((HOST, PORT), timeout=8)
        tmp = os.path.join(os.environ.get('TEMP', '/tmp'), 'gate_cert_%s.pem' % PORT)
        open(tmp, 'w', encoding='ascii').write(pem)
        cert = ssl._ssl._test_decode_cert(tmp)
        out['cert'] = {'subject': cert.get('subject'), 'issuer': cert.get('issuer'), 'notAfter': cert.get('notAfter')}
        exp = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        out['cert']['days_left'] = days
        if days < 0:
            findings.append(gc.finding('TLS-CERT-EXPIRED', 'medium', 'SSL 证书已过期', evidence=cert.get('notAfter', ''), remediation='更换证书'))
        elif days <= 30:
            findings.append(gc.finding('TLS-CERT-SOON', 'low', f'SSL 证书 {days} 天内过期', evidence=cert.get('notAfter', ''), remediation='尽快续期'))
        try:
            ssl.match_hostname(cert, HOST)
        except Exception:
            findings.append(gc.finding('TLS-CERT-HOST', 'low', 'SSL 证书主机名不匹配', evidence=json.dumps(cert.get('subject'), ensure_ascii=False), remediation='使用匹配目标域名的证书'))
    except Exception:
        pass
    gc.emit('tls_ssl_deep', 'crypto', 'PASS', findings, summary=json.dumps(out, ensure_ascii=False)[:1000])
if __name__ == '__main__':
    main()
