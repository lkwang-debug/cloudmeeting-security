"""中间件/主机：SSH 算法发现（弱 KEX/加密/MAC/主机密钥）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import paramiko
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
WEAK_KEX = ('diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1')
WEAK_CIPHERS = ('3des-cbc', 'arcfour', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc')
WEAK_MACS = ('hmac-md5', 'hmac-sha1-96')
WEAK_KEYS = ('ssh-dss',)

def main():
    targets = os.environ.get('GATE_SSH_TARGETS', '' + _pub.shell('SEC_DB_HOST') + ',' + _pub.shell('SEC_DB_HOST') + '').split(',')
    user = os.environ.get('GATE_SSH_USER', 'root')
    pwd = os.environ.get('GATE_SSH_PASS', '')
    (findings, out) = ([], [])
    for host in [h.strip() for h in targets if h.strip()]:
        try:
            t = paramiko.Transport((host, 22))
            t.start_client(timeout=8)
            opts = t.get_security_options()
            info = {'host': host, 'kex': list(opts.kex), 'ciphers': list(opts.ciphers), 'macs': list(getattr(opts, 'macs', getattr(opts, 'digests', []))), 'keys': list(opts.key_types)}
            out.append(info)
            weak = [x for x in info['kex'] if x in WEAK_KEX]
            if weak:
                findings.append(gc.finding('SSH-WEAK-KEX', 'medium', f"{host} 支持弱 KEX: {', '.join(weak)}", evidence=json.dumps(weak), remediation='升级 OpenSSH，禁用弱 KEX'))
            wc = [x for x in info['ciphers'] if x in WEAK_CIPHERS]
            if wc:
                findings.append(gc.finding('SSH-WEAK-CIPHER', 'medium', f"{host} 支持弱加密算法: {', '.join(wc)}", evidence=json.dumps(wc), remediation='禁用 CBC/3DES/RC4'))
            wm = [x for x in info['macs'] if x in WEAK_MACS]
            if wm:
                findings.append(gc.finding('SSH-WEAK-MAC', 'low', f"{host} 支持弱 MAC: {', '.join(wm)}", evidence=json.dumps(wm), remediation='禁用 MD5/SHA1-96'))
            wk = [x for x in info['keys'] if x in WEAK_KEYS]
            if wk:
                findings.append(gc.finding('SSH-WEAK-KEY', 'medium', f'{host} 支持 ssh-dss', evidence=json.dumps(wk)))
            t.close()
        except Exception as e:
            out.append({'host': host, 'error': str(e)[:120]})
    gc.emit('ssh_algorithms', 'middleware', 'PASS', findings, summary=json.dumps({'targets': out}, ensure_ascii=False)[:1000])
if __name__ == '__main__':
    main()
