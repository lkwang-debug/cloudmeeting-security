"""内部暴露面（可选/授权）：服务器之间内通端口的只读探测。

默认关闭。开启后从当前扫描机/受控主机对配置的已知服务端口做 TCP 连通性检查，
不做全端口扫描，不爆破账号，不执行破坏性命令。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT

def load_cfg():
    try:
        from runner import env_config
        return env_config.load()
    except Exception:
        return {}

def probe(host, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return {'host': host, 'port': port, 'open': True}
    except Exception as e:
        return {'host': host, 'port': port, 'open': False, 'error': str(e)[:80]}
    finally:
        try:
            s.close()
        except Exception:
            pass

def main():
    cfg = load_cfg()
    c = cfg.get('internal_exposure') or {}
    if not c.get('enabled'):
        gc.emit('internal_exposure', 'application', 'PASS', [gc.finding('INTERNAL-EXPOSURE-DISABLED', 'info', '内部暴露面扫描默认关闭（需授权后启用）')], summary='disabled')
        return
    hosts = c.get('hosts') or []
    ports = [int(x) for x in c.get('ports') or []]
    results = []
    with ThreadPoolExecutor(max_workers=int(c.get('max_workers', 10))) as ex:
        futs = [ex.submit(probe, h, p, float(c.get('timeout', 1.5))) for h in hosts for p in ports]
        for f in futs:
            results.append(f.result())
    data = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'enabled': True, 'hosts': hosts, 'ports': ports, 'results': results}
    json.dump(data, open(os.path.join(ROOT, 'reports', 'final', 'INTERNAL_EXPOSURE.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    gc.emit('internal_exposure', 'application', 'PASS', [], summary=json.dumps({'hosts': hosts, 'ports': ports, 'open': [r for r in results if r.get('open')]}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
