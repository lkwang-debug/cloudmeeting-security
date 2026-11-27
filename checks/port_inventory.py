"""外部暴露端口扫描：只扫配置的放行/外部可达端口，不做全端口扫描。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
BASE = gc.base_url()
CFG = os.path.join(ROOT, 'configs', 'scan.local.yaml')

def load_cfg():
    try:
        from runner import env_config
        return env_config.load()
    except Exception:
        return {}

def load_scan_cfg(cfg):
    return cfg.get('port_scan') or {}

def http_probe(host, port, https, timeout):
    scheme = 'https' if https else 'http'
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        r = requests.get('%s://%s:%s/' % (scheme, host, port), timeout=timeout, verify=False, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=False)
        return {'http': r.status_code, 'server': r.headers.get('Server', ''), 'location': r.headers.get('Location', '')[:120], 'len': len(r.text or '')}
    except Exception as e:
        return {'error': str(e)[:120]}

def probe(host, port, timeout, https):
    out = {'host': host, 'port': port, 'open': False}
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        out['open'] = True
        out['service'] = 'tcp'
        if https:
            try:
                ctx = ssl._create_unverified_context()
                ss = ctx.wrap_socket(socket.socket(), server_hostname=host)
                ss.settimeout(timeout)
                ss.connect((host, port))
                out['tls'] = {'version': ss.version(), 'cipher': ss.cipher()[0] if ss.cipher() else ''}
                ss.close()
            except Exception as e:
                out['tls_error'] = str(e)[:100]
        else:
            try:
                s.sendall(b'HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n' % host.encode())
                data = s.recv(256)
                if data:
                    out['banner'] = data.decode('utf-8', 'replace').splitlines()[0][:160]
            except Exception:
                pass
        if port in (80, 443, 28080, 28443):
            out['http'] = http_probe(host, port, https, timeout)
    except Exception as e:
        out['error'] = str(e)[:100]
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out

def main():
    cfg = load_cfg()
    web = cfg.get('web') or {}
    base_url = web.get('base_url') or BASE
    u = urlparse(base_url)
    host = web.get('host') or u.hostname or ''
    scheme = web.get('scheme') or u.scheme or 'https'
    base_port = int(web.get('port') or u.port or (443 if scheme == 'https' else 80))
    scan_cfg = load_scan_cfg(cfg)
    if not scan_cfg.get('enabled', True):
        gc.emit('port_inventory', 'application', 'PASS', [gc.finding('PORT-SCAN-DISABLED', 'info', '外部端口扫描未启用')], summary='disabled')
        return
    extra = [int(x) for x in scan_cfg.get('extra_ports') or [1089, 28201]]
    ports = list(dict.fromkeys([base_port] + extra))
    timeout = float(scan_cfg.get('timeout', 1.5))
    results = []
    with ThreadPoolExecutor(max_workers=int(scan_cfg.get('max_workers', 10))) as ex:
        futs = {ex.submit(probe, host, p, timeout, scheme == 'https' and p == base_port): p for p in ports}
        for f in futs:
            results.append(f.result())
    open_ports = [r['port'] for r in results if r.get('open')]
    data = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'target': host, 'scheme': scheme, 'base_port': base_port, 'candidate_ports': ports, 'open_ports': open_ports, 'results': results}
    os.makedirs(os.path.join(ROOT, 'reports', 'final'), exist_ok=True)
    json.dump(data, open(os.path.join(ROOT, 'reports', 'final', 'PORT_INVENTORY.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# 外部端口暴露面扫描', '', '- 目标：`%s`' % host, '- 部署方式：%s，基准端口：%s' % (scheme, base_port), '- 候选端口：%s' % ', '.join((str(p) for p in ports)), '', '| 端口 | 状态 | 服务/证据 |', '|---|---|---|']
    for r in results:
        ev = r.get('banner') or (r.get('http') and 'HTTP %s %s' % (r['http'].get('http'), r['http'].get('server', ''))) or ''
        lines.append('| %s | %s | %s |' % (r['port'], 'OPEN' if r.get('open') else 'closed/filtered', str(ev)[:80]))
    open(os.path.join(ROOT, 'reports', 'final', 'PORT_SCAN_REPORT_20261126.md'), 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    findings = []
    for r in results:
        if r.get('open') and r['port'] != base_port:
            findings.append(gc.finding('PORT-EXPOSED', 'info', '外部可达端口：%s:%s' % (host, r['port']), evidence=json.dumps(r, ensure_ascii=False)[:300], remediation='确认是否为必需端口；非必需关闭/限制来源'))
    gc.emit('port_inventory', 'application', 'PASS', findings, summary=json.dumps({'target': host, 'scheme': scheme, 'candidates': ports, 'open': open_ports}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
