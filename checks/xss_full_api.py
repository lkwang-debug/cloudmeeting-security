"""应用安全：全量只读接口反射 XSS 扫描（基于 API 清单）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
try:
    from checks import inventory_common as inv
except ImportError:
    import inventory_common as inv
PAYLOADS = ['<script>alert(1)</script>', '"><svg/onload=alert(1)>', 'xsssecauto123']

def main():
    eps = inv.read_endpoints()
    (findings, probes) = ([], [])
    for ep in eps:
        keys = (ep.get('body_keys') or []) + (ep.get('query_keys') or [])
        keys = [k for k in dict.fromkeys(keys) if k not in ('t', 'timestamp')][:4]
        if not keys:
            continue
        for key in keys:
            for pl in PAYLOADS:
                vals = {k: '' for k in keys}
                vals[key] = pl
                r = inv.request(ep, vals)
                body = str(r.get('body', ''))
                probes.append({'path': ep['path'], 'param': key, 'http': r.get('http'), 'reflected': pl in body})
                if pl in body:
                    findings.append(gc.finding('XSS-API-REFLECT', 'high', f"反射 XSS：{ep['path']} 参数 {key}", evidence=body[:300], remediation='输出编码/CSP'))
                    break
    gc.emit('xss_full_api', 'application', 'PASS', findings, summary=json.dumps({'endpoints': len(eps), 'probes': len(probes)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
