"""应用安全：全量只读 SQL/NoSQL/LDAP/HTML 注入扫描（基于 API 清单）。"""
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
PAYLOADS = [('sql', "'"), ('sql', "' OR '1'='1"), ('sql', "1' AND '1'='2"), ('nosql', '{"$ne": null}'), ('ldap', '*)(uid=*)'), ('html', '<h1>secauto</h1>')]
ERR = ('sql', 'syntax', 'exception', 'odbc', 'mysql', 'jdbc', 'unclosed', 'ldap', 'mongo')

def main():
    eps = inv.read_endpoints()
    (findings, probes) = ([], [])
    for ep in eps:
        keys = (ep.get('body_keys') or []) + (ep.get('query_keys') or [])
        keys = [k for k in dict.fromkeys(keys) if k not in ('t', 'timestamp')][:4]
        if not keys:
            continue
        base = inv.request(ep, {k: '' for k in keys})
        for key in keys:
            for (kind, pl) in PAYLOADS:
                vals = {k: '' for k in keys}
                vals[key] = pl
                r = inv.request(ep, vals)
                low = str(r.get('body', '')).lower()
                if r.get('error'):
                    continue
                probes.append({'path': ep['path'], 'param': key, 'kind': kind, 'http': r.get('http'), 'code': r.get('code'), 'len': r.get('len')})
                if any((s in low for s in ERR)) and str(r.get('code')) not in ('9003', '1002', '1003'):
                    findings.append(gc.finding('SQLI' if kind == 'sql' else kind.upper() + '-INJECTION', 'high', f"{kind} 注入特征：{ep['path']} 参数 {key}", evidence=str(r.get('body'))[:300], remediation='参数化/转义/白名单'))
                elif base.get('len') and r.get('len') and (abs(r['len'] - base['len']) > 120):
                    findings.append(gc.finding('INJECTION-DIFF', 'medium', f"参数注入响应差异：{ep['path']} {key} ({kind})", evidence=json.dumps(r, ensure_ascii=False)[:300], remediation='参数化/白名单'))
    gc.emit('injection_full', 'application', 'PASS', findings, summary=json.dumps({'endpoints': len(eps), 'probes': len(probes), 'findings': len(findings)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
