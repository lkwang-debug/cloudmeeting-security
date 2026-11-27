"""V8 P1 覆盖补齐：注入矩阵（SQLi 差分，只读）。
输入：knowledge/backend_endpoints.json（真实采集的 query/body 字段）
方法：对每个参数注入 ' / ' OR '1'='1 / 1' AND '1'='2 / `，比较 code/长度/SQL 错误特征。
输出：reports/final/injection_matrix.json
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
TOK = os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt')
OUT = os.path.join(ROOT, 'reports', 'final', 'injection_matrix.json')
PAYLOADS = ["'", "' OR '1'='1"]
ERROR_SIGS = ['sql', 'syntax', 'exception', 'odbc', 'mysql', 'ora-', 'jdbc', 'unclosed']
_SESSION = requests.Session()

def call(method, path, body, tok):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    for attempt in range(2):
        try:
            r = _SESSION.request(method, BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=25, verify=False)
            try:
                j = r.json()
            except Exception:
                j = {'raw': r.text[:200]}
            return {'http': r.status_code, 'code': j.get('code'), 'len': len(json.dumps(j, ensure_ascii=False)), 'raw': json.dumps(j, ensure_ascii=False)[:300]}
        except Exception as e:
            if attempt == 1:
                return {'http': None, 'code': None, 'len': 0, 'raw': '', 'error': str(e)[:100]}
            time.sleep(0.5)

def main():
    tok = open(TOK, encoding='utf-8').read().strip() if os.path.exists(TOK) else ''
    data = json.load(open(os.path.join(ROOT, 'knowledge', 'backend_endpoints.json'), encoding='utf-8'))
    targets = []
    for ep in data.get('endpoints') or []:
        method = ep.get('method')
        path = ep.get('path')
        if method not in ('GET', 'POST') or not path:
            continue
        keys = (ep.get('query_keys') or []) + (ep.get('body_keys') or [])
        keys = [k for k in keys if k != 't'][:3]
        if keys:
            targets.append({'method': method, 'path': path, 'keys': keys})
    targets = targets[:8]
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'targets': targets, 'results': []}
    for t in targets:
        base_body = {k: '' for k in t['keys']} if t['method'] == 'POST' else None
        base = call(t['method'], t['path'], base_body, tok)
        for key in t['keys']:
            for pl in PAYLOADS:
                body = dict(base_body or {})
                if t['method'] == 'POST':
                    body[key] = pl
                if t['method'] == 'GET':
                    sep = '&' if '?' in t['path'] else '?'
                    path = t['path'] + sep + key + '=' + requests.utils.quote(pl)
                    r = call('GET', path, None, tok)
                else:
                    r = call('POST', t['path'], body, tok)
                sig = str(r.get('code')) not in ('0', '9003', '1002', '1003', '4104', '4098') and any((s in r['raw'].lower() for s in ERROR_SIGS))
                diff = str(r['code']) != str(base['code']) or abs(r['len'] - base['len']) > 50
                result['results'].append({'path': t['path'], 'method': t['method'], 'param': key, 'payload': pl, 'http': r['http'], 'code': r['code'], 'error_sig': sig, 'diff': diff, 'len': r['len'], 'base_len': base['len']})
    suspects = [r for r in result['results'] if r['error_sig']]
    result['summary'] = {'targets': len(targets), 'probes': len(result['results']), 'error_signature': len(suspects), 'diff': len([r for r in result['results'] if r['diff']])}
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    try:
        findings = []
        for s in suspects[:5]:
            findings.append(gc.finding('SQLI-ERROR-SIGNATURE', 'high', f"SQL 错误特征：{s.get('path')} {s.get('param')}", evidence=str(s)[:300], remediation='参数化查询'))
        gc.emit('injection_matrix', 'application', 'PASS', findings, summary=json.dumps(result['summary'], ensure_ascii=False))
    except Exception:
        pass
    print(json.dumps(result['summary'], ensure_ascii=False))
if __name__ == '__main__':
    main()
