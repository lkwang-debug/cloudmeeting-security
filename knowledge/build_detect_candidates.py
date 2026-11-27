"""V8：条件检测自动识别（detect_candidates 生成）。
输入：knowledge/endpoints.json、knowledge/backend_endpoints.json、detect_rules.yaml、tools_cache/chunks 文本
输出：knowledge/detect_candidates.json（候选端点/依据/所需前置/置信度/配置门控）
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KN = os.path.join(ROOT, 'knowledge')
OUT = os.path.join(KN, 'detect_candidates.json')
CHUNKS = os.path.join(ROOT, 'tools_cache', 'chunks')

def load_endpoints():
    eps = []
    p = os.path.join(KN, 'backend_endpoints.json')
    if os.path.exists(p):
        data = json.load(open(p, encoding='utf-8'))
        eps += data.get('endpoints') or []
    p2 = os.path.join(KN, 'endpoints.json')
    if os.path.exists(p2):
        data = json.load(open(p2, encoding='utf-8'))
        eps += data.get('endpoints') or data.get('cases') or []
    p3 = os.path.join(KN, 'all_backend_endpoints.json')
    if os.path.exists(p3):
        data = json.load(open(p3, encoding='utf-8'))
        for path in data.get('endpoints') or []:
            if isinstance(path, str):
                m = 'POST' if any((k in path.lower() for k in ('add', 'update', 'delete', 'batch', 'import', 'upload', 'submit', 'edit', 'modify', 'del'))) else 'GET'
                eps.append({'path': path, 'method': m})
    return eps

def chunk_keywords():
    kws = ['WebSocket', 'EventSource', 'text/event-stream', 'ws://', 'wss://', 'upload', 'import']
    hits = {}
    if os.path.isdir(CHUNKS):
        for fn in os.listdir(CHUNKS):
            try:
                t = open(os.path.join(CHUNKS, fn), encoding='utf-8', errors='replace').read()
            except Exception:
                continue
            found = [k for k in kws if k.lower() in t.lower()]
            if found:
                hits[fn] = found
    return hits

def main():
    rules = yaml.safe_load(open(os.path.join(KN, 'detect_rules.yaml'), encoding='utf-8'))
    eps = load_endpoints()
    cand = {'generated_at': __import__('time').strftime('%Y-%m-%dT%H:%M:%S'), 'rules_version': rules.get('version'), 'by_rule': {}, 'summary': {}}

    def add(rule, path, method, reason, requires, confidence):
        c = cand['by_rule'].setdefault(rule, [])
        if any((x['path'] == path and x['method'] == method for x in c)):
            return
        c.append({'path': path, 'method': method, 'reason': reason, 'requires': requires, 'confidence': confidence})
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        path = ep.get('path') or ep.get('url') or ''
        method = ep.get('method') or 'GET'
        low = path.lower()
        if any((k in low for k in ('url', 'callback', 'webhook', 'redirect', 'fetch', 'proxy', 'live', 'stream', 'ai', 'sso', 'file', 'import', 'upload', 'avatar', 'photo'))):
            add('ssrf_xxe', path, method, 'URL/文件类关键字', ['oast_domain', 'auth'], 'medium')
        if any((k in low for k in ('add', 'create', 'update', 'delete', 'batch', 'import', 'upload', 'submit', 'grant', 'authorize'))):
            add('race', path, method, '写操作关键字', ['isolated_data', 'write_whitelist'], 'low')
        if any((k in low for k in ('/upload', '/import', '/excel'))):
            add('file_upload', path, method, '上传/导入关键字', ['multipart', 'isolated_data'], 'medium')
    for (fn, kws) in chunk_keywords().items():
        add('long_connection', f'chunk:{fn}', 'WS', f"客户端关键字:{','.join(kws)}", ['browser_cdp', 'network_log'], 'high')
    add('long_connection', '/ngproxy/ws/webproxy/', 'WS', '已抓包的 Web WS 协议', ['token', 'room'], 'high')
    add('long_connection', '/ngproxy/ws/wsgw', 'WS', 'WS 网关地址下发', ['token'], 'medium')
    gate = {}
    scope_path = os.path.join(ROOT, 'configs', 'scope.yaml')
    if os.path.exists(scope_path):
        scope = yaml.safe_load(open(scope_path, encoding='utf-8')) or {}
        gate = scope.get('execution') or {}
    cand['gating'] = {'ssrf_xxe': bool((gate.get('ssrf') or {}).get('enabled')), 'race': bool((gate.get('race') or {}).get('enabled')), 'long_connection': bool((gate.get('longconn') or {}).get('enabled')), 'file_upload': True}
    cand['summary'] = {k: len(v) for (k, v) in cand['by_rule'].items()}
    os.makedirs(KN, exist_ok=True)
    json.dump(cand, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(cand['summary'], ensure_ascii=False), '->', OUT)
if __name__ == '__main__':
    main()
