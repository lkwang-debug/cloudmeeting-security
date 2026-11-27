"""全量 API 扫描公共库：清单、鉴权、只读接口过滤、请求。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import requests
import urllib3
import yaml
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
try:
    from checks import web_auth
except ImportError:
    import web_auth
urllib3.disable_warnings()
ROOT = gc.ROOT
INVENTORY = os.path.join(ROOT, 'knowledge', 'api_inventory.json')
BASE = gc.base_url()
WRITE_HINTS = ('add', 'delete', 'del', 'update', 'edit', 'save', 'batch', 'import', 'upload', 'create', 'remove', 'reset', 'bind', 'auth', 'execute', 'set')

def load():
    if not os.path.exists(INVENTORY):
        return []
    return json.load(open(INVENTORY, encoding='utf-8')).get('endpoints') or []

def auth():
    cfg = os.path.join(ROOT, 'configs', 'web_automation.yaml')
    root = {}
    try:
        root = yaml.safe_load(open(cfg, encoding='utf-8')) or {}
    except Exception:
        pass
    return web_auth.headers(root)

def read_endpoints(limit=None):
    out = []
    for e in load():
        path = e.get('path', '')
        method = e.get('method', 'POST').upper()
        low = path.lower()
        if method not in ('GET', 'POST'):
            continue
        if method == 'POST' and any((h in low for h in WRITE_HINTS)):
            continue
        if any((x in low for x in ('delete', 'remove', 'upload', 'import', 'export'))):
            continue
        out.append(e)
        if limit and len(out) >= limit:
            break
    return out

def request(ep, key_values, extra_headers=None):
    method = ep.get('method', 'POST').upper()
    headers = {'User-Agent': 'Mozilla/5.0', 'Origin': BASE, 'Referer': BASE + '/ui/login', 'Content-Type': 'application/json', **auth(), **(extra_headers or {})}
    body = {k: v for (k, v) in (key_values or {}).items()}
    params = {'t': str(int(time.time() * 1000))}
    if method == 'GET':
        params.update(key_values or {})
        body = None
    try:
        r = requests.request(method, BASE + ep['path'], headers=headers, params=params, json=body, timeout=12, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        return {'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'len': len(r.text or ''), 'body': (r.text or '')[:1500]}
    except Exception as e:
        return {'error': str(e)[:120]}
